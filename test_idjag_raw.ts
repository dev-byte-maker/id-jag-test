import * as http from "http";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { exec } from "child_process";
import { URLSearchParams } from "url";

// ── Config ────────────────────────────────────────────────────────────────────

loadEnv(path.resolve(__dirname, "../.env"));

const AGENT_CLIENT_ID     = process.env.IDP_CLIENT_ID!;
const AGENT_CLIENT_SECRET = process.env.IDP_CLIENT_SECRET!;
const MCP_SERVER_URL      = process.env.MCP_URL!;
const AS_TOKEN_URL        = "https://mcpauthz.com/oauth/token";
const OIDC_CALLBACK_URL   = "http://localhost:8126/callback";

// ── Leg 1: OIDC login — authorization_code + PKCE, no client secret ──────────

async function oidcLogin(): Promise<string> {
  const discovery = await fetchJson<OidcDiscovery>("https://mcpauthz.com/.well-known/openid-configuration");

  const pkce     = generatePkce();
  const state    = randomBase64Url(16);
  const nonce    = randomBase64Url(16);

  const authorizeUrl = buildAuthorizeUrl(discovery.authorization_endpoint, {
    client_id:             AGENT_CLIENT_ID,
    redirect_uri:          OIDC_CALLBACK_URL,
    scope:                 "openid email profile",
    state,
    nonce,
    code_challenge:        pkce.challenge,
    code_challenge_method: "S256",
  });

  const authCode = await openBrowserAndWaitForCode(authorizeUrl);

  const tokens = await exchangeCodeForTokens({
    tokenEndpoint: discovery.token_endpoint,
    code:          authCode,
    codeVerifier:  pkce.verifier,
  });

  return tokens.id_token;
}

// ── Leg 2: token exchange — id_token → ID-JAG (with client secret) ───────────

async function exchangeIdTokenForIdJag(idToken: string): Promise<string> {
  const body = new URLSearchParams({
    grant_type:             "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token:          idToken,
    subject_token_type:     "urn:ietf:params:oauth:token-type:id_token",
    requested_token_type:   "urn:ietf:params:oauth:token-type:id-jag",
    resource:               MCP_SERVER_URL,
  });

  const response = await fetchWithClientAuth<TokenResponse>(AS_TOKEN_URL, body);

  if (!response.access_token) {
    throw new Error(`Leg 2 failed: ${JSON.stringify(response)}`);
  }

  return response.access_token;
}

// ── Leg 3: jwt-bearer — ID-JAG → MCP access token (with client secret) ───────

async function redeemIdJagForMcpToken(idJag: string, scopes: string): Promise<string> {
  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion:  idJag,
    resource:   MCP_SERVER_URL,
    scope:      scopes,
  });

  const response = await fetchWithClientAuth<TokenResponse>(AS_TOKEN_URL, body);

  if (response.error === "access_pending") {
    throw Object.assign(new Error("access_pending"), response);
  }

  if (!response.access_token) {
    throw new Error(`Leg 3 failed: ${JSON.stringify(response)}`);
  }

  return response.access_token;
}

// ── Leg 4: call the MCP server ────────────────────────────────────────────────

async function callMcpToolsList(accessToken: string): Promise<McpTool[]> {
  const response = await fetch(MCP_SERVER_URL, {
    method:  "POST",
    headers: {
      "Content-Type":  "application/json",
      "Authorization": `Bearer ${accessToken}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
  });

  const body = await response.json() as McpResponse;
  console.log(`[Leg 4] HTTP ${response.status}`);

  return body?.result?.tools ?? [];
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log("=".repeat(60));
  console.log("  ID-JAG raw flow (4 legs)");
  console.log("=".repeat(60));
  console.log(`  client_id  : ${AGENT_CLIENT_ID}`);
  console.log(`  mcp_server : ${MCP_SERVER_URL}`);
  console.log("=".repeat(60) + "\n");

  // Leg 1 — OIDC login
  console.log("[Leg 1] OIDC login (PKCE, no secret)...");
  const idToken = await oidcLogin();
  console.log("[Leg 1] ✓ id_token obtained\n");

  // Leg 2 — token exchange
  console.log("[Leg 2] Token exchange: id_token → ID-JAG...");
  const idJag = await exchangeIdTokenForIdJag(idToken);
  console.log("[Leg 2] ✓ ID-JAG obtained\n");

  // Leg 3 — jwt-bearer (retry on access_pending)
  console.log("[Leg 3] jwt-bearer: ID-JAG → MCP access token...");
  const mcpAccessToken = await redeemWithPendingRetry(idJag);
  console.log("[Leg 3] ✓ access token obtained\n");

  // Leg 4 — call MCP
  const tools = await callMcpToolsList(mcpAccessToken);
  console.log(`\nTools (${tools.length}):`);
  for (const tool of tools) {
    console.log(`  • ${tool.name}${tool.description ? " — " + tool.description : ""}`);
  }

  // Confirm it is ID-JAG by decoding the token claims
  printTokenClaims(mcpAccessToken);
}

async function redeemWithPendingRetry(idJag: string): Promise<string> {
  const SCOPES = "mcp:read mcp:tools:read";
  while (true) {
    try {
      return await redeemIdJagForMcpToken(idJag, SCOPES);
    } catch (err: any) {
      if (err.message !== "access_pending") throw err;
      console.log("[Leg 3] access_pending — approve in AuthSec Console:");
      console.log("  Applications → MCP server → Requests → approve + assign role");
      console.log("  Retrying in 5s...");
      await sleep(5000);
    }
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function loadEnv(envPath: string) {
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, "utf8").split("\n")) {
    const eqIndex = line.indexOf("=");
    if (eqIndex < 0) continue;
    const key   = line.slice(0, eqIndex).trim();
    const value = line.slice(eqIndex + 1).trim();
    if (key && !process.env[key]) process.env[key] = value;
  }
}

function generatePkce() {
  const verifier  = randomBase64Url(48);
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

function randomBase64Url(bytes: number): string {
  return crypto.randomBytes(bytes).toString("base64url");
}

function buildAuthorizeUrl(endpoint: string, params: Record<string, string>): string {
  const query = new URLSearchParams({ response_type: "code", ...params });
  return `${endpoint}?${query}`;
}

function openBrowserAndWaitForCode(authorizeUrl: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const callbackUrl = new URL(req.url!, OIDC_CALLBACK_URL);
      const code  = callbackUrl.searchParams.get("code");
      const error = callbackUrl.searchParams.get("error");

      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<h2>Login successful — you can close this tab.</h2>");
      server.close();

      if (error || !code) reject(new Error(error ?? "missing code"));
      else resolve(code);
    });

    server.listen(8126, () => {
      console.log("  Browser opening...");
      exec(`start "" "${authorizeUrl}"`);
    });
  });
}

async function exchangeCodeForTokens(opts: {
  tokenEndpoint: string;
  code: string;
  codeVerifier: string;
}): Promise<{ id_token: string; access_token: string }> {
  const body = new URLSearchParams({
    grant_type:    "authorization_code",
    code:          opts.code,
    redirect_uri:  OIDC_CALLBACK_URL,
    client_id:     AGENT_CLIENT_ID,
    code_verifier: opts.codeVerifier,
    // NOTE: no client_secret — public client + PKCE
  });

  return fetchJson<{ id_token: string; access_token: string }>(opts.tokenEndpoint, {
    method:  "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body:    body.toString(),
  });
}

function fetchWithClientAuth<T>(url: string, body: URLSearchParams): Promise<T> {
  const credentials = Buffer.from(`${AGENT_CLIENT_ID}:${AGENT_CLIENT_SECRET}`).toString("base64");
  return fetchJson<T>(url, {
    method:  "POST",
    headers: {
      "Content-Type":  "application/x-www-form-urlencoded",
      "Authorization": `Basic ${credentials}`,
    },
    body: body.toString(),
  });
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  return response.json() as Promise<T>;
}

function printTokenClaims(token: string) {
  const parts = token.split(".");
  if (parts.length !== 3) { console.log("\nToken is opaque — cannot decode claims"); return; }
  const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString());
  console.log("\n--- Token claims ---");
  console.log("sub (user) :", claims.sub);
  console.log("act (agent):", JSON.stringify(claims.act) ?? "(none — NOT id-jag)");
  console.log("tf         :", claims.tf ?? "(none)");
  console.log("aud        :", claims.aud);
  console.log("flow       :", claims.act ? "✓ ID-JAG" : "✗ not ID-JAG");
  console.log("--------------------");
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface OidcDiscovery {
  authorization_endpoint: string;
  token_endpoint: string;
}

interface TokenResponse {
  access_token?: string;
  id_token?: string;
  error?: string;
  error_description?: string;
}

interface McpTool {
  name: string;
  description?: string;
}

interface McpResponse {
  result?: { tools: McpTool[] };
}

// ── Run ───────────────────────────────────────────────────────────────────────

main().catch(err => {
  console.error("\n[ERROR]", err.message);
  process.exit(1);
});
