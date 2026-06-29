import * as http from "http"; import * as crypto from "crypto"; import { exec } from "child_process";
import * as fs from "fs"; import * as path from "path"; import { URLSearchParams } from "url";

for (const l of fs.readFileSync(path.resolve(__dirname,"../.env"),"utf8").split("\n")) { const e=l.indexOf("="); if(e>0){const k=l.slice(0,e).trim(),v=l.slice(e+1).trim();if(!process.env[k])process.env[k]=v;} }

const CLIENT_ID     = process.env.IDP_CLIENT_ID!;
const CLIENT_SECRET = process.env.IDP_CLIENT_SECRET!;
const MCP_URL       = process.env.MCP_URL!;
const TOKEN_URL     = "https://mcpauthz.com/oauth/token";
const REDIRECT      = "http://localhost:8126/callback";

// ── Leg 1 — log the user in (authorization_code + PKCE, NO secret) ───────────
async function leg1_oidcLogin(): Promise<{ idToken: string }> {
  const meta = await fetch("https://mcpauthz.com/.well-known/openid-configuration").then(r=>r.json()) as any;
  const ver = crypto.randomBytes(48).toString("base64url");
  const ch  = crypto.createHash("sha256").update(ver).digest("base64url");
  const p   = new URLSearchParams({
    response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT,
    scope: "openid email profile", state: crypto.randomBytes(16).toString("base64url"),
    nonce: crypto.randomBytes(16).toString("base64url"),
    code_challenge: ch, code_challenge_method: "S256",
  });
  return new Promise((resolve, reject) => {
    const s = http.createServer(async (req, res) => {
      const code = new URL(req.url!, "http://localhost:8126").searchParams.get("code");
      if (!code) { res.writeHead(400); res.end("missing code"); s.close(); reject(new Error("missing code")); return; }
      res.writeHead(200); res.end("<h2>Done — close this tab.</h2>"); s.close();
      // NOTE: no client_secret here — public client + PKCE
      const td = await fetch(TOKEN_URL, {
        method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "authorization_code", code,
          redirect_uri: REDIRECT, client_id: CLIENT_ID, code_verifier: ver }).toString(),
      }).then(r=>r.json()) as any;
      console.log("[Leg 1] token response:", JSON.stringify({ id_token: td.id_token ? "(present)" : "(missing)", access_token: td.access_token ? "(present)" : "(missing)", error: td.error }));
      td.id_token ? resolve({ idToken: td.id_token }) : reject(new Error(JSON.stringify(td)));
    });
    s.listen(8126, () => { console.log("[Leg 1] Browser opening..."); exec(`start "" "${meta.authorization_endpoint}?${p}"`); });
  });
}

// ── Leg 2 — exchange id_token for ID-JAG (token-exchange, WITH secret) ───────
async function leg2_tokenExchange(idToken: string): Promise<string> {
  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token: idToken,
    subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
    requested_token_type: "urn:ietf:params:oauth:token-type:id-jag",
    resource: MCP_URL,
  });
  const r = await fetch(TOKEN_URL, {
    method: "POST", headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Authorization": "Basic " + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64"),
    },
    body: body.toString(),
  });
  const td = await r.json() as any;
  console.log("[Leg 2] HTTP", r.status, JSON.stringify(td).slice(0, 200));
  if (!r.ok) throw new Error(`Leg 2 failed: ${JSON.stringify(td)}`);
  return td.access_token; // this is the ID-JAG
}

// ── Leg 3 — redeem ID-JAG for MCP access token (jwt-bearer, WITH secret) ─────
async function leg3_jwtBearer(idJag: string, scopes: string): Promise<string> {
  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: idJag,
    resource: MCP_URL,
    scope: scopes,
  });
  const r = await fetch(TOKEN_URL, {
    method: "POST", headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Authorization": "Basic " + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64"),
    },
    body: body.toString(),
  });
  const td = await r.json() as any;
  console.log("[Leg 3] HTTP", r.status, JSON.stringify(td).slice(0, 200));
  if (td.error === "access_pending") throw Object.assign(new Error("access_pending"), td);
  if (!r.ok) throw new Error(`Leg 3 failed: ${JSON.stringify(td)}`);
  return td.access_token;
}

// ── Leg 4 — call MCP server ───────────────────────────────────────────────────
async function leg4_callMcp(token: string) {
  const r = await fetch(MCP_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
  });
  const data = await r.json() as any;
  console.log("\n[Leg 4] HTTP", r.status);
  const tools = data?.result?.tools ?? [];
  console.log(`Tools (${tools.length}):`);
  for (const t of tools) console.log(`  • ${t.name}`);
  if (tools.length === 0) console.log("  (raw response):", JSON.stringify(data));

  // decode token claims to confirm ID-JAG
  const parts = token.split(".");
  if (parts.length === 3) {
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    console.log("\n--- Token claims ---");
    console.log("sub:", claims.sub);
    console.log("act:", JSON.stringify(claims.act) ?? "(none)");
    console.log("tf (token-family):", claims.tf ?? "(none)");
    console.log("aud:", claims.aud);
    console.log("flow:", claims.act ? "✓ ID-JAG" : "NOT id-jag");
    console.log("--------------------");
  } else {
    console.log("\nToken is opaque — cannot decode claims");
  }
}

(async () => {
  console.log("=".repeat(60));
  console.log("  ID-JAG raw flow — 4 legs");
  console.log("=".repeat(60));
  console.log("  CLIENT_ID:", CLIENT_ID);
  console.log("  MCP_URL  :", MCP_URL);
  console.log("=".repeat(60) + "\n");

  // Leg 1
  const { idToken } = await leg1_oidcLogin();
  console.log("[Leg 1] ✓ id_token obtained\n");

  // Leg 2
  console.log("[Leg 2] Token exchange: id_token → ID-JAG...");
  const idJag = await leg2_tokenExchange(idToken);
  console.log("[Leg 2] ✓ ID-JAG obtained\n");

  // Leg 3 — with access_pending retry loop
  console.log("[Leg 3] jwt-bearer: ID-JAG → MCP access token...");
  let mcpToken: string;
  while (true) {
    try {
      mcpToken = await leg3_jwtBearer(idJag, "mcp:read mcp:tools:read");
      console.log("[Leg 3] ✓ access token obtained\n");
      break;
    } catch (e: any) {
      if (e.message === "access_pending") {
        console.log("[Leg 3] access_pending — go to AuthSec Console:");
        console.log("  Applications → MCP server → Requests → approve + assign role");
        console.log("  Retrying in 5s...");
        await new Promise(r => setTimeout(r, 5000));
      } else throw e;
    }
  }

  // Leg 4
  await leg4_callMcp(mcpToken!);
})().catch(e => { console.error("\n[FATAL]", e.message); process.exit(1); });
