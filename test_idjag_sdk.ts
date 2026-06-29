import * as http from "http";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { exec } from "child_process";
import { URLSearchParams } from "url";
import { AgentIdentity, PendingApprovalError, pollUntilApproved } from "@authsec/sdk";

for (const l of fs.readFileSync(path.resolve(__dirname, "../.env"), "utf8").split("\n")) {
  const e = l.indexOf("=");
  if (e > 0) { const k = l.slice(0, e).trim(), v = l.slice(e + 1).trim(); if (!process.env[k]) process.env[k] = v; }
}

// Leg 1 — browser OIDC login (PKCE, no client secret) → id_token
async function oidcLogin(): Promise<string> {
  const m = await fetch("https://mcpauthz.com/.well-known/openid-configuration").then(r => r.json()) as any;
  const ver = crypto.randomBytes(48).toString("base64url");
  const ch  = crypto.createHash("sha256").update(ver).digest("base64url");
  const p   = new URLSearchParams({ response_type: "code", client_id: process.env.IDP_CLIENT_ID!, redirect_uri: "http://localhost:8126/callback", scope: "openid email profile mcp:read mcp:tools:read", state: crypto.randomBytes(16).toString("base64url"), nonce: crypto.randomBytes(16).toString("base64url"), code_challenge: ch, code_challenge_method: "S256" });
  return new Promise((resolve, reject) => {
    const s = http.createServer(async (req, res) => {
      const code = new URL(req.url!, "http://localhost:8126").searchParams.get("code")!;
      res.writeHead(200); res.end("Done"); s.close();
      const t = await fetch(m.token_endpoint, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: "http://localhost:8126/callback", client_id: process.env.IDP_CLIENT_ID!, code_verifier: ver }).toString() }).then(r => r.json()) as any;
      t.id_token ? resolve(t.id_token) : reject(new Error(JSON.stringify(t)));
    });
    s.listen(8126, () => exec(`start "" "${m.authorization_endpoint}?${p}"`));
  });
}

(async () => {

const agent = new AgentIdentity({
  issuer:        "https://mcpauthz.com",
  clientId:      process.env.IDP_CLIENT_ID!,
  clientSecret:  process.env.IDP_CLIENT_SECRET!,
  idpIssuer:     "https://mcpauthz.com",  // enables XAA
  preferredMode: "auto",                  // XAA whenever a user session is passed (4.6.1+)
});

// Leg 1 (browser OIDC login) is still YOURS — get the user's id_token however you like.
const idToken = await oidcLogin();        // reuse the raw script's PKCE login

// Legs 2-4 collapse into one call:
let token: string;
try {
  token = await agent.accessFor(process.env.MCP_URL!, {
    userSession: { subject_token: idToken },
    requestedScopes: ["mcp:read", "mcp:tools:read"],
  });
} catch (err) {
  if (err instanceof PendingApprovalError) {
    token = await pollUntilApproved(agent, process.env.MCP_URL!, (err as any).statusUrl);
  } else throw err;
}

// Call the MCP server
const res = await fetch(process.env.MCP_URL!, {
  method: "POST",
  headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token!}` },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
});
console.log("HTTP", res.status, await res.json());

})().catch(e => { console.error("[ERROR]", e.message); process.exit(1); });
