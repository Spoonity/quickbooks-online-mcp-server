import crypto from "node:crypto";

const API_KEY = process.env.MCP_API_KEY;
const BASE = "https://qb.spoonity.com";

// Quick DCR
const dcr = await (await fetch(BASE+"/register", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({client_name:"debug",redirect_uris:["http://localhost/callback"],grant_types:["authorization_code"],response_types:["code"],token_endpoint_auth_method:"client_secret_post"}) })).json();

// PKCE
const cv = crypto.randomBytes(32).toString("base64url");
const cc = crypto.createHash("sha256").update(cv).digest("base64url");

// Auth
const authUrl = `${BASE}/authorize?client_id=${dcr.client_id}&redirect_uri=http://localhost/callback&response_type=code&code_challenge=${cc}&code_challenge_method=S256&state=dbg`;
const html = await (await fetch(authUrl, {redirect:"manual"})).text();
const loginId = html.match(/name="login_id"\s+value="([^"]+)"/)[1];
const loginRes = await fetch(`${BASE}/login`, {method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"login_id="+loginId+"&api_key="+encodeURIComponent(API_KEY),redirect:"manual"});
const loc = loginRes.headers.get("location");
const code = new URL(loc).searchParams.get("code");
const tokens = await (await fetch(`${BASE}/token`, {method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({grant_type:"authorization_code",code,redirect_uri:"http://localhost/callback",client_id:dcr.client_id,client_secret:dcr.client_secret||"",code_verifier:cv}).toString()})).json();

console.log("TOKEN OK:", !!tokens.access_token);

// MCP Init - raw debug
const initRes = await fetch(`${BASE}/`, {method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json, text/event-stream","Authorization":"Bearer "+tokens.access_token},body:JSON.stringify({jsonrpc:"2.0",id:"1",method:"initialize",params:{protocolVersion:"2025-03-26",capabilities:{},clientInfo:{name:"dbg",version:"1.0.0"}}})});
console.log("STATUS:", initRes.status);
console.log("CONTENT-TYPE:", initRes.headers.get("content-type"));
console.log("SESSION-ID:", initRes.headers.get("mcp-session-id"));
const raw = await initRes.text();
console.log("BODY:", raw.substring(0, 500));
