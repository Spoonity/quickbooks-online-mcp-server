import crypto from "node:crypto";
const BASE = "https://qb.spoonity.com";
const API_KEY = process.argv[2] || process.env.MCP_API_KEY;

// DCR + Auth + Token
const dcr = await (await fetch(BASE+"/register", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({client_name:"debug",redirect_uris:["http://localhost/callback"],grant_types:["authorization_code"],response_types:["code"],token_endpoint_auth_method:"client_secret_post"})})).json();
const cv = crypto.randomBytes(32).toString("base64url");
const cc = crypto.createHash("sha256").update(cv).digest("base64url");
const html = await (await fetch(`${BASE}/authorize?client_id=${dcr.client_id}&redirect_uri=http://localhost/callback&response_type=code&code_challenge=${cc}&code_challenge_method=S256&state=dbg`, {redirect:"manual"})).text();
const loginId = html.match(/name="login_id"\s+value="([^"]+)"/)[1];
const loginRes = await fetch(`${BASE}/login`, {method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"login_id="+loginId+"&api_key="+encodeURIComponent(API_KEY),redirect:"manual"});
const code = new URL(loginRes.headers.get("location")).searchParams.get("code");
const tokens = await (await fetch(`${BASE}/token`, {method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({grant_type:"authorization_code",code,redirect_uri:"http://localhost/callback",client_id:dcr.client_id,client_secret:dcr.client_secret||"",code_verifier:cv}).toString()})).json();

// Init
const init = await (await fetch(`${BASE}/`, {method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json, text/event-stream","Authorization":"Bearer "+tokens.access_token},body:JSON.stringify({jsonrpc:"2.0",id:"1",method:"initialize",params:{protocolVersion:"2025-03-26",capabilities:{},clientInfo:{name:"dbg",version:"1.0.0"}}})}));
const sid = init.headers.get("mcp-session-id");
const initData = await init.json();
console.log("Session:", sid);

// tools/list
const list = await (await fetch(`${BASE}/`, {method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json, text/event-stream","Authorization":"Bearer "+tokens.access_token,"Mcp-Session-Id":sid},body:JSON.stringify({jsonrpc:"2.0",id:"2",method:"tools/list",params:{}})})).json();

const tools = list.result?.tools || [];
console.log(`\nTotal tools: ${tools.length}`);
console.log("\nInvoice-related tools:");
tools.filter(t => t.name.includes("invoice") || t.name.includes("Invoice")).forEach(t => console.log(`  - ${t.name}: ${t.description}`));
console.log("\nAll tool names:");
tools.forEach(t => console.log(`  ${t.name}`));
