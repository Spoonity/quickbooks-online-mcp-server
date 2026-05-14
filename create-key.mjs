import crypto from "node:crypto";

const BASE = "https://qb.spoonity.com";
const API_KEY = process.env.MCP_API_KEY;

// DCR
const dcr = await (await fetch(BASE+"/register", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({client_name:"admin-cli",redirect_uris:["http://localhost/callback"],grant_types:["authorization_code"],response_types:["code"],token_endpoint_auth_method:"client_secret_post"})})).json();

// PKCE
const cv = crypto.randomBytes(32).toString("base64url");
const cc = crypto.createHash("sha256").update(cv).digest("base64url");

// Auth
const html = await (await fetch(`${BASE}/authorize?client_id=${dcr.client_id}&redirect_uri=http://localhost/callback&response_type=code&code_challenge=${cc}&code_challenge_method=S256&state=cli`, {redirect:"manual"})).text();
const loginId = html.match(/name="login_id"\s+value="([^"]+)"/)[1];
const loginRes = await fetch(`${BASE}/login`, {method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"login_id="+loginId+"&api_key="+encodeURIComponent(API_KEY),redirect:"manual"});
const code = new URL(loginRes.headers.get("location")).searchParams.get("code");

// Token
const tokens = await (await fetch(`${BASE}/token`, {method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({grant_type:"authorization_code",code,redirect_uri:"http://localhost/callback",client_id:dcr.client_id,client_secret:dcr.client_secret||"",code_verifier:cv}).toString()})).json();

// Create key
const res = await fetch(`${BASE}/admin/keys`, {method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+tokens.access_token},body:JSON.stringify({owner:"adriana.miranda@spoonity.com",role:"readonly",label:"Adriana Miranda Readonly Key"})});
const result = await res.json();
console.log(JSON.stringify(result, null, 2));
