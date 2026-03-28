#!/usr/bin/env node
/**
 * One-time QuickBooks re-authorization script.
 * Opens browser → you log in → saves fresh tokens to .env
 * After this, the MCP server will auto-rotate tokens on every refresh.
 */
import dotenv from 'dotenv';
import OAuthClient from 'intuit-oauth';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import open from 'open';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, '.env') });

const client_id = process.env.QUICKBOOKS_CLIENT_ID;
const client_secret = process.env.QUICKBOOKS_CLIENT_SECRET;
const environment = process.env.QUICKBOOKS_ENVIRONMENT || 'production';
const redirectUri = 'http://localhost:3000/auth/quickbooks/callback';

const oauthClient = new OAuthClient({
  clientId: client_id,
  clientSecret: client_secret,
  environment,
  redirectUri,
});

const server = http.createServer(async (req, res) => {
  if (!req.url?.startsWith('/auth/quickbooks/callback')) return;

  try {
    const response = await oauthClient.createToken(req.url);
    const tokens = response.token;

    // Update .env with new tokens
    const envPath = path.join(__dirname, '.env');
    let envContent = fs.readFileSync(envPath, 'utf-8');
    const lines = envContent.split('\n');

    const update = (name, value) => {
      const idx = lines.findIndex(l => l.startsWith(`${name}=`));
      if (idx !== -1) lines[idx] = `${name}=${value}`;
      else lines.push(`${name}=${value}`);
    };

    update('QUICKBOOKS_REFRESH_TOKEN', tokens.refresh_token);
    if (tokens.realmId) update('QUICKBOOKS_REALM_ID', tokens.realmId);

    fs.writeFileSync(envPath, lines.join('\n'));

    console.log('\n✅ Authorization successful!');
    console.log(`   Refresh token: ${tokens.refresh_token.slice(0, 20)}...`);
    console.log(`   Realm ID: ${tokens.realmId}`);
    console.log('   Tokens saved to .env');
    console.log('\n   The MCP server will now auto-rotate tokens on each refresh.');
    console.log('   You should not need to re-authenticate again.\n');

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body style="display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;background:#f0fdf4"><h2 style="color:#16a34a">✓ QuickBooks connected! You can close this tab.</h2></body></html>');

    setTimeout(() => { server.close(); process.exit(0); }, 1000);
  } catch (err) {
    console.error('❌ Auth error:', err.message);
    res.writeHead(500, { 'Content-Type': 'text/html' });
    res.end('<html><body style="display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;background:#fef2f2"><h2 style="color:#dc2626">Error — check console</h2></body></html>');
  }
});

server.listen(3000, async () => {
  const authUri = oauthClient.authorizeUri({
    scope: [OAuthClient.scopes.Accounting],
    state: 'mcp-reauth',
  });
  console.log('🔐 Opening browser for QuickBooks authorization...');
  console.log(`   (If browser doesn't open, visit: ${authUri})\n`);
  await open(authUri);
});
