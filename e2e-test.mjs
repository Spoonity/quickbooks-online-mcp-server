#!/usr/bin/env node
/**
 * E2E smoke test for the QBO MCP Server.
 *
 * Tests:
 *   1. Health endpoint
 *   2. OAuth DCR + token exchange
 *   3. MCP session initialization (tools/list)
 *   4. Tool calls across all major categories
 *
 * Usage:
 *   MCP_API_KEY=<key> node e2e-test.mjs
 *   MCP_API_KEY=<key> node e2e-test.mjs https://qb.spoonity.com
 */

const BASE = process.argv[2] || "https://qb.spoonity.com";
const API_KEY = process.env.MCP_API_KEY;

if (!API_KEY) {
    console.error("❌ MCP_API_KEY env var is required");
    process.exit(1);
}

const crypto = await import("node:crypto");

let passed = 0;
let failed = 0;
let skipped = 0;

function ok(name) { passed++; console.log(`  ✅ ${name}`); }
function fail(name, err) { failed++; console.log(`  ❌ ${name}: ${err}`); }
function skip(name, reason) { skipped++; console.log(`  ⏭️  ${name}: ${reason}`); }

// ── 1. Health ───────────────────────────────────────────────────────────────

console.log("\n🔍 Health Check");
try {
    const res = await fetch(`${BASE}/health`);
    const data = await res.json();
    if (data.status === "ok" && data.tools > 0) {
        ok(`Health OK — ${data.tools} tools, qboConnected=${data.qboConnected}`);
    } else {
        fail("Health", JSON.stringify(data));
    }
} catch (e) { fail("Health", e.message); }

// ── 2. OAuth Flow ───────────────────────────────────────────────────────────

console.log("\n🔐 OAuth Flow");

// 2a. Dynamic Client Registration
let clientId, clientSecret;
try {
    const dcrRes = await fetch(`${BASE}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            client_name: "e2e-test",
            redirect_uris: ["http://localhost/callback"],
            grant_types: ["authorization_code"],
            response_types: ["code"],
            token_endpoint_auth_method: "client_secret_post",
        }),
    });
    const dcr = await dcrRes.json();
    clientId = dcr.client_id;
    clientSecret = dcr.client_secret;
    if (clientId) {
        ok(`DCR — client_id=${clientId.substring(0, 8)}...`);
    } else {
        fail("DCR", JSON.stringify(dcr));
    }
} catch (e) { fail("DCR", e.message); }

// 2b. PKCE
const codeVerifier = crypto.randomBytes(32).toString("base64url");
const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

// 2c. Authorize (get login form, submit API key)
let authCode;
try {
    const authUrl = new URL(`${BASE}/authorize`);
    authUrl.searchParams.set("client_id", clientId);
    authUrl.searchParams.set("redirect_uri", "http://localhost/callback");
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("code_challenge", codeChallenge);
    authUrl.searchParams.set("code_challenge_method", "S256");
    authUrl.searchParams.set("state", "e2e-test");

    const authRes = await fetch(authUrl.toString(), { redirect: "manual" });
    const html = await authRes.text();

    // Extract login_id from the hidden form field
    const loginIdMatch = html.match(/name="login_id"\s+value="([^"]+)"/);
    if (!loginIdMatch) throw new Error("Could not find login_id in auth form");
    const loginId = loginIdMatch[1];
    ok("Authorize — got login form");

    // Submit API key
    const loginRes = await fetch(`${BASE}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `login_id=${loginId}&api_key=${encodeURIComponent(API_KEY)}`,
        redirect: "manual",
    });

    const location = loginRes.headers.get("location");
    if (location) {
        const callbackUrl = new URL(location);
        authCode = callbackUrl.searchParams.get("code");
        ok(`Login — got auth code=${authCode?.substring(0, 8)}...`);
    } else {
        fail("Login", `Status ${loginRes.status}, no redirect`);
    }
} catch (e) { fail("Authorize/Login", e.message); }

// 2d. Token exchange
let accessToken;
try {
    const tokenRes = await fetch(`${BASE}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
            grant_type: "authorization_code",
            code: authCode,
            redirect_uri: "http://localhost/callback",
            client_id: clientId,
            client_secret: clientSecret || "",
            code_verifier: codeVerifier,
        }).toString(),
    });
    const tokens = await tokenRes.json();
    accessToken = tokens.access_token;
    if (accessToken) {
        ok(`Token exchange — expires_in=${tokens.expires_in}s`);
    } else {
        fail("Token exchange", JSON.stringify(tokens));
    }
} catch (e) { fail("Token exchange", e.message); }

if (!accessToken) {
    console.error("\n❌ Cannot continue without access token");
    process.exit(1);
}

// ── 3. MCP Session ──────────────────────────────────────────────────────────

console.log("\n📡 MCP Protocol");

async function mcpCall(method, params = {}, sessionId = null) {
    const headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": `Bearer ${accessToken}`,
    };
    if (sessionId) headers["Mcp-Session-Id"] = sessionId;

    const res = await fetch(`${BASE}/`, {
        method: "POST",
        headers,
        body: JSON.stringify({
            jsonrpc: "2.0",
            id: crypto.randomUUID(),
            method,
            params,
        }),
    });

    const sid = res.headers.get("mcp-session-id");
    const contentType = res.headers.get("content-type") || "";
    
    let data;
    if (contentType.includes("text/event-stream")) {
        // Parse SSE response
        const text = await res.text();
        const lines = text.split("\n");
        for (const line of lines) {
            if (line.startsWith("data: ")) {
                try {
                    data = JSON.parse(line.substring(6));
                } catch {}
            }
        }
    } else {
        data = await res.json();
    }
    return { data, sessionId: sid || sessionId, status: res.status };
}

// 3a. Initialize
let sessionId;
try {
    const init = await mcpCall("initialize", {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "e2e-test", version: "1.0.0" },
    });
    sessionId = init.sessionId;
    const serverName = init.data?.result?.serverInfo?.name;
    ok(`Initialize — session=${sessionId?.substring(0, 8)}..., server=${serverName}`);
} catch (e) { fail("Initialize", e.message); }

// 3b. List tools
let toolNames = [];
try {
    const list = await mcpCall("tools/list", {}, sessionId);
    toolNames = (list.data?.result?.tools || []).map(t => t.name);
    ok(`tools/list — ${toolNames.length} tools available`);

    if (toolNames.length < 100) {
        fail("Tool count", `Expected 109, got ${toolNames.length}`);
    }
} catch (e) { fail("tools/list", e.message); }

// ── 4. Tool Calls ───────────────────────────────────────────────────────────

console.log("\n🧪 Tool Calls");

async function testTool(name, args) {
    if (!toolNames.includes(name)) {
        skip(name, "not in tools list");
        return null;
    }
    try {
        const result = await mcpCall("tools/call", { name, arguments: args }, sessionId);

        // MCP protocol-level error (e.g. -32602 validation)
        if (result.data?.error) {
            fail(name, `MCP error ${result.data.error.code}: ${result.data.error.message?.substring(0, 100)}`);
            return null;
        }

        const content = result.data?.result?.content;
        if (content && content.length > 0) {
            const summary = content[0]?.text || "";
            const text = content.map(c => c.text).join("\n");
            // Only check the summary line for errors — data content may contain
            // words like "Error" or "Premium" in entity names (e.g. "Premium Plan")
            if (summary.startsWith("Error")) {
                if (summary.includes("project-management") || summary.includes("Premium")) {
                    skip(name, "Premium API required");
                } else {
                    fail(name, summary.substring(0, 120));
                }
            } else {
                const preview = text.substring(0, 80).replace(/\n/g, " ");
                ok(`${name} — ${preview}...`);
            }
            return text;
        } else {
            fail(name, `No content: ${JSON.stringify(result.data)?.substring(0, 120)}`);
        }
    } catch (e) {
        fail(name, e.message);
    }
    return null;
}

// Core entities (original tools — top-level schema wrapped in params)
await testTool("search_customers", { params: { limit: 2 } });
await testTool("search_invoices", { params: { criteria: [] } });
await testTool("search_items", { params: { criteria: [] } });
await testTool("search_vendors", { params: { limit: 2 } });
await testTool("search_employees", { params: { limit: 2 } });
await testTool("search_bills", { params: { limit: 2 } });
await testTool("search_accounts", { params: { criteria: [] } });
await testTool("search_estimates", { params: { limit: 2 } });

// New entities (bulk tools)
await testTool("search_payments", { params: {} });
await testTool("search_credit_memos", { params: {} });
await testTool("search_sales_receipts", { params: {} });
await testTool("search_deposits", { params: {} });
await testTool("search_purchase_orders", { params: {} });
await testTool("search_vendor_credits", { params: {} });
await testTool("search_transfers", { params: {} });
await testTool("search_tax_codes", { params: {} });
await testTool("search_tax_rates", { params: {} });
await testTool("search_classes", { params: {} });
await testTool("search_departments", { params: {} });

// Projects (read-only via REST)
await testTool("search_projects", { params: {} });

// Reports (top-level params)
await testTool("report_profit_loss", { params: { date_macro: "Last Month" } });
await testTool("report_balance_sheet", { params: { date_macro: "Today" } });
await testTool("report_cash_flow", { params: { date_macro: "Last Month" } });
await testTool("report_trial_balance", { params: { date_macro: "Today" } });
await testTool("report_aged_receivables", { params: {} });
await testTool("report_aged_payables", { params: {} });

// General Ledger — limit date range to avoid huge response
await testTool("report_general_ledger", { params: {
    start_date: "2026-05-01",
    end_date: "2026-05-12",
} });

// ── Summary ─────────────────────────────────────────────────────────────────

console.log(`\n${"═".repeat(50)}`);
console.log(`  ✅ Passed:  ${passed}`);
console.log(`  ❌ Failed:  ${failed}`);
console.log(`  ⏭️  Skipped: ${skipped}`);
console.log(`${"═".repeat(50)}`);
console.log(failed > 0 ? "\n❌ E2E TEST FAILED" : "\n✅ E2E TEST PASSED");
process.exit(failed > 0 ? 1 : 0);

