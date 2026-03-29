#!/usr/bin/env node

/**
 * QuickBooks Online MCP Server — Production-Grade
 *
 * Dual transport: stdio (local) and HTTP (Cloud Run).
 * HTTP mode includes OAuth 2.1 authentication, rate limiting, and session management.
 *
 * Environment Variables:
 *   QUICKBOOKS_CLIENT_ID        — Intuit app client ID
 *   QUICKBOOKS_CLIENT_SECRET    — Intuit app client secret
 *   QUICKBOOKS_REFRESH_TOKEN    — Initial QBO refresh token (optional if using setup endpoint)
 *   QUICKBOOKS_REALM_ID         — QBO company ID
 *   QUICKBOOKS_ENVIRONMENT      — "production" or "sandbox"
 *   QBO_REDIRECT_URI            — OAuth callback URL for QBO auth
 *   MCP_TRANSPORT               — "http" or "stdio" (default: stdio)
 *   MCP_PORT / PORT             — HTTP port (default: 3100, Cloud Run injects PORT)
 *   MCP_BASE_URL                — Public base URL for OAuth metadata
 *   MCP_API_KEY                 — Shared secret for MCP authentication
 *   MCP_CORS_ORIGIN             — CORS origin (default: *)
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { QuickbooksMCPServer } from "./server/qbo-mcp-server.js";
import { RegisterTool } from "./helpers/register-tool.js";
import { quickbooksClient } from "./clients/quickbooks-client.js";
import type { ApiKeyRole } from "./auth/token-store.js";

// Tool imports
import { CreateCustomerTool } from "./tools/create-customer.tool.js";
import { GetCustomerTool } from "./tools/get-customer.tool.js";
import { UpdateCustomerTool } from "./tools/update-customer.tool.js";
import { DeleteCustomerTool } from "./tools/delete-customer.tool.js";
import { SearchCustomersTool } from "./tools/search-customers.tool.js";
import { CreateEstimateTool } from "./tools/create-estimate.tool.js";
import { GetEstimateTool } from "./tools/get-estimate.tool.js";
import { UpdateEstimateTool } from "./tools/update-estimate.tool.js";
import { DeleteEstimateTool } from "./tools/delete-estimate.tool.js";
import { SearchEstimatesTool } from "./tools/search-estimates.tool.js";
import { CreateBillTool } from "./tools/create-bill.tool.js";
import { UpdateBillTool } from "./tools/update-bill.tool.js";
import { DeleteBillTool } from "./tools/delete-bill.tool.js";
import { GetBillTool } from "./tools/get-bill.tool.js";
import { SearchBillsTool } from "./tools/search-bills.tool.js";
import { ReadInvoiceTool } from "./tools/read-invoice.tool.js";
import { SearchInvoicesTool } from "./tools/search-invoices.tool.js";
import { CreateInvoiceTool } from "./tools/create-invoice.tool.js";
import { UpdateInvoiceTool } from "./tools/update-invoice.tool.js";
import { CreateAccountTool } from "./tools/create-account.tool.js";
import { UpdateAccountTool } from "./tools/update-account.tool.js";
import { SearchAccountsTool } from "./tools/search-accounts.tool.js";
import { ReadItemTool } from "./tools/read-item.tool.js";
import { SearchItemsTool } from "./tools/search-items.tool.js";
import { CreateItemTool } from "./tools/create-item.tool.js";
import { UpdateItemTool } from "./tools/update-item.tool.js";
import { CreateVendorTool } from "./tools/create-vendor.tool.js";
import { UpdateVendorTool } from "./tools/update-vendor.tool.js";
import { DeleteVendorTool } from "./tools/delete-vendor.tool.js";
import { GetVendorTool } from "./tools/get-vendor.tool.js";
import { SearchVendorsTool } from "./tools/search-vendors.tool.js";
import { CreateEmployeeTool } from "./tools/create-employee.tool.js";
import { GetEmployeeTool } from "./tools/get-employee.tool.js";
import { UpdateEmployeeTool } from "./tools/update-employee.tool.js";
import { SearchEmployeesTool } from "./tools/search-employees.tool.js";
import { CreateJournalEntryTool } from "./tools/create-journal-entry.tool.js";
import { GetJournalEntryTool } from "./tools/get-journal-entry.tool.js";
import { UpdateJournalEntryTool } from "./tools/update-journal-entry.tool.js";
import { DeleteJournalEntryTool } from "./tools/delete-journal-entry.tool.js";
import { SearchJournalEntriesTool } from "./tools/search-journal-entries.tool.js";
import { CreateBillPaymentTool } from "./tools/create-bill-payment.tool.js";
import { GetBillPaymentTool } from "./tools/get-bill-payment.tool.js";
import { UpdateBillPaymentTool } from "./tools/update-bill-payment.tool.js";
import { DeleteBillPaymentTool } from "./tools/delete-bill-payment.tool.js";
import { SearchBillPaymentsTool } from "./tools/search-bill-payments.tool.js";
import { CreatePurchaseTool } from "./tools/create-purchase.tool.js";
import { GetPurchaseTool } from "./tools/get-purchase.tool.js";
import { UpdatePurchaseTool } from "./tools/update-purchase.tool.js";
import { DeletePurchaseTool } from "./tools/delete-purchase.tool.js";
import { SearchPurchasesTool } from "./tools/search-purchases.tool.js";

// ── Configuration ───────────────────────────────────────────────────────────

const TRANSPORT = process.env.MCP_TRANSPORT ?? (process.argv.includes("--http") ? "http" : "stdio");
const PORT = parseInt(process.env.PORT ?? process.env.MCP_PORT ?? "3100", 10);
const BASE_URL = process.env.MCP_BASE_URL ?? `http://localhost:${PORT}`;
const CORS_ORIGIN = process.env.MCP_CORS_ORIGIN ?? "*";
const MAX_SESSIONS = parseInt(process.env.MCP_MAX_SESSIONS ?? "50", 10);
const SESSION_TTL_MS = parseInt(process.env.MCP_SESSION_TTL_MS ?? String(30 * 60 * 1000), 10);

// ── All tool definitions ────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ALL_TOOLS: Array<{ name: string; description: string; schema: any; handler: any }> = [
    CreateCustomerTool, GetCustomerTool, UpdateCustomerTool, DeleteCustomerTool, SearchCustomersTool,
    CreateEstimateTool, GetEstimateTool, UpdateEstimateTool, DeleteEstimateTool, SearchEstimatesTool,
    CreateBillTool, UpdateBillTool, DeleteBillTool, GetBillTool, SearchBillsTool,
    ReadInvoiceTool, SearchInvoicesTool, CreateInvoiceTool, UpdateInvoiceTool,
    CreateAccountTool, UpdateAccountTool, SearchAccountsTool,
    ReadItemTool, SearchItemsTool, CreateItemTool, UpdateItemTool,
    CreateVendorTool, UpdateVendorTool, DeleteVendorTool, GetVendorTool, SearchVendorsTool,
    CreateEmployeeTool, GetEmployeeTool, UpdateEmployeeTool, SearchEmployeesTool,
    CreateJournalEntryTool, GetJournalEntryTool, UpdateJournalEntryTool, DeleteJournalEntryTool, SearchJournalEntriesTool,
    CreateBillPaymentTool, GetBillPaymentTool, UpdateBillPaymentTool, DeleteBillPaymentTool, SearchBillPaymentsTool,
    CreatePurchaseTool, GetPurchaseTool, UpdatePurchaseTool, DeletePurchaseTool, SearchPurchasesTool,
];

/** Register all tools (used in stdio mode — full access). */
function registerAllTools(server: ReturnType<typeof QuickbooksMCPServer.GetServer>): void {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    for (const tool of ALL_TOOLS) RegisterTool(server, tool as any);
}

/** Register only tools allowed for the given role (used in HTTP mode). */
function registerToolsForRole(server: ReturnType<typeof QuickbooksMCPServer.GetServer>, role: ApiKeyRole): number {
    // Dynamic import of isToolAllowedForRole would create a circular dep,
    // so we define the role check inline using the same logic.
    const ROLE_PERMS: Record<string, { allowed: string[]; denied: string[] }> = {
        admin:    { allowed: ["*"], denied: [] },
        readonly: { allowed: ["search_customers", "get_customer", "search_invoices", "read_invoice", "search_estimates", "get_estimate", "search_items", "read_item", "search_bills", "get_bill", "search_vendors", "get_vendor"], denied: [] },
        finance:  { allowed: ["search_", "get_", "read_", "create_invoice", "update_invoice", "create_bill", "update_bill", "create_bill_payment", "update_bill_payment", "get_bill_payment", "search_bill_payment", "create_purchase", "update_purchase", "get_purchase", "search_purchase", "search_accounts", "create_account", "update_account", "create_journal_entry", "update_journal_entry", "get_journal_entry", "search_journal_entry"], denied: ["delete_"] },
        editor:   { allowed: ["*"], denied: ["delete_"] },
    };
    const perms = ROLE_PERMS[role] ?? ROLE_PERMS.readonly;
    let count = 0;
    for (const tool of ALL_TOOLS) {
        let denied = false;
        for (const p of perms.denied) { if (tool.name.startsWith(p)) { denied = true; break; } }
        if (denied) continue;
        let allowed = perms.allowed.includes("*");
        if (!allowed) {
            for (const p of perms.allowed) {
                // Entries ending with _ are prefix matches, others are exact matches
                if (p.endsWith("_") ? tool.name.startsWith(p) : tool.name === p) { allowed = true; break; }
            }
        }
        if (allowed) { RegisterTool(server, tool as any); count++; }
    }
    return count;
}

// ═══════════════════════════════════════════════════════════════════════════
//  STARTUP
// ═══════════════════════════════════════════════════════════════════════════

async function main() {
    if (TRANSPORT === "http") {
        await startHttpServer();
    } else {
        await startStdioServer();
    }
}

// ─── Stdio Transport ────────────────────────────────────────────────────────

async function startStdioServer() {
    const server = QuickbooksMCPServer.GetServer();
    registerAllTools(server);

    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("[qbo-mcp] Running in stdio mode (50 tools)");
}

// ─── HTTP Transport (with OAuth) ────────────────────────────────────────────

async function startHttpServer() {
    const express = (await import("express")).default;
    const { StreamableHTTPServerTransport } = await import("@modelcontextprotocol/sdk/server/streamableHttp.js");
    const { mcpAuthRouter } = await import("@modelcontextprotocol/sdk/server/auth/router.js");
    const { requireBearerAuth } = await import("@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js");
    const { rateLimit } = await import("express-rate-limit");
    const { QBOOAuthProvider } = await import("./auth/provider.js");
    const { TokenStore } = await import("./auth/token-store.js");
    const { randomUUID } = await import("node:crypto");
    const { McpServer } = await import("@modelcontextprotocol/sdk/server/mcp.js");

    const app = express();
    app.set("trust proxy", 1);

    // ── Persistent store ────────────────────────────────────────────────
    const tokenStore = new TokenStore();
    quickbooksClient.setTokenStore(tokenStore);

    // ── MCP OAuth provider ──────────────────────────────────────────────
    const oauthProvider = new QBOOAuthProvider();
    oauthProvider.setStore(tokenStore);

    const issuerUrl = new URL(BASE_URL);

    // ── Rate limiters ───────────────────────────────────────────────────
    const tokenRateLimiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        limit: 15,
        standardHeaders: "draft-7",
        legacyHeaders: false,
        message: { error: "Too many authentication attempts." },
    });

    const loginRateLimiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        limit: 10,
        standardHeaders: "draft-7",
        legacyHeaders: false,
        message: { error: "Too many login attempts." },
    });

    // ── Auth routes ─────────────────────────────────────────────────────
    app.use("/token", tokenRateLimiter);
    app.post("/login", loginRateLimiter, express.urlencoded({ extended: false }), oauthProvider.handleLoginPost);
    app.use("/authorize", oauthProvider.captureAuthorizeRedirectUri);

    try {
        app.use(mcpAuthRouter({
            provider: oauthProvider,
            issuerUrl,
            baseUrl: issuerUrl,
            scopesSupported: [],
            resourceName: "QuickBooks MCP Server",
        }));
        console.error("[oauth] Auth router mounted");
    } catch (err) {
        console.error("[oauth] FATAL: Failed to mount auth router:", err);
        process.exit(1);
    }

    // ── CORS ────────────────────────────────────────────────────────────
    app.use((_req, res, next) => {
        res.header("Access-Control-Allow-Origin", CORS_ORIGIN);
        res.header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        res.header("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization, Mcp-Session-Id, Last-Event-ID");
        res.header("Access-Control-Expose-Headers", "Mcp-Session-Id");
        if (_req.method === "OPTIONS") { res.sendStatus(204); return; }
        next();
    });

    // ── Bearer auth middleware ───────────────────────────────────────────
    const bearerAuth = requireBearerAuth({ verifier: oauthProvider });

    // ── Health endpoint ─────────────────────────────────────────────────
    app.get("/health", (_req, res) => {
        res.json({
            status: "ok",
            qboConnected: quickbooksClient.hasCredentials(),
            activeSessions: sessions.size,
        });
    });

    // ── QBO Setup endpoint (for initial/re-auth) ────────────────────────
    app.get("/auth/quickbooks/setup", (_req, res) => {
        const authUrl = quickbooksClient.getAuthorizationUrl();
        res.redirect(302, authUrl);
    });

    app.get("/auth/quickbooks/callback", async (req, res) => {
        try {
            await quickbooksClient.handleOAuthCallback(req.url);
            res.send(`<html><body style="display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;background:#f0fdf4">
                <div style="text-align:center">
                    <h2 style="color:#16a34a">✓ QuickBooks Connected!</h2>
                    <p style="color:#666;margin-top:8px;">Token saved. You can close this tab.</p>
                </div>
            </body></html>`);
        } catch (err: any) {
            console.error("[qbo] OAuth callback error:", err);
            res.status(500).send(`<html><body style="display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;background:#fef2f2">
                <div style="text-align:center">
                    <h2 style="color:#dc2626">Error connecting QuickBooks</h2>
                    <p style="color:#666;margin-top:8px;">${err.message}</p>
                </div>
            </body></html>`);
        }
    });

    // ── Landing page ────────────────────────────────────────────────────
    app.get("/", (_req, res) => {
        if (_req.headers.accept?.includes("text/html")) {
            res.send(renderLandingPage());
            return;
        }
        // Non-browser clients get 405 (MCP expects POST)
        res.status(405).json({ error: "Method not allowed. Use POST for MCP messages." });
    });

    // ── Session management ──────────────────────────────────────────────
    type SessionEntry = {
        server: InstanceType<typeof McpServer>;
        transport: InstanceType<typeof StreamableHTTPServerTransport>;
        timer: ReturnType<typeof setTimeout>;
    };
    const sessions = new Map<string, SessionEntry>();

    // ── MCP endpoint ────────────────────────────────────────────────────
    app.post("/", bearerAuth, async (req, res) => {
        try {
            const sessionId = req.headers["mcp-session-id"] as string | undefined;
            const existing = sessionId ? sessions.get(sessionId) : undefined;

            if (existing) {
                clearTimeout(existing.timer);
                existing.timer = setTimeout(() => {
                    sessions.delete(sessionId!);
                    existing.transport.close?.();
                    console.error(`[session] Expired: ${sessionId}`);
                }, SESSION_TTL_MS);
                await existing.transport.handleRequest(req, res);
                return;
            }

            if (sessionId) {
                res.status(404).json({
                    jsonrpc: "2.0",
                    error: { code: -32000, message: "Session not found. Please re-initialize." },
                });
                return;
            }

            if (sessions.size >= MAX_SESSIONS) {
                res.status(429).json({ error: "Too many active sessions." });
                return;
            }

            // Extract role from auth context
            const authInfo = (req as any).auth;
            const role: ApiKeyRole = (authInfo?.extra?.role as ApiKeyRole) || "readonly";
            const owner: string = (authInfo?.extra?.owner as string) || "unknown";

            // Create new session with role-filtered tools
            const sessionServer = QuickbooksMCPServer.GetServerInstance();
            const toolCount = registerToolsForRole(sessionServer, role);

            const transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: () => randomUUID(),
                enableJsonResponse: true,
            });

            await sessionServer.connect(transport);
            await transport.handleRequest(req, res);

            const sid = transport.sessionId;
            if (sid) {
                const timer = setTimeout(() => {
                    sessions.delete(sid);
                    transport.close?.();
                    console.error(`[session] Expired: ${sid} (total: ${sessions.size})`);
                }, SESSION_TTL_MS);
                sessions.set(sid, { server: sessionServer, transport, timer });
                console.error(`[session] New: ${sid} (role: ${role}, owner: ${owner}, tools: ${toolCount}, total: ${sessions.size})`);
            }
        } catch (err) {
            console.error("[mcp] Error:", err);
            if (!res.headersSent) res.status(500).json({ error: "Internal server error" });
        }
    });

    // ── GET/ DELETE for SSE and session cleanup ──────────────────────────
    app.get("/", bearerAuth, async (req, res) => {
        const sessionId = req.headers["mcp-session-id"] as string;
        const existing = sessionId ? sessions.get(sessionId) : undefined;
        if (!existing) { res.status(404).json({ error: "Session not found" }); return; }
        await existing.transport.handleRequest(req, res);
    });

    app.delete("/", bearerAuth, async (req, res) => {
        const sessionId = req.headers["mcp-session-id"] as string;
        const existing = sessionId ? sessions.get(sessionId) : undefined;
        if (existing) {
            clearTimeout(existing.timer);
            sessions.delete(sessionId);
            existing.transport.close?.();
        }
        res.sendStatus(204);
    });

    // ── Admin: API Key Management ────────────────────────────────────────
    // Protected by a simple check: only admin keys can manage keys.
    // Usage: curl -H "Authorization: Bearer <admin-token>" /admin/keys

    app.get("/admin/keys", bearerAuth, async (req, res) => {
        const authInfo = (req as any).auth;
        if (authInfo?.extra?.role !== "admin") {
            res.status(403).json({ error: "Admin access required" });
            return;
        }
        const keys = tokenStore.getAllApiKeys().map(k => ({
            id: k.id,
            owner: k.owner,
            role: k.role,
            label: k.label,
            active: k.active,
            createdAt: new Date(k.createdAt).toISOString(),
        }));
        res.json({ keys });
    });

    app.post("/admin/keys", bearerAuth, express.json(), async (req, res) => {
        const authInfo = (req as any).auth;
        if (authInfo?.extra?.role !== "admin") {
            res.status(403).json({ error: "Admin access required" });
            return;
        }
        const { owner, role, label } = req.body;
        if (!owner || !role) {
            res.status(400).json({ error: "owner and role are required" });
            return;
        }
        const validRoles = ["admin", "readonly", "finance", "editor"];
        if (!validRoles.includes(role)) {
            res.status(400).json({ error: `role must be one of: ${validRoles.join(", ")}` });
            return;
        }
        // Generate a new API key
        const { randomBytes } = await import("node:crypto");
        const rawKey = randomBytes(30).toString("base64url");
        const { createHash: ch } = await import("node:crypto");

        tokenStore.saveApiKey({
            id: randomUUID(),
            keyHash: ch("sha256").update(rawKey).digest("hex"),
            owner,
            role,
            label: label || `${role} key for ${owner}`,
            active: true,
            createdAt: Date.now(),
        });

        console.error(`[admin] Created ${role} API key for ${owner}`);
        // Return the raw key ONCE — it can't be retrieved later
        res.json({
            apiKey: rawKey,
            owner,
            role,
            label: label || `${role} key for ${owner}`,
            warning: "Save this key now — it cannot be retrieved again.",
        });
    });

    app.delete("/admin/keys/:id", bearerAuth, async (req, res) => {
        const authInfo = (req as any).auth;
        if (authInfo?.extra?.role !== "admin") {
            res.status(403).json({ error: "Admin access required" });
            return;
        }
        tokenStore.deactivateApiKey(req.params.id as string);
        console.error(`[admin] Deactivated key: ${req.params.id}`);
        res.json({ success: true });
    });

    // ── Start ───────────────────────────────────────────────────────────
    app.listen(PORT, () => {
        console.error(`[qbo-mcp] HTTP server running on port ${PORT}`);
        console.error(`[qbo-mcp] Base URL: ${BASE_URL}`);
        console.error(`[qbo-mcp] QBO connected: ${quickbooksClient.hasCredentials()}`);
        console.error(`[qbo-mcp] ${ALL_TOOLS.length} tools registered`);
    });
}

// ── Landing Page ────────────────────────────────────────────────────────────

function renderLandingPage(): string {
    return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>QuickBooks MCP Server</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:48px;max-width:520px;width:100%;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,0.4)}
.badge{display:inline-block;background:#172554;color:#3b82f6;padding:4px 12px;border-radius:999px;font-size:12px;font-weight:600;margin-bottom:16px}
h1{font-size:24px;font-weight:700;margin-bottom:8px}
.sub{color:#94a3b8;font-size:14px;margin-bottom:24px}
.stat{display:flex;justify-content:center;gap:32px;margin-bottom:24px}
.stat div{text-align:center}
.stat .num{font-size:28px;font-weight:700;color:#3b82f6}
.stat .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#64748b}
.links{border-top:1px solid #334155;padding-top:20px;font-size:13px;color:#64748b}
a{color:#3b82f6;text-decoration:none}
a:hover{text-decoration:underline}
</style></head><body>
<div class="card">
<div class="badge">MCP Server</div>
<h1>QuickBooks Online</h1>
<p class="sub">Production-grade MCP server for QuickBooks Online with OAuth 2.1 authentication</p>
<div class="stat">
  <div><div class="num">50</div><div class="lbl">Tools</div></div>
  <div><div class="num">10</div><div class="lbl">Entity Types</div></div>
</div>
<div class="links">
  <a href="/.well-known/oauth-authorization-server">OAuth Discovery</a> · 
  <a href="/health">Health Check</a> · 
  <a href="/auth/quickbooks/setup">QBO Setup</a>
</div>
</div>
</body></html>`;
}

main().catch((error) => {
    console.error("Fatal:", error);
    process.exit(1);
});