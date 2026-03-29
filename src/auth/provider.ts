/**
 * QBO MCP OAuth 2.1 Provider — Multi-Key Role-Based Authentication
 *
 * Supports multiple API keys with different roles:
 *   - admin:    Full access to all 50 tools
 *   - readonly: Only search/get/read tools
 *   - finance:  Invoices, bills, bill payments, accounts, purchases
 *   - editor:   Everything except delete tools
 *
 * On first boot with no keys in the DB, creates an admin key from
 * MCP_API_KEY env var (backward compatible).
 *
 * Supports:
 *   - Dynamic Client Registration (DCR)
 *   - Browser-based login form (ChatGPT, Claude)
 *   - PKCE
 *   - Token rotation
 */

import { Response, Request, NextFunction } from "express";
import {
    OAuthServerProvider,
    AuthorizationParams,
} from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import {
    OAuthClientInformationFull,
    OAuthTokenRevocationRequest,
    OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { randomUUID, createHash } from "node:crypto";
import { TokenStore, ApiKeyRole } from "./token-store.js";

// ── Configuration ───────────────────────────────────────────────────────────

const BOOTSTRAP_API_KEY = process.env.MCP_API_KEY ?? "";
const ACCESS_TOKEN_TTL_S = 24 * 60 * 60; // 24 hours

function hashKey(key: string): string {
    return createHash("sha256").update(key).digest("hex");
}

// ── Tool Access Control ─────────────────────────────────────────────────────

/**
 * Defines which tool name prefixes each role can access.
 * Tool names follow the pattern: action_entity (e.g. search_customers, create_invoice)
 */
const ROLE_PERMISSIONS: Record<ApiKeyRole, { allowedPrefixes: string[]; deniedPrefixes: string[] }> = {
    admin: {
        allowedPrefixes: ["*"],  // everything
        deniedPrefixes: [],
    },
    readonly: {
        allowedPrefixes: ["search_", "get_", "read_"],
        deniedPrefixes: [],
    },
    finance: {
        allowedPrefixes: [
            "search_", "get_", "read_",       // all reads
            "create_invoice", "update_invoice", // invoices
            "create_bill", "update_bill",       // bills
            "create_bill_payment", "update_bill_payment", "get_bill_payment", "search_bill_payment",
            "create_purchase", "update_purchase", "get_purchase", "search_purchase",
            "search_accounts", "create_account", "update_account",
            "create_journal_entry", "update_journal_entry", "get_journal_entry", "search_journal_entry",
        ],
        deniedPrefixes: ["delete_"],
    },
    editor: {
        allowedPrefixes: ["*"],  // everything except delete
        deniedPrefixes: ["delete_"],
    },
};

export function isToolAllowedForRole(toolName: string, role: ApiKeyRole): boolean {
    const perms = ROLE_PERMISSIONS[role];
    if (!perms) return false;

    // Check denied first
    for (const prefix of perms.deniedPrefixes) {
        if (toolName.startsWith(prefix)) return false;
    }

    // Check allowed
    if (perms.allowedPrefixes.includes("*")) return true;
    for (const prefix of perms.allowedPrefixes) {
        if (toolName.startsWith(prefix)) return true;
    }

    return false;
}

/** Get a human-readable description of what a role can do */
export function getRoleDescription(role: ApiKeyRole): string {
    switch (role) {
        case "admin": return "Full access — all tools including create, update, delete";
        case "readonly": return "Read-only — search, get, and read tools only";
        case "finance": return "Finance — read all + invoices, bills, payments, accounts, journals (no delete)";
        case "editor": return "Editor — all tools except delete";
        default: return "Unknown role";
    }
}

// ── Known Redirect URIs ─────────────────────────────────────────────────────

const KNOWN_REDIRECT_URIS: string[] = [
    "https://claude.ai/api/mcp/auth_callback",
    "https://chatgpt.com/connector_platform_oauth_redirect",
    "https://platform.openai.com/apps-manage/oauth",
    "http://localhost/callback",
    "http://127.0.0.1/callback",
];

function isLocalhostRedirectUri(uri: string): boolean {
    try {
        const u = new URL(uri);
        return (
            u.protocol === "http:" &&
            (u.hostname === "localhost" || u.hostname === "127.0.0.1") &&
            u.pathname === "/callback"
        );
    } catch {
        return false;
    }
}

// ── Token & Auth Code Entries ───────────────────────────────────────────────

interface AuthCodeEntry {
    clientId: string;
    codeChallenge: string;
    redirectUri: string;
    role: ApiKeyRole;
    owner: string;
    expiresAt: number;
}

interface TokenEntry {
    clientId: string;
    scopes: string[];
    role: ApiKeyRole;
    owner: string;
    expiresAt: number;
}

// ── Client Store ────────────────────────────────────────────────────────────

class QBOClientStore implements OAuthRegisteredClientsStore {
    clients = new Map<string, OAuthClientInformationFull>();
    private store: TokenStore | null = null;
    _pendingRedirectUri: string | null = null;

    setStore(store: TokenStore): void {
        this.store = store;
        for (const pc of store.getAllClients()) {
            try {
                this.clients.set(pc.clientId, JSON.parse(pc.clientData));
            } catch (err) {
                console.error(`[store] Failed to rehydrate client ${pc.clientId}:`, err);
            }
        }
        console.error(`[store] Rehydrated ${this.clients.size} client(s)`);
    }

    getClient(clientId: string): OAuthClientInformationFull | undefined {
        const existing = this.clients.get(clientId);
        if (existing) {
            for (const uri of KNOWN_REDIRECT_URIS) {
                if (!existing.redirect_uris.includes(uri)) {
                    existing.redirect_uris.push(uri);
                }
            }
            if (this._pendingRedirectUri && !existing.redirect_uris.includes(this._pendingRedirectUri)) {
                existing.redirect_uris.push(this._pendingRedirectUri);
                this._pendingRedirectUri = null;
            }
            return existing;
        }
        return undefined;
    }

    registerClient(
        client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">
    ): OAuthClientInformationFull {
        const clientId = (client as any).client_id ?? randomUUID();
        const full: OAuthClientInformationFull = {
            ...client,
            client_id: clientId,
            client_id_issued_at: Math.floor(Date.now() / 1000),
        };
        this.clients.set(clientId, full);
        this.store?.saveClient({
            clientId,
            clientData: JSON.stringify(full),
            apiKeyHash: "",
            createdAt: Date.now(),
        });
        console.error(`[oauth] Registered client: ${clientId}`);
        return full;
    }
}

// ── Provider ────────────────────────────────────────────────────────────────

export class QBOOAuthProvider implements OAuthServerProvider {
    private _clientsStore = new QBOClientStore();
    private authCodes = new Map<string, AuthCodeEntry>();
    private accessTokens = new Map<string, TokenEntry>();
    private refreshTokens = new Map<string, TokenEntry>();
    private store: TokenStore | null = null;

    setStore(store: TokenStore): void {
        this.store = store;
        const pruned = store.pruneExpired();
        if (pruned > 0) console.error(`[store] Pruned ${pruned} expired token(s)`);

        this._clientsStore.setStore(store);

        // Bootstrap: if no API keys exist and MCP_API_KEY is set, create an admin key
        const existingKeys = store.getAllApiKeys();
        if (existingKeys.length === 0 && BOOTSTRAP_API_KEY) {
            store.saveApiKey({
                id: randomUUID(),
                keyHash: hashKey(BOOTSTRAP_API_KEY),
                owner: "max@spoonity.com",
                role: "admin",
                label: "Bootstrap admin key",
                active: true,
                createdAt: Date.now(),
            });
            console.error(`[auth] Bootstrapped admin API key from MCP_API_KEY env var`);
        }

        // Log key count
        const allKeys = store.getAllApiKeys();
        console.error(`[auth] ${allKeys.length} API key(s) registered:`);
        for (const k of allKeys) {
            console.error(`  - ${k.label || k.id.substring(0, 8)} (${k.role}, owner: ${k.owner}, active: ${k.active})`);
        }

        // Rehydrate tokens
        for (const pt of store.getAllTokens("access")) {
            if (pt.expiresAt < Date.now()) continue;
            this.accessTokens.set(pt.token, {
                clientId: pt.clientId,
                scopes: JSON.parse(pt.scopes),
                role: (pt.role as ApiKeyRole) || "admin",
                owner: pt.owner || "",
                expiresAt: pt.expiresAt,
            });
        }
        for (const pt of store.getAllTokens("refresh")) {
            this.refreshTokens.set(pt.token, {
                clientId: pt.clientId,
                scopes: JSON.parse(pt.scopes),
                role: (pt.role as ApiKeyRole) || "admin",
                owner: pt.owner || "",
                expiresAt: pt.expiresAt,
            });
        }
        console.error(`[store] Rehydrated ${this.accessTokens.size} access, ${this.refreshTokens.size} refresh token(s)`);
    }

    get clientsStore(): OAuthRegisteredClientsStore {
        return this._clientsStore;
    }

    // ── Middleware ────────────────────────────────────────────────────────

    captureAuthorizeRedirectUri = (req: Request, _res: Response, next: NextFunction): void => {
        const redirectUri = (req.query?.redirect_uri ?? req.body?.redirect_uri) as string | undefined;
        if (redirectUri && isLocalhostRedirectUri(redirectUri)) {
            const clientId = (req.query?.client_id ?? req.body?.client_id) as string | undefined;
            if (clientId) {
                const client = this._clientsStore.clients.get(clientId);
                if (client && !client.redirect_uris.includes(redirectUri)) {
                    client.redirect_uris.push(redirectUri);
                }
            }
            this._clientsStore._pendingRedirectUri = redirectUri;
        }
        next();
    };

    // ── Authorize ────────────────────────────────────────────────────────

    readonly pendingAuthorize = new Map<string, {
        client: OAuthClientInformationFull;
        params: AuthorizationParams;
    }>();

    async authorize(
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
        res: Response
    ): Promise<void> {
        const loginId = randomUUID();
        this.pendingAuthorize.set(loginId, { client, params });
        setTimeout(() => this.pendingAuthorize.delete(loginId), 10 * 60 * 1000);

        res.setHeader("Content-Type", "text/html");
        res.send(this.renderLoginForm(loginId));
    }

    handleLoginPost = (req: Request, res: Response): void => {
        const { login_id, api_key } = req.body;

        const pending = this.pendingAuthorize.get(login_id);
        if (!pending) {
            res.status(400).send("Login session expired. Please try again.");
            return;
        }

        if (!api_key) {
            res.status(403).send("API key is required.");
            return;
        }

        // Look up the key in the database
        const keyHash = hashKey(api_key);
        const apiKeyEntry = this.store?.getApiKeyByHash(keyHash);

        if (!apiKeyEntry) {
            console.error(`[auth] Invalid API key attempt (hash: ${keyHash.substring(0, 16)}...)`);
            res.status(403).send("Invalid API key.");
            return;
        }

        this.pendingAuthorize.delete(login_id);
        console.error(`[auth] Authenticated: ${apiKeyEntry.owner} (role: ${apiKeyEntry.role}, label: ${apiKeyEntry.label})`);
        this.completeAuthorize(pending.client, pending.params, apiKeyEntry.role, apiKeyEntry.owner, res);
    };

    private completeAuthorize(
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
        role: ApiKeyRole,
        owner: string,
        res: Response
    ): void {
        const code = randomUUID();
        this.authCodes.set(code, {
            clientId: client.client_id,
            codeChallenge: params.codeChallenge,
            redirectUri: params.redirectUri,
            role,
            owner,
            expiresAt: Date.now() + 5 * 60 * 1000,
        });

        const redirectUrl = new URL(params.redirectUri);
        redirectUrl.searchParams.set("code", code);
        if (params.state) redirectUrl.searchParams.set("state", params.state);

        res.redirect(302, redirectUrl.toString());
    }

    // ── PKCE ─────────────────────────────────────────────────────────────

    async challengeForAuthorizationCode(
        _client: OAuthClientInformationFull,
        authorizationCode: string
    ): Promise<string> {
        const entry = this.authCodes.get(authorizationCode);
        if (!entry || Date.now() > entry.expiresAt) {
            throw new Error("Invalid or expired authorization code");
        }
        return entry.codeChallenge;
    }

    // ── Token Exchange ───────────────────────────────────────────────────

    async exchangeAuthorizationCode(
        client: OAuthClientInformationFull,
        authorizationCode: string,
    ): Promise<OAuthTokens> {
        const entry = this.authCodes.get(authorizationCode);
        if (!entry || Date.now() > entry.expiresAt) {
            throw new Error("Invalid or expired authorization code");
        }
        if (entry.clientId !== client.client_id) {
            throw new Error("Authorization code does not match client");
        }
        this.authCodes.delete(authorizationCode);

        const accessToken = randomUUID();
        const refreshToken = randomUUID();
        const expiresAt = Date.now() + ACCESS_TOKEN_TTL_S * 1000;

        const tokenEntry: TokenEntry = {
            clientId: client.client_id,
            scopes: [],
            role: entry.role,
            owner: entry.owner,
            expiresAt,
        };

        this.accessTokens.set(accessToken, tokenEntry);
        this.refreshTokens.set(refreshToken, { ...tokenEntry, expiresAt: Infinity });

        const persistBase = { clientId: client.client_id, scopes: "[]", role: entry.role, owner: entry.owner };
        this.store?.saveToken({ ...persistBase, token: accessToken, type: "access", expiresAt });
        this.store?.saveToken({ ...persistBase, token: refreshToken, type: "refresh", expiresAt: Infinity });

        console.error(`[oauth] Issued tokens — role: ${entry.role}, owner: ${entry.owner}`);

        return {
            access_token: accessToken,
            token_type: "Bearer",
            expires_in: ACCESS_TOKEN_TTL_S,
            refresh_token: refreshToken,
        };
    }

    // ── Refresh ──────────────────────────────────────────────────────────

    async exchangeRefreshToken(
        client: OAuthClientInformationFull,
        refreshToken: string,
    ): Promise<OAuthTokens> {
        const entry = this.refreshTokens.get(refreshToken);
        if (!entry || entry.clientId !== client.client_id) {
            throw new Error("Invalid refresh token");
        }

        const newAccessToken = randomUUID();
        const newRefreshToken = randomUUID();
        const newExpiry = Date.now() + ACCESS_TOKEN_TTL_S * 1000;

        this.accessTokens.set(newAccessToken, { ...entry, expiresAt: newExpiry });
        this.refreshTokens.set(newRefreshToken, { ...entry, expiresAt: Date.now() + 90 * 24 * 60 * 60 * 1000 });

        this.refreshTokens.delete(refreshToken);
        this.store?.deleteToken(refreshToken, "refresh");

        const persistBase = { clientId: entry.clientId, scopes: "[]", role: entry.role, owner: entry.owner };
        this.store?.saveToken({ ...persistBase, token: newAccessToken, type: "access", expiresAt: newExpiry });
        this.store?.saveToken({ ...persistBase, token: newRefreshToken, type: "refresh", expiresAt: Infinity });

        return {
            access_token: newAccessToken,
            token_type: "Bearer",
            expires_in: ACCESS_TOKEN_TTL_S,
            refresh_token: newRefreshToken,
        };
    }

    // ── Verify ───────────────────────────────────────────────────────────

    async verifyAccessToken(token: string): Promise<AuthInfo> {
        const entry = this.accessTokens.get(token);
        if (!entry) throw new Error("Invalid access token");
        if (Date.now() > entry.expiresAt) {
            this.accessTokens.delete(token);
            throw new Error("Access token expired");
        }
        return {
            token,
            clientId: entry.clientId,
            scopes: entry.scopes,
            expiresAt: Math.floor(entry.expiresAt / 1000),
            extra: {
                role: entry.role,
                owner: entry.owner,
            },
        };
    }

    // ── Revoke ───────────────────────────────────────────────────────────

    async revokeToken(
        _client: OAuthClientInformationFull,
        request: OAuthTokenRevocationRequest
    ): Promise<void> {
        const { token } = request;
        if (this.accessTokens.has(token)) {
            this.accessTokens.delete(token);
            this.store?.deleteToken(token, "access");
        }
        if (this.refreshTokens.has(token)) {
            this.refreshTokens.delete(token);
            this.store?.deleteToken(token, "refresh");
        }
    }

    // ── Login Form ──────────────────────────────────────────────────────

    private renderLoginForm(loginId: string): string {
        return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect — QuickBooks MCP</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0f172a; color: #e2e8f0; min-height: 100vh;
    display: flex; align-items: center; justify-content: center; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 16px;
    padding: 40px; width: 100%; max-width: 400px; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }
  .logo { text-align: center; margin-bottom: 24px; }
  .logo svg { width: 48px; height: 48px; }
  h1 { text-align: center; font-size: 20px; font-weight: 600; margin-bottom: 8px; }
  .subtitle { text-align: center; font-size: 13px; color: #94a3b8; margin-bottom: 28px; }
  label { display: block; font-size: 11px; text-transform: uppercase;
    letter-spacing: 0.05em; color: #94a3b8; margin-bottom: 6px; }
  input { width: 100%; padding: 12px 14px; background: #0f172a; border: 1px solid #475569;
    border-radius: 8px; color: #fff; font-size: 14px; outline: none;
    transition: border-color 0.2s; margin-bottom: 16px; }
  input:focus { border-color: #2563eb; }
  button { width: 100%; padding: 12px; border: none; border-radius: 8px; cursor: pointer;
    font-size: 14px; font-weight: 600; color: #fff;
    background: linear-gradient(135deg, #2563eb, #3b82f6); transition: opacity 0.2s; }
  button:hover { opacity: 0.9; }
</style>
</head><body>
<div class="card">
  <div class="logo">
    <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="24" cy="24" r="24" fill="#2563eb"/>
      <text x="24" y="30" text-anchor="middle" fill="white" font-size="18" font-weight="bold" font-family="sans-serif">QB</text>
    </svg>
  </div>
  <h1>QuickBooks MCP Server</h1>
  <p class="subtitle">Enter your API key to connect</p>
  <form method="POST" action="/login">
    <input type="hidden" name="login_id" value="${loginId}">
    <label for="api_key">API Key</label>
    <input type="password" id="api_key" name="api_key" placeholder="Enter your MCP API key" required autofocus>
    <button type="submit">Connect</button>
  </form>
</div>
</body></html>`;
    }
}
