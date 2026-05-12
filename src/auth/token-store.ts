/**
 * SQLite-backed persistent store for MCP OAuth tokens and QBO credentials.
 *
 * Stores:
 *   - MCP OAuth clients (registered MCP consumers)
 *   - MCP access/refresh tokens
 *   - QBO refresh token (separate from .env for Cloud Run)
 *
 * Durable backing via GCP Secret Manager:
 *   - QBO refresh token and API keys are written through to Secret Manager
 *   - On cold start, SQLite is hydrated from Secret Manager
 *   - This allows Cloud Run containers to restart without losing QBO auth
 */

import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

// ── Types ───────────────────────────────────────────────────────────────────

export interface PersistedClient {
    clientId: string;
    clientData: string; // JSON
    apiKeyHash: string;
    createdAt: number;
}

export interface PersistedToken {
    token: string;
    type: "access" | "refresh";
    clientId: string;
    scopes: string; // JSON array
    expiresAt: number;
}

export interface PersistedQBOToken {
    refreshToken: string;
    realmId: string;
    updatedAt: number;
}

export type ApiKeyRole = "admin" | "readonly" | "finance" | "editor";

export interface PersistedApiKey {
    id: string;
    keyHash: string;
    owner: string;
    role: ApiKeyRole;
    label: string;
    active: boolean;
    createdAt: number;
}

// ── Secret Manager Backend ──────────────────────────────────────────────────

const GCP_PROJECT = process.env.GCP_PROJECT ?? "spoonity-group-ordering";
const SM_QBO_TOKEN_SECRET = process.env.SM_QBO_TOKEN_SECRET ?? "qbo-mcp-qbo-token";
const SM_API_KEYS_SECRET = process.env.SM_API_KEYS_SECRET ?? "qbo-mcp-api-keys";
const SM_CLIENTS_SECRET = "qbo-mcp-clients";
const SM_TOKENS_SECRET = "qbo-mcp-tokens";

/**
 * Lazy-loaded GCP Secret Manager client.
 * Only initialized if we're in HTTP/Cloud Run mode — skipped for local stdio.
 */
class SecretManagerBackend {
    private client: any = null;
    private enabled: boolean;

    constructor() {
        this.enabled = process.env.MCP_TRANSPORT === "http" || !!process.env.K_SERVICE;
    }

    private async getClient() {
        if (!this.enabled) return null;
        if (!this.client) {
            try {
                const { SecretManagerServiceClient } = await import("@google-cloud/secret-manager");
                this.client = new SecretManagerServiceClient();
                console.error("[sm] Secret Manager client initialized");
            } catch (err) {
                console.error("[sm] Failed to initialize Secret Manager:", err);
                this.enabled = false;
                return null;
            }
        }
        return this.client;
    }

    /** Read the latest version of a secret. Returns null if not found or empty. */
    async readSecret(secretId: string): Promise<string | null> {
        const client = await this.getClient();
        if (!client) return null;

        try {
            const name = `projects/${GCP_PROJECT}/secrets/${secretId}/versions/latest`;
            const [version] = await client.accessSecretVersion({ name });
            const payload = version?.payload?.data;
            if (!payload) return null;
            const value = typeof payload === "string" ? payload : Buffer.from(payload).toString("utf8");
            return value || null;
        } catch (err: any) {
            // 404 = secret or version doesn't exist yet
            if (err.code === 5 || err.message?.includes("NOT_FOUND")) {
                console.error(`[sm] Secret ${secretId} not found — will create on first write`);
                return null;
            }
            console.error(`[sm] Error reading secret ${secretId}:`, err.message);
            return null;
        }
    }

    /** Write a new version to a secret, creating the secret if needed. */
    async writeSecret(secretId: string, data: string): Promise<void> {
        const client = await this.getClient();
        if (!client) return;

        const parent = `projects/${GCP_PROJECT}`;
        const secretName = `${parent}/secrets/${secretId}`;

        try {
            // Ensure secret exists
            try {
                await client.getSecret({ name: secretName });
            } catch (err: any) {
                if (err.code === 5 || err.message?.includes("NOT_FOUND")) {
                    await client.createSecret({
                        parent,
                        secretId,
                        secret: { replication: { automatic: {} } },
                    });
                    console.error(`[sm] Created secret: ${secretId}`);
                } else {
                    throw err;
                }
            }

            // Add new version
            await client.addSecretVersion({
                parent: secretName,
                payload: { data: Buffer.from(data, "utf8") },
            });
            console.error(`[sm] Updated secret: ${secretId}`);
        } catch (err: any) {
            console.error(`[sm] Error writing secret ${secretId}:`, err.message);
        }
    }

    isEnabled(): boolean {
        return this.enabled;
    }
}

// ── Store ───────────────────────────────────────────────────────────────────

const DB_DIR = process.env.QBO_MCP_DATA_DIR ?? join(homedir(), ".qbo-mcp");
const DB_PATH = join(DB_DIR, "store.db");

export class TokenStore {
    private db: Database.Database;
    private sm: SecretManagerBackend;
    private smHydrated = false;

    constructor(dbPath?: string) {
        const p = dbPath ?? DB_PATH;
        mkdirSync(DB_DIR, { recursive: true });
        this.db = new Database(p);
        this.db.pragma("journal_mode = WAL");
        this.migrate();
        this.sm = new SecretManagerBackend();
    }

    /**
     * Hydrate SQLite from Secret Manager on cold start.
     * Call this once before any reads. It's idempotent.
     */
    async hydrate(): Promise<void> {
        if (this.smHydrated || !this.sm.isEnabled()) return;
        this.smHydrated = true;

        console.error("[sm] Hydrating from Secret Manager...");

        // ── QBO Token ───────────────────────────────────────────────────
        const qboRaw = await this.sm.readSecret(SM_QBO_TOKEN_SECRET);
        if (qboRaw) {
            try {
                const { refreshToken, realmId } = JSON.parse(qboRaw);
                if (refreshToken && realmId) {
                    // Only overwrite if SQLite is empty (fresh container)
                    const existing = this.getQBOToken();
                    if (!existing) {
                        this._saveQBOTokenLocal(refreshToken, realmId);
                        console.error(`[sm] Hydrated QBO token (realm: ${realmId})`);
                    } else {
                        console.error("[sm] QBO token already in SQLite — skipping hydration");
                    }
                }
            } catch (err) {
                console.error("[sm] Failed to parse QBO token secret:", err);
            }
        } else {
            console.error("[sm] No QBO token in Secret Manager");
        }

        // ── API Keys ────────────────────────────────────────────────────
        const keysRaw = await this.sm.readSecret(SM_API_KEYS_SECRET);
        if (keysRaw) {
            try {
                const keys: PersistedApiKey[] = JSON.parse(keysRaw);
                // Only hydrate if SQLite has no keys (fresh container)
                const existingKeys = this.getAllApiKeys();
                if (existingKeys.length === 0 && keys.length > 0) {
                    for (const key of keys) {
                        this._saveApiKeyLocal(key);
                    }
                    console.error(`[sm] Hydrated ${keys.length} API key(s)`);
                } else {
                    console.error(`[sm] ${existingKeys.length} API key(s) already in SQLite — skipping hydration`);
                }
            } catch (err) {
                console.error("[sm] Failed to parse API keys secret:", err);
            }
        } else {
            console.error("[sm] No API keys in Secret Manager");
        }

        // ── MCP OAuth Clients ────────────────────────────────────────────
        const clientsRaw = await this.sm.readSecret(SM_CLIENTS_SECRET);
        if (clientsRaw) {
            try {
                const clients: PersistedClient[] = JSON.parse(clientsRaw);
                const existingClients = this.getAllClients();
                if (existingClients.length === 0 && clients.length > 0) {
                    for (const c of clients) {
                        this._saveClientLocal(c);
                    }
                    console.error(`[sm] Hydrated ${clients.length} MCP OAuth client(s)`);
                } else {
                    console.error(`[sm] ${existingClients.length} client(s) already in SQLite — skipping hydration`);
                }
            } catch (err) {
                console.error("[sm] Failed to parse clients secret:", err);
            }
        } else {
            console.error("[sm] No MCP clients in Secret Manager");
        }

        // ── MCP OAuth Tokens ─────────────────────────────────────────────
        const tokensRaw = await this.sm.readSecret(SM_TOKENS_SECRET);
        if (tokensRaw) {
            try {
                const tokens: (PersistedToken & { role?: string; owner?: string })[] = JSON.parse(tokensRaw);
                // Only hydrate non-expired tokens into a fresh SQLite
                const existingAccess = this.getAllTokens("access");
                const existingRefresh = this.getAllTokens("refresh");
                if (existingAccess.length === 0 && existingRefresh.length === 0 && tokens.length > 0) {
                    let count = 0;
                    for (const t of tokens) {
                        if (t.expiresAt > Date.now()) {
                            this._saveTokenLocal(t);
                            count++;
                        }
                    }
                    console.error(`[sm] Hydrated ${count} MCP OAuth token(s) (${tokens.length - count} expired, skipped)`);
                } else {
                    console.error(`[sm] ${existingAccess.length + existingRefresh.length} token(s) already in SQLite — skipping hydration`);
                }
            } catch (err) {
                console.error("[sm] Failed to parse tokens secret:", err);
            }
        } else {
            console.error("[sm] No MCP tokens in Secret Manager");
        }
    }

    private migrate(): void {
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS clients (
                client_id   TEXT PRIMARY KEY,
                client_data TEXT NOT NULL,
                api_key_hash TEXT NOT NULL DEFAULT '',
                created_at  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tokens (
                token       TEXT PRIMARY KEY,
                type        TEXT NOT NULL CHECK(type IN ('access', 'refresh')),
                client_id   TEXT NOT NULL,
                scopes      TEXT NOT NULL DEFAULT '[]',
                role        TEXT NOT NULL DEFAULT 'admin',
                owner       TEXT NOT NULL DEFAULT '',
                expires_at  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS qbo_tokens (
                id              INTEGER PRIMARY KEY CHECK(id = 1),
                refresh_token   TEXT NOT NULL,
                realm_id        TEXT NOT NULL,
                updated_at      INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS api_keys (
                id          TEXT PRIMARY KEY,
                key_hash    TEXT NOT NULL UNIQUE,
                owner       TEXT NOT NULL,
                role        TEXT NOT NULL DEFAULT 'readonly',
                label       TEXT NOT NULL DEFAULT '',
                active      INTEGER NOT NULL DEFAULT 1,
                created_at  INTEGER NOT NULL
            );
        `);
    }

    // ── MCP Clients ─────────────────────────────────────────────────────

    /** Save client to SQLite only (used during hydration). */
    private _saveClientLocal(client: PersistedClient): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO clients (client_id, client_data, api_key_hash, created_at)
            VALUES (?, ?, ?, ?)
        `).run(client.clientId, client.clientData, client.apiKeyHash, client.createdAt);
    }

    /** Save client to SQLite + write-through to Secret Manager. */
    saveClient(client: PersistedClient): void {
        this._saveClientLocal(client);
        this.syncClientsToSM();
    }

    getClient(clientId: string): PersistedClient | undefined {
        return this.db.prepare(`
            SELECT client_id AS clientId, client_data AS clientData,
                   api_key_hash AS apiKeyHash, created_at AS createdAt
            FROM clients WHERE client_id = ?
        `).get(clientId) as PersistedClient | undefined;
    }

    getAllClients(): PersistedClient[] {
        return this.db.prepare(`
            SELECT client_id AS clientId, client_data AS clientData,
                   api_key_hash AS apiKeyHash, created_at AS createdAt
            FROM clients
        `).all() as PersistedClient[];
    }

    // ── MCP Tokens ──────────────────────────────────────────────────────

    /** Save token to SQLite only (used during hydration). */
    private _saveTokenLocal(tok: PersistedToken & { role?: string; owner?: string }): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO tokens (token, type, client_id, scopes, role, owner, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(tok.token, tok.type, tok.clientId, tok.scopes, tok.role ?? "admin", tok.owner ?? "", tok.expiresAt);
    }

    /** Save token to SQLite + write-through to Secret Manager. */
    saveToken(tok: PersistedToken & { role?: string; owner?: string }): void {
        this._saveTokenLocal(tok);
        this.syncTokensToSM();
    }

    getAllTokens(type: "access" | "refresh"): (PersistedToken & { role: string; owner: string })[] {
        return this.db.prepare(`
            SELECT token, type, client_id AS clientId, scopes, role, owner, expires_at AS expiresAt
            FROM tokens WHERE type = ?
        `).all(type) as (PersistedToken & { role: string; owner: string })[];
    }

    deleteToken(token: string, type: string): void {
        this.db.prepare(`DELETE FROM tokens WHERE token = ? AND type = ?`).run(token, type);
        this.syncTokensToSM();
    }

    pruneExpired(): number {
        const r = this.db.prepare(`DELETE FROM tokens WHERE expires_at < ? AND expires_at != 0`)
            .run(Date.now());
        return r.changes;
    }

    // ── API Keys ────────────────────────────────────────────────────────

    /** Save API key to SQLite only (used during hydration). */
    private _saveApiKeyLocal(key: PersistedApiKey): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO api_keys (id, key_hash, owner, role, label, active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(key.id, key.keyHash, key.owner, key.role, key.label, key.active ? 1 : 0, key.createdAt);
    }

    /** Save API key to SQLite + write-through to Secret Manager. */
    saveApiKey(key: PersistedApiKey): void {
        this._saveApiKeyLocal(key);
        this.syncApiKeysToSM();
    }

    getApiKeyByHash(keyHash: string): PersistedApiKey | undefined {
        const row = this.db.prepare(`
            SELECT id, key_hash AS keyHash, owner, role, label, active, created_at AS createdAt
            FROM api_keys WHERE key_hash = ? AND active = 1
        `).get(keyHash) as any;
        return row ? { ...row, active: !!row.active } : undefined;
    }

    getAllApiKeys(): PersistedApiKey[] {
        return (this.db.prepare(`
            SELECT id, key_hash AS keyHash, owner, role, label, active, created_at AS createdAt
            FROM api_keys ORDER BY created_at DESC
        `).all() as any[]).map(r => ({ ...r, active: !!r.active }));
    }

    /** Deactivate API key in SQLite + write-through to Secret Manager. */
    deactivateApiKey(id: string): void {
        this.db.prepare(`UPDATE api_keys SET active = 0 WHERE id = ?`).run(id);
        this.syncApiKeysToSM();
    }

    /** Write all API keys to Secret Manager (fire-and-forget). */
    private syncApiKeysToSM(): void {
        const keys = this.getAllApiKeys();
        this.sm.writeSecret(SM_API_KEYS_SECRET, JSON.stringify(keys)).catch(err => {
            console.error("[sm] Failed to sync API keys:", err);
        });
    }

    /** Write all MCP OAuth clients to Secret Manager (fire-and-forget). */
    private syncClientsToSM(): void {
        const clients = this.getAllClients();
        this.sm.writeSecret(SM_CLIENTS_SECRET, JSON.stringify(clients)).catch(err => {
            console.error("[sm] Failed to sync MCP clients:", err);
        });
    }

    /** Write all MCP OAuth tokens to Secret Manager (fire-and-forget). */
    private syncTokensToSM(): void {
        // Only persist non-expired tokens
        const access = this.getAllTokens("access").filter(t => t.expiresAt > Date.now());
        const refresh = this.getAllTokens("refresh").filter(t => t.expiresAt > Date.now());
        const all = [...access, ...refresh];
        this.sm.writeSecret(SM_TOKENS_SECRET, JSON.stringify(all)).catch(err => {
            console.error("[sm] Failed to sync MCP tokens:", err);
        });
    }

    // ── QBO Tokens ──────────────────────────────────────────────────────

    /** Save QBO token to SQLite only (used during hydration). */
    private _saveQBOTokenLocal(refreshToken: string, realmId: string): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO qbo_tokens (id, refresh_token, realm_id, updated_at)
            VALUES (1, ?, ?, ?)
        `).run(refreshToken, realmId, Date.now());
    }

    /** Save QBO token to SQLite + write-through to Secret Manager. */
    saveQBOToken(refreshToken: string, realmId: string): void {
        this._saveQBOTokenLocal(refreshToken, realmId);

        // Write-through to Secret Manager (fire-and-forget)
        this.sm.writeSecret(
            SM_QBO_TOKEN_SECRET,
            JSON.stringify({ refreshToken, realmId, updatedAt: Date.now() })
        ).catch(err => {
            console.error("[sm] Failed to sync QBO token:", err);
        });
    }

    getQBOToken(): PersistedQBOToken | undefined {
        return this.db.prepare(`
            SELECT refresh_token AS refreshToken, realm_id AS realmId, updated_at AS updatedAt
            FROM qbo_tokens WHERE id = 1
        `).get() as PersistedQBOToken | undefined;
    }
}
