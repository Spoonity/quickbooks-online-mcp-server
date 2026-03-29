/**
 * SQLite-backed persistent store for MCP OAuth tokens and QBO credentials.
 *
 * Stores:
 *   - MCP OAuth clients (registered MCP consumers)
 *   - MCP access/refresh tokens
 *   - QBO refresh token (separate from .env for Cloud Run)
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

// ── Store ───────────────────────────────────────────────────────────────────

const DB_DIR = process.env.QBO_MCP_DATA_DIR ?? join(homedir(), ".qbo-mcp");
const DB_PATH = join(DB_DIR, "store.db");

export class TokenStore {
    private db: Database.Database;

    constructor(dbPath?: string) {
        const p = dbPath ?? DB_PATH;
        mkdirSync(DB_DIR, { recursive: true });
        this.db = new Database(p);
        this.db.pragma("journal_mode = WAL");
        this.migrate();
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

    saveClient(client: PersistedClient): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO clients (client_id, client_data, api_key_hash, created_at)
            VALUES (?, ?, ?, ?)
        `).run(client.clientId, client.clientData, client.apiKeyHash, client.createdAt);
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

    saveToken(tok: PersistedToken & { role?: string; owner?: string }): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO tokens (token, type, client_id, scopes, role, owner, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(tok.token, tok.type, tok.clientId, tok.scopes, tok.role ?? "admin", tok.owner ?? "", tok.expiresAt);
    }

    getAllTokens(type: "access" | "refresh"): (PersistedToken & { role: string; owner: string })[] {
        return this.db.prepare(`
            SELECT token, type, client_id AS clientId, scopes, role, owner, expires_at AS expiresAt
            FROM tokens WHERE type = ?
        `).all(type) as (PersistedToken & { role: string; owner: string })[];
    }

    deleteToken(token: string, type: string): void {
        this.db.prepare(`DELETE FROM tokens WHERE token = ? AND type = ?`).run(token, type);
    }

    pruneExpired(): number {
        const r = this.db.prepare(`DELETE FROM tokens WHERE expires_at < ? AND expires_at != 0`)
            .run(Date.now());
        return r.changes;
    }

    // ── API Keys ────────────────────────────────────────────────────────

    saveApiKey(key: PersistedApiKey): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO api_keys (id, key_hash, owner, role, label, active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(key.id, key.keyHash, key.owner, key.role, key.label, key.active ? 1 : 0, key.createdAt);
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

    deactivateApiKey(id: string): void {
        this.db.prepare(`UPDATE api_keys SET active = 0 WHERE id = ?`).run(id);
    }

    // ── QBO Tokens ──────────────────────────────────────────────────────

    saveQBOToken(refreshToken: string, realmId: string): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO qbo_tokens (id, refresh_token, realm_id, updated_at)
            VALUES (1, ?, ?, ?)
        `).run(refreshToken, realmId, Date.now());
    }

    getQBOToken(): PersistedQBOToken | undefined {
        return this.db.prepare(`
            SELECT refresh_token AS refreshToken, realm_id AS realmId, updated_at AS updatedAt
            FROM qbo_tokens WHERE id = 1
        `).get() as PersistedQBOToken | undefined;
    }
}
