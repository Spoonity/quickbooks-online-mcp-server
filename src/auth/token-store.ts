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
                expires_at  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS qbo_tokens (
                id              INTEGER PRIMARY KEY CHECK(id = 1),
                refresh_token   TEXT NOT NULL,
                realm_id        TEXT NOT NULL,
                updated_at      INTEGER NOT NULL
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

    saveToken(tok: PersistedToken): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO tokens (token, type, client_id, scopes, expires_at)
            VALUES (?, ?, ?, ?, ?)
        `).run(tok.token, tok.type, tok.clientId, tok.scopes, tok.expiresAt);
    }

    getAllTokens(type: "access" | "refresh"): PersistedToken[] {
        return this.db.prepare(`
            SELECT token, type, client_id AS clientId, scopes, expires_at AS expiresAt
            FROM tokens WHERE type = ?
        `).all(type) as PersistedToken[];
    }

    deleteToken(token: string, type: string): void {
        this.db.prepare(`DELETE FROM tokens WHERE token = ? AND type = ?`).run(token, type);
    }

    pruneExpired(): number {
        const r = this.db.prepare(`DELETE FROM tokens WHERE expires_at < ? AND expires_at != 0`)
            .run(Date.now());
        return r.changes;
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
