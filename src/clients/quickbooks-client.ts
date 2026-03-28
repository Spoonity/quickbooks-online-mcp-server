/**
 * QuickBooks Online API Client
 *
 * Handles OAuth token management with auto-refresh and rotation.
 * Tokens are persisted to SQLite (via TokenStore) instead of .env files.
 *
 * On Cloud Run:
 *   - Initial QBO auth is done via /auth/quickbooks/setup endpoint
 *   - Refresh tokens auto-rotate and persist to SQLite
 *   - If refresh token expires, server shows setup instructions via health endpoint
 *
 * Locally:
 *   - Falls back to .env for initial credentials
 *   - Browser OAuth flow for re-auth (startOAuthFlow)
 */

import dotenv from "dotenv";
import QuickBooks from "node-quickbooks";
import OAuthClient from "intuit-oauth";
import http from "http";
import open from "open";
import { TokenStore } from "../auth/token-store.js";

dotenv.config();

const client_id = process.env.QUICKBOOKS_CLIENT_ID;
const client_secret = process.env.QUICKBOOKS_CLIENT_SECRET;
const environment = process.env.QUICKBOOKS_ENVIRONMENT || "production";
const redirect_uri = process.env.QBO_REDIRECT_URI || "http://localhost:3000/auth/quickbooks/callback";

if (!client_id || !client_secret) {
    throw Error("QUICKBOOKS_CLIENT_ID and QUICKBOOKS_CLIENT_SECRET must be set");
}

class QuickbooksClient {
    private readonly clientId: string;
    private readonly clientSecret: string;
    private refreshToken?: string;
    private realmId?: string;
    private readonly environment: string;
    private accessToken?: string;
    private accessTokenExpiry?: Date;
    private quickbooksInstance?: QuickBooks;
    private oauthClient: OAuthClient;
    private redirectUri: string;
    private tokenStore: TokenStore | null = null;

    constructor(config: {
        clientId: string;
        clientSecret: string;
        refreshToken?: string;
        realmId?: string;
        environment: string;
        redirectUri: string;
    }) {
        this.clientId = config.clientId;
        this.clientSecret = config.clientSecret;
        this.refreshToken = config.refreshToken;
        this.realmId = config.realmId;
        this.environment = config.environment;
        this.redirectUri = config.redirectUri;
        this.oauthClient = new OAuthClient({
            clientId: this.clientId,
            clientSecret: this.clientSecret,
            environment: this.environment,
            redirectUri: this.redirectUri,
        });
    }

    /** Attach persistent store. Overrides env-based token if DB has a newer one. */
    setTokenStore(store: TokenStore): void {
        this.tokenStore = store;
        const saved = store.getQBOToken();
        if (saved) {
            this.refreshToken = saved.refreshToken;
            this.realmId = saved.realmId;
            console.error(`[qbo] Loaded token from DB (updated: ${new Date(saved.updatedAt).toISOString()})`);
        }
    }

    /** Returns true if the client has a refresh token available. */
    hasCredentials(): boolean {
        return !!(this.refreshToken && this.realmId);
    }

    /** Get the OAuth authorization URL for initial setup. */
    getAuthorizationUrl(state: string = "qbo-setup"): string {
        return this.oauthClient.authorizeUri({
            scope: [OAuthClient.scopes.Accounting as string],
            state,
        }).toString();
    }

    /** Handle the OAuth callback — exchange code for tokens. */
    async handleOAuthCallback(url: string): Promise<void> {
        const response = await this.oauthClient.createToken(url);
        const tokens = response.token as any;

        this.refreshToken = tokens.refresh_token;
        this.realmId = tokens.realmId;

        // Persist to SQLite
        if (this.refreshToken && this.realmId) {
            this.tokenStore?.saveQBOToken(this.refreshToken, this.realmId);
            console.error(`[qbo] OAuth callback: tokens saved to DB`);
        }
    }

    /**
     * Local-only: opens browser for OAuth flow.
     * Not used on Cloud Run — use /auth/quickbooks/setup instead.
     */
    async startLocalOAuthFlow(): Promise<void> {
        const port = new URL(this.redirectUri).port || "3000";
        const pathname = new URL(this.redirectUri).pathname;

        return new Promise((resolve, reject) => {
            const server = http.createServer(async (req, res) => {
                if (!req.url?.startsWith(pathname)) return;
                try {
                    await this.handleOAuthCallback(req.url);
                    res.writeHead(200, { "Content-Type": "text/html" });
                    res.end(`<html><body style="display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;background:#f0fdf4"><h2 style="color:#16a34a">✓ QuickBooks connected! You can close this tab.</h2></body></html>`);
                    setTimeout(() => { server.close(); resolve(); }, 1000);
                } catch (error) {
                    console.error("[qbo] OAuth error:", error);
                    res.writeHead(500, { "Content-Type": "text/html" });
                    res.end(`<html><body style="display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;background:#fef2f2"><h2 style="color:#dc2626">Error — check console</h2></body></html>`);
                    reject(error);
                }
            });

            server.listen(parseInt(port), async () => {
                const authUri = this.getAuthorizationUrl();
                console.error(`[qbo] Opening browser for authorization...`);
                await open(authUri);
            });

            server.on("error", reject);
        });
    }

    async refreshAccessToken(): Promise<{ access_token: string; expires_in: number }> {
        if (!this.refreshToken) {
            // In stdio mode, try local OAuth flow
            if (process.env.MCP_TRANSPORT !== "http") {
                await this.startLocalOAuthFlow();
                if (!this.refreshToken) {
                    throw new Error("Failed to obtain refresh token");
                }
            } else {
                throw new Error("QBO not connected. Visit /auth/quickbooks/setup to authorize.");
            }
        }

        try {
            const authResponse = await this.oauthClient.refreshUsingToken(this.refreshToken);
            this.accessToken = authResponse.token.access_token;

            // Rotate refresh token
            const tokens = authResponse.token as any;
            if (tokens.refresh_token) {
                this.refreshToken = tokens.refresh_token;
                // Persist rotated token
                if (this.realmId) {
                    this.tokenStore?.saveQBOToken(this.refreshToken!, this.realmId);
                }
                console.error("[qbo] Refresh token rotated and saved");
            }

            const expiresIn = authResponse.token.expires_in || 3600;
            this.accessTokenExpiry = new Date(Date.now() + expiresIn * 1000);

            return { access_token: this.accessToken, expires_in: expiresIn };
        } catch (error: any) {
            // Expired refresh token — clear it
            if (error.message?.includes("400") || error.statusCode === 400) {
                console.error("[qbo] Refresh token expired — needs re-authorization");
                this.refreshToken = undefined;

                if (process.env.MCP_TRANSPORT !== "http") {
                    await this.startLocalOAuthFlow();
                    if (this.refreshToken) {
                        return this.refreshAccessToken();
                    }
                }
                throw new Error("QBO refresh token expired. Visit /auth/quickbooks/setup to re-authorize.");
            }
            throw new Error(`Failed to refresh QBO token: ${error.message}`);
        }
    }

    async authenticate(): Promise<QuickBooks> {
        if (!this.refreshToken || !this.realmId) {
            if (process.env.MCP_TRANSPORT !== "http") {
                await this.startLocalOAuthFlow();
                if (!this.refreshToken || !this.realmId) {
                    throw new Error("Failed to obtain QBO credentials");
                }
            } else {
                throw new Error("QBO not connected. Visit /auth/quickbooks/setup to authorize.");
            }
        }

        const now = new Date();
        if (!this.accessToken || !this.accessTokenExpiry || this.accessTokenExpiry <= now) {
            await this.refreshAccessToken();
        }

        this.quickbooksInstance = new QuickBooks(
            this.clientId,
            this.clientSecret,
            this.accessToken!,
            false,
            this.realmId!,
            this.environment === "sandbox",
            false,
            null,
            "2.0",
            this.refreshToken
        );

        return this.quickbooksInstance;
    }

    getQuickbooks(): QuickBooks {
        if (!this.quickbooksInstance) {
            throw new Error("QuickBooks not authenticated. Call authenticate() first");
        }
        return this.quickbooksInstance;
    }
}

// ── Singleton ───────────────────────────────────────────────────────────────

export const quickbooksClient = new QuickbooksClient({
    clientId: client_id,
    clientSecret: client_secret,
    refreshToken: process.env.QUICKBOOKS_REFRESH_TOKEN,
    realmId: process.env.QUICKBOOKS_REALM_ID,
    environment,
    redirectUri: redirect_uri,
});
