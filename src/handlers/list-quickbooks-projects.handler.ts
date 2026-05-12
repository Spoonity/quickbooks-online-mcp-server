import { quickbooksClient } from "../clients/quickbooks-client.js";
import { ToolResponse } from "../types/tool-response.js";
import { formatError } from "../helpers/format-error.js";

/**
 * List / search projects via the QBO REST Query API.
 *
 * Uses the standard Accounting scope (com.intuit.quickbooks.accounting).
 * The Project entity supports read-only queries via:
 *   SELECT * FROM Project [WHERE ...]
 *
 * Note: Creating/updating projects requires the Premium GraphQL API
 * (project-management.project scope + Silver+ partner tier).
 */

export interface ListProjectsOptions {
    status?: string;
    customerRef?: string;
    nameContains?: string;
    maxResults?: number;
    startPosition?: number;
}

export async function listQuickbooksProjects(
    options: ListProjectsOptions = {}
): Promise<ToolResponse<any>> {
    try {
        await quickbooksClient.authenticate();
        const qb = quickbooksClient.getQuickbooks();

        // Sanitize input to prevent query injection
        const sanitize = (val: string): string => val.replace(/['\\]/g, "");

        // Build the SQL-like query
        const conditions: string[] = [];
        if (options.status) {
            conditions.push(`Status = '${sanitize(options.status)}'`);
        }
        if (options.customerRef) {
            conditions.push(`CustomerRef = '${sanitize(options.customerRef)}'`);
        }
        if (options.nameContains) {
            conditions.push(`Name LIKE '%${sanitize(options.nameContains)}%'`);
        }

        let query = "SELECT * FROM Project";
        if (conditions.length > 0) {
            query += ` WHERE ${conditions.join(" AND ")}`;
        }

        const maxResults = Math.min(options.maxResults ?? 100, 1000);
        const startPosition = options.startPosition ?? 1;
        query += ` MAXRESULTS ${maxResults} STARTPOSITION ${startPosition}`;

        return new Promise((resolve) => {
            // node-quickbooks doesn't have a native Project method,
            // so we use the raw query endpoint
            (qb as any).query(query, (err: any, data: any) => {
                if (err) {
                    resolve({
                        result: null,
                        isError: true,
                        error: formatError(err),
                    });
                } else {
                    resolve({
                        result: data,
                        isError: false,
                        error: null,
                    });
                }
            });
        });
    } catch (error) {
        return {
            result: null,
            isError: true,
            error: formatError(error),
        };
    }
}
