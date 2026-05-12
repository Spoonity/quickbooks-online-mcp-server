import { quickbooksClient } from "../clients/quickbooks-client.js";
import { ToolResponse } from "../types/tool-response.js";
import { formatError } from "../helpers/format-error.js";

/**
 * Get a single project by ID via the QBO REST Query API.
 */
export async function getQuickbooksProject(id: string): Promise<ToolResponse<any>> {
    try {
        await quickbooksClient.authenticate();
        const qb = quickbooksClient.getQuickbooks();

        const sanitize = (val: string): string => val.replace(/['\\]/g, "");
        const query = `SELECT * FROM Project WHERE Id = '${sanitize(id)}'`;

        return new Promise((resolve) => {
            (qb as any).query(query, (err: any, data: any) => {
                if (err) {
                    resolve({
                        result: null,
                        isError: true,
                        error: formatError(err),
                    });
                } else {
                    // query returns QueryResponse with array; extract single entity
                    const projects = data?.QueryResponse?.Project;
                    if (projects && projects.length > 0) {
                        resolve({
                            result: projects[0],
                            isError: false,
                            error: null,
                        });
                    } else {
                        resolve({
                            result: null,
                            isError: true,
                            error: `Project with ID '${id}' not found.`,
                        });
                    }
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
