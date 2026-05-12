import { quickbooksClient } from "../clients/quickbooks-client.js";
import { ToolResponse } from "../types/tool-response.js";
import { formatError } from "../helpers/format-error.js";

/**
 * Generic CRUD handler for QuickBooks Online entities.
 *
 * Replaces the need for individual handler files per entity/operation.
 * Maps operation + entity to the correct node-quickbooks method.
 */

type CrudOp = "create" | "get" | "search" | "update" | "delete" | "void";

/** Mapping of entity keys to node-quickbooks method fragments */
const ENTITY_MAP: Record<string, { singular: string; plural: string }> = {
    Payment:       { singular: "Payment",       plural: "Payments" },
    CreditMemo:    { singular: "CreditMemo",    plural: "CreditMemos" },
    SalesReceipt:  { singular: "SalesReceipt",  plural: "SalesReceipts" },
    Deposit:       { singular: "Deposit",       plural: "Deposits" },
    PurchaseOrder: { singular: "PurchaseOrder",  plural: "PurchaseOrders" },
    VendorCredit:  { singular: "VendorCredit",   plural: "VendorCredits" },
    Transfer:      { singular: "Transfer",       plural: "Transfers" },
    TaxCode:       { singular: "TaxCode",        plural: "TaxCodes" },
    TaxRate:       { singular: "TaxRate",         plural: "TaxRates" },
    Class:         { singular: "Class",          plural: "Classes" },
    Department:    { singular: "Department",      plural: "Departments" },
};

function getMethodName(op: CrudOp, entity: string): string {
    const e = ENTITY_MAP[entity];
    if (!e) throw new Error(`Unknown entity: ${entity}`);

    switch (op) {
        case "create": return `create${e.singular}`;
        case "get":    return `get${e.singular}`;
        case "search": return `find${e.plural}`;
        case "update": return `update${e.singular}`;
        case "delete": return `delete${e.singular}`;
        case "void":   return `void${e.singular}`;
    }
}

/** Create a new entity */
export async function createEntity(entity: string, payload: any): Promise<ToolResponse<any>> {
    try {
        await quickbooksClient.authenticate();
        const qb = quickbooksClient.getQuickbooks();
        const method = getMethodName("create", entity);

        return new Promise((resolve) => {
            (qb as any)[method](payload, (err: any, result: any) => {
                if (err) {
                    resolve({ result: null, isError: true, error: formatError(err) });
                } else {
                    resolve({ result, isError: false, error: null });
                }
            });
        });
    } catch (error) {
        return { result: null, isError: true, error: formatError(error) };
    }
}

/** Get a single entity by ID */
export async function getEntity(entity: string, id: string): Promise<ToolResponse<any>> {
    try {
        await quickbooksClient.authenticate();
        const qb = quickbooksClient.getQuickbooks();
        const method = getMethodName("get", entity);

        return new Promise((resolve) => {
            (qb as any)[method](id, (err: any, result: any) => {
                if (err) {
                    resolve({ result: null, isError: true, error: formatError(err) });
                } else {
                    resolve({ result, isError: false, error: null });
                }
            });
        });
    } catch (error) {
        return { result: null, isError: true, error: formatError(error) };
    }
}

/** Search/find entities with criteria */
export async function searchEntities(entity: string, criteria: any = {}): Promise<ToolResponse<any>> {
    try {
        await quickbooksClient.authenticate();
        const qb = quickbooksClient.getQuickbooks();
        const method = getMethodName("search", entity);
        const e = ENTITY_MAP[entity];

        return new Promise((resolve) => {
            (qb as any)[method](criteria, (err: any, data: any) => {
                if (err) {
                    resolve({ result: null, isError: true, error: formatError(err) });
                } else {
                    // node-quickbooks returns { QueryResponse: { EntityName: [...] } }
                    const items = data?.QueryResponse?.[e.singular] ?? data?.QueryResponse ?? [];
                    resolve({ result: items, isError: false, error: null });
                }
            });
        });
    } catch (error) {
        return { result: null, isError: true, error: formatError(error) };
    }
}

/** Update an entity (payload must include Id and SyncToken) */
export async function updateEntity(entity: string, payload: any): Promise<ToolResponse<any>> {
    try {
        await quickbooksClient.authenticate();
        const qb = quickbooksClient.getQuickbooks();
        const method = getMethodName("update", entity);

        return new Promise((resolve) => {
            (qb as any)[method](payload, (err: any, result: any) => {
                if (err) {
                    resolve({ result: null, isError: true, error: formatError(err) });
                } else {
                    resolve({ result, isError: false, error: null });
                }
            });
        });
    } catch (error) {
        return { result: null, isError: true, error: formatError(error) };
    }
}

/** Delete an entity (requires Id and SyncToken) */
export async function deleteEntity(entity: string, idOrPayload: any): Promise<ToolResponse<any>> {
    try {
        await quickbooksClient.authenticate();
        const qb = quickbooksClient.getQuickbooks();
        const method = getMethodName("delete", entity);

        return new Promise((resolve) => {
            (qb as any)[method](idOrPayload, (err: any, result: any) => {
                if (err) {
                    resolve({ result: null, isError: true, error: formatError(err) });
                } else {
                    resolve({ result, isError: false, error: null });
                }
            });
        });
    } catch (error) {
        return { result: null, isError: true, error: formatError(error) };
    }
}

/** Void a transaction (Payments, Invoices) */
export async function voidEntity(entity: string, idOrPayload: any): Promise<ToolResponse<any>> {
    try {
        await quickbooksClient.authenticate();
        const qb = quickbooksClient.getQuickbooks();
        const method = getMethodName("void", entity);

        if (typeof (qb as any)[method] !== "function") {
            return { result: null, isError: true, error: `Void is not supported for ${entity}.` };
        }

        return new Promise((resolve) => {
            (qb as any)[method](idOrPayload, (err: any, result: any) => {
                if (err) {
                    resolve({ result: null, isError: true, error: formatError(err) });
                } else {
                    resolve({ result, isError: false, error: null });
                }
            });
        });
    } catch (error) {
        return { result: null, isError: true, error: formatError(error) };
    }
}
