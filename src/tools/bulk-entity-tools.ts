/**
 * Bulk entity tool definitions — Payments, Credit Memos, Sales Receipts,
 * Deposits, Purchase Orders, Vendor Credits, Transfers, Tax Codes,
 * Tax Rates, Classes, and Departments.
 *
 * Uses the generic CRUD handler to avoid per-entity handler boilerplate.
 */

import { createEntity, getEntity, searchEntities, updateEntity, deleteEntity, voidEntity } from "../handlers/generic-quickbooks-crud.handler.js";
import { ToolDefinition } from "../types/tool-definition.js";
import { z } from "zod";

// ─── Helper: tool factory ──────────────────────────────────────────────────

function makeSearchTool(
    entity: string,
    name: string,
    description: string
): ToolDefinition<any> {
    const schema = z.object({
        criteria: z.any().optional().describe("Search criteria object or array of { field, value, operator? } objects. Supports operators: =, IN, LIKE, >, <, >=, <=. Also accepts limit, offset, asc, desc."),
    });
    return {
        name,
        description,
        schema,
        handler: async (args: any) => {
            const params = args.params ?? {};
            const response = await searchEntities(entity, params.criteria ?? {});
            if (response.isError) {
                return { content: [{ type: "text" as const, text: `Error: ${response.error}` }] };
            }
            const items = Array.isArray(response.result) ? response.result : [response.result];
            return {
                content: [
                    { type: "text" as const, text: `Found ${items.length} result(s):` },
                    ...items.map((i: any) => ({ type: "text" as const, text: JSON.stringify(i) })),
                ],
            };
        },
    };
}

function makeGetTool(
    entity: string,
    name: string,
    description: string
): ToolDefinition<any> {
    const schema = z.object({ id: z.string().describe("The QBO entity ID.") });
    return {
        name,
        description,
        schema,
        handler: async (args: any) => {
            const params = args.params ?? {};
            const response = await getEntity(entity, params.id);
            if (response.isError) {
                return { content: [{ type: "text" as const, text: `Error: ${response.error}` }] };
            }
            return { content: [{ type: "text" as const, text: JSON.stringify(response.result) }] };
        },
    };
}

function makeCreateTool(
    entity: string,
    name: string,
    description: string,
    schema: z.ZodObject<any>
): ToolDefinition<any> {
    return {
        name,
        description,
        schema,
        handler: async (args: any) => {
            const params = args.params ?? {};
            const response = await createEntity(entity, params);
            if (response.isError) {
                return { content: [{ type: "text" as const, text: `Error creating ${entity}: ${response.error}` }] };
            }
            return {
                content: [
                    { type: "text" as const, text: `${entity} created:` },
                    { type: "text" as const, text: JSON.stringify(response.result) },
                ],
            };
        },
    };
}

function makeUpdateTool(
    entity: string,
    name: string,
    description: string
): ToolDefinition<any> {
    const schema = z.object({
        payload: z.any().describe(`The ${entity} object with Id, SyncToken, and fields to update.`),
    });
    return {
        name,
        description,
        schema,
        handler: async (args: any) => {
            const params = args.params ?? {};
            const response = await updateEntity(entity, params.payload);
            if (response.isError) {
                return { content: [{ type: "text" as const, text: `Error updating ${entity}: ${response.error}` }] };
            }
            return {
                content: [
                    { type: "text" as const, text: `${entity} updated:` },
                    { type: "text" as const, text: JSON.stringify(response.result) },
                ],
            };
        },
    };
}

function makeDeleteTool(
    entity: string,
    name: string,
    description: string
): ToolDefinition<any> {
    const schema = z.object({
        payload: z.any().describe(`Object with Id and SyncToken of the ${entity} to delete.`),
    });
    return {
        name,
        description,
        schema,
        handler: async (args: any) => {
            const params = args.params ?? {};
            const response = await deleteEntity(entity, params.payload);
            if (response.isError) {
                return { content: [{ type: "text" as const, text: `Error deleting ${entity}: ${response.error}` }] };
            }
            return { content: [{ type: "text" as const, text: `${entity} deleted successfully.` }] };
        },
    };
}

function makeVoidTool(
    entity: string,
    name: string,
    description: string
): ToolDefinition<any> {
    const schema = z.object({
        payload: z.any().describe(`Object with Id and SyncToken of the ${entity} to void.`),
    });
    return {
        name,
        description,
        schema,
        handler: async (args: any) => {
            const params = args.params ?? {};
            const response = await voidEntity(entity, params.payload);
            if (response.isError) {
                return { content: [{ type: "text" as const, text: `Error voiding ${entity}: ${response.error}` }] };
            }
            return { content: [{ type: "text" as const, text: `${entity} voided successfully.` }] };
        },
    };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PAYMENTS — Customer payments received against invoices
// ═══════════════════════════════════════════════════════════════════════════

export const SearchPaymentsTool = makeSearchTool("Payment", "search_payments",
    "Search customer payments in QuickBooks Online. Returns payments received against invoices.");

export const GetPaymentTool = makeGetTool("Payment", "get_payment",
    "Get a single customer payment by ID from QuickBooks Online.");

export const CreatePaymentTool = makeCreateTool("Payment", "create_payment",
    "Record a customer payment in QuickBooks Online. Link to invoices via Line items with LinkedTxn.",
    z.object({
        TotalAmt: z.number().describe("Total payment amount."),
        CustomerRef: z.object({ value: z.string() }).describe("Customer reference { value: 'customerId' }."),
        Line: z.array(z.any()).optional().describe("Line items linking payment to invoices via LinkedTxn."),
        PaymentMethodRef: z.object({ value: z.string() }).optional().describe("Payment method reference."),
        DepositToAccountRef: z.object({ value: z.string() }).optional().describe("Account to deposit payment into."),
    })
);

export const UpdatePaymentTool = makeUpdateTool("Payment", "update_payment",
    "Update an existing customer payment in QuickBooks Online. Payload must include Id and SyncToken.");

export const DeletePaymentTool = makeDeleteTool("Payment", "delete_payment",
    "Delete a customer payment from QuickBooks Online.");

export const VoidPaymentTool = makeVoidTool("Payment", "void_payment",
    "Void a customer payment in QuickBooks Online. Keeps the record but zeroes the amount.");

// ═══════════════════════════════════════════════════════════════════════════
//  CREDIT MEMOS — Customer refunds/credits
// ═══════════════════════════════════════════════════════════════════════════

export const SearchCreditMemosTool = makeSearchTool("CreditMemo", "search_credit_memos",
    "Search credit memos in QuickBooks Online. Credit memos represent refunds or credits issued to customers.");

export const GetCreditMemoTool = makeGetTool("CreditMemo", "get_credit_memo",
    "Get a single credit memo by ID from QuickBooks Online.");

export const CreateCreditMemoTool = makeCreateTool("CreditMemo", "create_credit_memo",
    "Create a credit memo in QuickBooks Online. Issues a credit/refund to a customer.",
    z.object({
        CustomerRef: z.object({ value: z.string() }).describe("Customer reference { value: 'customerId' }."),
        Line: z.array(z.any()).describe("Line items for the credit memo."),
    })
);

export const UpdateCreditMemoTool = makeUpdateTool("CreditMemo", "update_credit_memo",
    "Update a credit memo in QuickBooks Online. Payload must include Id and SyncToken.");

export const DeleteCreditMemoTool = makeDeleteTool("CreditMemo", "delete_credit_memo",
    "Delete a credit memo from QuickBooks Online.");

// ═══════════════════════════════════════════════════════════════════════════
//  SALES RECEIPTS — Cash/immediate sales (no invoice)
// ═══════════════════════════════════════════════════════════════════════════

export const SearchSalesReceiptsTool = makeSearchTool("SalesReceipt", "search_sales_receipts",
    "Search sales receipts in QuickBooks Online. Sales receipts represent immediate/cash sales.");

export const GetSalesReceiptTool = makeGetTool("SalesReceipt", "get_sales_receipt",
    "Get a single sales receipt by ID from QuickBooks Online.");

export const CreateSalesReceiptTool = makeCreateTool("SalesReceipt", "create_sales_receipt",
    "Create a sales receipt in QuickBooks Online for a cash/immediate sale.",
    z.object({
        CustomerRef: z.object({ value: z.string() }).optional().describe("Customer reference."),
        Line: z.array(z.any()).describe("Line items for the sale."),
        PaymentMethodRef: z.object({ value: z.string() }).optional().describe("Payment method reference."),
        DepositToAccountRef: z.object({ value: z.string() }).optional().describe("Account to deposit into."),
    })
);

export const UpdateSalesReceiptTool = makeUpdateTool("SalesReceipt", "update_sales_receipt",
    "Update a sales receipt in QuickBooks Online. Payload must include Id and SyncToken.");

export const DeleteSalesReceiptTool = makeDeleteTool("SalesReceipt", "delete_sales_receipt",
    "Delete a sales receipt from QuickBooks Online.");

// ═══════════════════════════════════════════════════════════════════════════
//  DEPOSITS — Bank deposits grouping multiple payments
// ═══════════════════════════════════════════════════════════════════════════

export const SearchDepositsTool = makeSearchTool("Deposit", "search_deposits",
    "Search bank deposits in QuickBooks Online. Deposits group multiple payments into a single bank transaction.");

export const GetDepositTool = makeGetTool("Deposit", "get_deposit",
    "Get a single bank deposit by ID from QuickBooks Online.");

export const CreateDepositTool = makeCreateTool("Deposit", "create_deposit",
    "Create a bank deposit in QuickBooks Online grouping payments into a bank account.",
    z.object({
        DepositToAccountRef: z.object({ value: z.string() }).describe("Bank account to deposit into."),
        Line: z.array(z.any()).describe("Line items — each linked to a payment or direct deposit entry."),
    })
);

export const UpdateDepositTool = makeUpdateTool("Deposit", "update_deposit",
    "Update a bank deposit in QuickBooks Online. Payload must include Id and SyncToken.");

export const DeleteDepositTool = makeDeleteTool("Deposit", "delete_deposit",
    "Delete a bank deposit from QuickBooks Online.");

// ═══════════════════════════════════════════════════════════════════════════
//  PURCHASE ORDERS — Procurement workflow
// ═══════════════════════════════════════════════════════════════════════════

export const SearchPurchaseOrdersTool = makeSearchTool("PurchaseOrder", "search_purchase_orders",
    "Search purchase orders in QuickBooks Online. POs are sent to vendors for goods/services procurement.");

export const GetPurchaseOrderTool = makeGetTool("PurchaseOrder", "get_purchase_order",
    "Get a single purchase order by ID from QuickBooks Online.");

export const CreatePurchaseOrderTool = makeCreateTool("PurchaseOrder", "create_purchase_order",
    "Create a purchase order in QuickBooks Online for vendor procurement.",
    z.object({
        VendorRef: z.object({ value: z.string() }).describe("Vendor reference { value: 'vendorId' }."),
        Line: z.array(z.any()).describe("Line items for the purchase order."),
        APAccountRef: z.object({ value: z.string() }).optional().describe("Accounts payable account."),
    })
);

export const UpdatePurchaseOrderTool = makeUpdateTool("PurchaseOrder", "update_purchase_order",
    "Update a purchase order in QuickBooks Online. Payload must include Id and SyncToken.");

export const DeletePurchaseOrderTool = makeDeleteTool("PurchaseOrder", "delete_purchase_order",
    "Delete a purchase order from QuickBooks Online.");

// ═══════════════════════════════════════════════════════════════════════════
//  VENDOR CREDITS — Credits received from vendors
// ═══════════════════════════════════════════════════════════════════════════

export const SearchVendorCreditsTool = makeSearchTool("VendorCredit", "search_vendor_credits",
    "Search vendor credits in QuickBooks Online. Vendor credits reduce amounts owed to vendors.");

export const GetVendorCreditTool = makeGetTool("VendorCredit", "get_vendor_credit",
    "Get a single vendor credit by ID from QuickBooks Online.");

export const CreateVendorCreditTool = makeCreateTool("VendorCredit", "create_vendor_credit",
    "Create a vendor credit in QuickBooks Online. Reduces amounts owed to a vendor.",
    z.object({
        VendorRef: z.object({ value: z.string() }).describe("Vendor reference { value: 'vendorId' }."),
        Line: z.array(z.any()).describe("Line items for the vendor credit."),
    })
);

export const UpdateVendorCreditTool = makeUpdateTool("VendorCredit", "update_vendor_credit",
    "Update a vendor credit in QuickBooks Online. Payload must include Id and SyncToken.");

export const DeleteVendorCreditTool = makeDeleteTool("VendorCredit", "delete_vendor_credit",
    "Delete a vendor credit from QuickBooks Online.");

// ═══════════════════════════════════════════════════════════════════════════
//  TRANSFERS — Move money between accounts
// ═══════════════════════════════════════════════════════════════════════════

export const SearchTransfersTool = makeSearchTool("Transfer", "search_transfers",
    "Search account transfers in QuickBooks Online. Transfers move money between bank/asset accounts.");

export const GetTransferTool = makeGetTool("Transfer", "get_transfer",
    "Get a single transfer by ID from QuickBooks Online.");

export const CreateTransferTool = makeCreateTool("Transfer", "create_transfer",
    "Create a transfer between accounts in QuickBooks Online.",
    z.object({
        FromAccountRef: z.object({ value: z.string() }).describe("Source account { value: 'accountId' }."),
        ToAccountRef: z.object({ value: z.string() }).describe("Destination account { value: 'accountId' }."),
        Amount: z.number().describe("Transfer amount."),
    })
);

export const UpdateTransferTool = makeUpdateTool("Transfer", "update_transfer",
    "Update a transfer in QuickBooks Online. Payload must include Id and SyncToken.");

export const DeleteTransferTool = makeDeleteTool("Transfer", "delete_transfer",
    "Delete a transfer from QuickBooks Online.");

// ═══════════════════════════════════════════════════════════════════════════
//  TAX CODES — Tax configuration (read-only recommended)
// ═══════════════════════════════════════════════════════════════════════════

export const SearchTaxCodesTool = makeSearchTool("TaxCode", "search_tax_codes",
    "Search tax codes in QuickBooks Online. Tax codes define tax applicability for transactions.");

export const GetTaxCodeTool = makeGetTool("TaxCode", "get_tax_code",
    "Get a single tax code by ID from QuickBooks Online.");

// ═══════════════════════════════════════════════════════════════════════════
//  TAX RATES — Individual tax rate definitions (read-only recommended)
// ═══════════════════════════════════════════════════════════════════════════

export const SearchTaxRatesTool = makeSearchTool("TaxRate", "search_tax_rates",
    "Search tax rates in QuickBooks Online. Tax rates define the percentage for individual tax components.");

export const GetTaxRateTool = makeGetTool("TaxRate", "get_tax_rate",
    "Get a single tax rate by ID from QuickBooks Online.");

// ═══════════════════════════════════════════════════════════════════════════
//  CLASSES — P&L segmentation / tracking categories
// ═══════════════════════════════════════════════════════════════════════════

export const SearchClassesTool = makeSearchTool("Class", "search_classes",
    "Search classes in QuickBooks Online. Classes segment P&L for tracking by department, product line, etc.");

export const GetClassTool = makeGetTool("Class", "get_class",
    "Get a single class by ID from QuickBooks Online.");

export const CreateClassTool = makeCreateTool("Class", "create_class",
    "Create a class in QuickBooks Online for P&L segmentation.",
    z.object({
        Name: z.string().describe("Class name (e.g. 'Marketing', 'Product Line A')."),
        ParentRef: z.object({ value: z.string() }).optional().describe("Parent class for sub-classes."),
    })
);

export const UpdateClassTool = makeUpdateTool("Class", "update_class",
    "Update a class in QuickBooks Online. Payload must include Id and SyncToken.");

// ═══════════════════════════════════════════════════════════════════════════
//  DEPARTMENTS — Location-based reporting
// ═══════════════════════════════════════════════════════════════════════════

export const SearchDepartmentsTool = makeSearchTool("Department", "search_departments",
    "Search departments in QuickBooks Online. Departments represent locations/divisions for reporting.");

export const GetDepartmentTool = makeGetTool("Department", "get_department",
    "Get a single department by ID from QuickBooks Online.");

export const CreateDepartmentTool = makeCreateTool("Department", "create_department",
    "Create a department in QuickBooks Online for location-based reporting.",
    z.object({
        Name: z.string().describe("Department/location name."),
        ParentRef: z.object({ value: z.string() }).optional().describe("Parent department for sub-departments."),
    })
);

export const UpdateDepartmentTool = makeUpdateTool("Department", "update_department",
    "Update a department in QuickBooks Online. Payload must include Id and SyncToken.");
