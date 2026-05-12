import { quickbooksClient } from "../clients/quickbooks-client.js";
import { ToolResponse } from "../types/tool-response.js";
import { formatError } from "../helpers/format-error.js";

/**
 * Shared handler for all QBO financial reports.
 *
 * Maps a report type to the corresponding node-quickbooks method
 * and executes it with the provided options (date range, accounting method, etc.).
 *
 * Supported reports:
 *   ProfitAndLoss, BalanceSheet, CashFlow, TrialBalance,
 *   GeneralLedgerDetail, AgedReceivables, AgedPayables
 */

const REPORT_METHODS: Record<string, string> = {
    ProfitAndLoss: "reportProfitAndLoss",
    BalanceSheet: "reportBalanceSheet",
    CashFlow: "reportCashFlow",
    TrialBalance: "reportTrialBalance",
    GeneralLedgerDetail: "reportGeneralLedgerDetail",
    AgedReceivables: "reportAgedReceivables",
    AgedPayables: "reportAgedPayables",
};

export interface ReportOptions {
    start_date?: string;
    end_date?: string;
    accounting_method?: "Cash" | "Accrual";
    date_macro?: string;
    summarize_column_by?: string;
    customer?: string;
    vendor?: string;
    department?: string;
    account?: string;
    aging_period?: number;
    [key: string]: any;
}

export async function getQuickbooksReport(
    reportType: string,
    options: ReportOptions = {}
): Promise<ToolResponse<any>> {
    const methodName = REPORT_METHODS[reportType];
    if (!methodName) {
        return {
            result: null,
            isError: true,
            error: `Unknown report type: ${reportType}. Supported: ${Object.keys(REPORT_METHODS).join(", ")}`,
        };
    }

    // Warn if date range exceeds 6 months (Intuit recommendation)
    if (options.start_date && options.end_date) {
        const start = new Date(options.start_date);
        const end = new Date(options.end_date);
        const diffMs = end.getTime() - start.getTime();
        const diffDays = diffMs / (1000 * 60 * 60 * 24);
        if (diffDays > 183) {
            console.error(`[qbo] Warning: Report date range is ${Math.round(diffDays)} days. Intuit recommends <= 6 months for performance.`);
        }
    }

    // Strip undefined values from options
    const cleanOptions: Record<string, any> = {};
    for (const [key, value] of Object.entries(options)) {
        if (value !== undefined && value !== null && value !== "") {
            cleanOptions[key] = value;
        }
    }

    try {
        await quickbooksClient.authenticate();
        const qb = quickbooksClient.getQuickbooks();

        return new Promise((resolve) => {
            const method = (qb as any)[methodName];
            if (typeof method !== "function") {
                resolve({
                    result: null,
                    isError: true,
                    error: `node-quickbooks does not support method: ${methodName}`,
                });
                return;
            }

            method.call(qb, cleanOptions, (err: any, report: any) => {
                if (err) {
                    resolve({
                        result: null,
                        isError: true,
                        error: formatError(err),
                    });
                } else {
                    resolve({
                        result: report,
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
