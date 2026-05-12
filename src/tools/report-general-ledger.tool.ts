import { getQuickbooksReport } from "../handlers/get-quickbooks-report.handler.js";
import { ToolDefinition } from "../types/tool-definition.js";
import { z } from "zod";

const toolName = "report_general_ledger";
const toolDescription = "Generate a General Ledger Detail report from QuickBooks Online. Shows detailed transaction-level journal entries for all or specific accounts.";

const toolSchema = z.object({
  start_date: z.string().optional().describe("Start date (YYYY-MM-DD). Defaults to start of current fiscal year."),
  end_date: z.string().optional().describe("End date (YYYY-MM-DD). Defaults to today."),
  accounting_method: z.enum(["Cash", "Accrual"]).optional().describe("Accounting method. Defaults to company preference."),
  date_macro: z.string().optional().describe("Date shorthand (e.g. 'This Month', 'Last Quarter'). Overrides start/end dates."),
  account: z.string().optional().describe("Filter to a specific account by ID or name."),
  source_account_type: z.string().optional().describe("Filter by account type (e.g. 'Bank', 'Expense', 'Income')."),
});

type ToolParams = z.infer<typeof toolSchema>;

const toolHandler = async (args: any) => {
  const params = (args.params ?? {}) as ToolParams;
  const response = await getQuickbooksReport("GeneralLedgerDetail", params);

  if (response.isError) {
    return {
      content: [{ type: "text" as const, text: `Error generating General Ledger: ${response.error}` }],
    };
  }

  return {
    content: [
      { type: "text" as const, text: `General Ledger Detail Report:` },
      { type: "text" as const, text: JSON.stringify(response.result) },
    ],
  };
};

export const ReportGeneralLedgerTool: ToolDefinition<typeof toolSchema> = {
  name: toolName,
  description: toolDescription,
  schema: toolSchema,
  handler: toolHandler,
};
