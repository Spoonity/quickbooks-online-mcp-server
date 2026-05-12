import { getQuickbooksReport } from "../handlers/get-quickbooks-report.handler.js";
import { ToolDefinition } from "../types/tool-definition.js";
import { z } from "zod";

const toolName = "report_balance_sheet";
const toolDescription = "Generate a Balance Sheet report from QuickBooks Online. Shows assets, liabilities, and equity as of a specific date.";

const toolSchema = z.object({
  start_date: z.string().optional().describe("Start date (YYYY-MM-DD)."),
  end_date: z.string().optional().describe("End date / as-of date (YYYY-MM-DD). Defaults to today."),
  accounting_method: z.enum(["Cash", "Accrual"]).optional().describe("Accounting method. Defaults to company preference."),
  date_macro: z.string().optional().describe("Date shorthand (e.g. 'This Month', 'Last Fiscal Year'). Overrides start/end dates."),
  summarize_column_by: z.enum(["Total", "Month", "Quarter", "Year"]).optional().describe("How to group columns. Default: Total."),
});

type ToolParams = z.infer<typeof toolSchema>;

const toolHandler = async (args: any) => {
  const params = (args.params ?? {}) as ToolParams;
  const response = await getQuickbooksReport("BalanceSheet", params);

  if (response.isError) {
    return {
      content: [{ type: "text" as const, text: `Error generating Balance Sheet: ${response.error}` }],
    };
  }

  return {
    content: [
      { type: "text" as const, text: `Balance Sheet Report:` },
      { type: "text" as const, text: JSON.stringify(response.result) },
    ],
  };
};

export const ReportBalanceSheetTool: ToolDefinition<typeof toolSchema> = {
  name: toolName,
  description: toolDescription,
  schema: toolSchema,
  handler: toolHandler,
};
