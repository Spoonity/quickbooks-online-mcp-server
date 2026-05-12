import { getQuickbooksReport } from "../handlers/get-quickbooks-report.handler.js";
import { ToolDefinition } from "../types/tool-definition.js";
import { z } from "zod";

const toolName = "report_cash_flow";
const toolDescription = "Generate a Cash Flow Statement from QuickBooks Online. Shows cash flows from operating, investing, and financing activities.";

const toolSchema = z.object({
  start_date: z.string().optional().describe("Start date (YYYY-MM-DD). Defaults to start of current fiscal year."),
  end_date: z.string().optional().describe("End date (YYYY-MM-DD). Defaults to today."),
  accounting_method: z.enum(["Cash", "Accrual"]).optional().describe("Accounting method. Defaults to company preference."),
  date_macro: z.string().optional().describe("Date shorthand (e.g. 'This Month', 'Last Quarter'). Overrides start/end dates."),
  summarize_column_by: z.enum(["Total", "Month", "Quarter", "Year"]).optional().describe("How to group columns. Default: Total."),
});

type ToolParams = z.infer<typeof toolSchema>;

const toolHandler = async (args: any) => {
  const params = (args.params ?? {}) as ToolParams;
  const response = await getQuickbooksReport("CashFlow", params);

  if (response.isError) {
    return {
      content: [{ type: "text" as const, text: `Error generating Cash Flow report: ${response.error}` }],
    };
  }

  return {
    content: [
      { type: "text" as const, text: `Cash Flow Statement:` },
      { type: "text" as const, text: JSON.stringify(response.result) },
    ],
  };
};

export const ReportCashFlowTool: ToolDefinition<typeof toolSchema> = {
  name: toolName,
  description: toolDescription,
  schema: toolSchema,
  handler: toolHandler,
};
