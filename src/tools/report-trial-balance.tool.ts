import { getQuickbooksReport } from "../handlers/get-quickbooks-report.handler.js";
import { ToolDefinition } from "../types/tool-definition.js";
import { z } from "zod";

const toolName = "report_trial_balance";
const toolDescription = "Generate a Trial Balance report from QuickBooks Online. Shows debit and credit balances for all accounts at a point in time.";

const toolSchema = z.object({
  start_date: z.string().optional().describe("Start date (YYYY-MM-DD)."),
  end_date: z.string().optional().describe("End date (YYYY-MM-DD). Defaults to today."),
  accounting_method: z.enum(["Cash", "Accrual"]).optional().describe("Accounting method. Defaults to company preference."),
  date_macro: z.string().optional().describe("Date shorthand (e.g. 'This Month', 'Last Fiscal Year'). Overrides start/end dates."),
});

type ToolParams = z.infer<typeof toolSchema>;

const toolHandler = async (args: any) => {
  const params = (args.params ?? {}) as ToolParams;
  const response = await getQuickbooksReport("TrialBalance", params);

  if (response.isError) {
    return {
      content: [{ type: "text" as const, text: `Error generating Trial Balance: ${response.error}` }],
    };
  }

  return {
    content: [
      { type: "text" as const, text: `Trial Balance Report:` },
      { type: "text" as const, text: JSON.stringify(response.result) },
    ],
  };
};

export const ReportTrialBalanceTool: ToolDefinition<typeof toolSchema> = {
  name: toolName,
  description: toolDescription,
  schema: toolSchema,
  handler: toolHandler,
};
