import { getQuickbooksReport } from "../handlers/get-quickbooks-report.handler.js";
import { ToolDefinition } from "../types/tool-definition.js";
import { z } from "zod";

const toolName = "report_aged_receivables";
const toolDescription = "Generate an Aged Receivables (A/R Aging) report from QuickBooks Online. Shows outstanding customer invoices grouped by aging period (current, 1-30, 31-60, 61-90, 91+ days).";

const toolSchema = z.object({
  start_date: z.string().optional().describe("Start date (YYYY-MM-DD)."),
  end_date: z.string().optional().describe("Report as-of date (YYYY-MM-DD). Defaults to today."),
  customer: z.string().optional().describe("Filter to a specific customer by ID."),
  aging_period: z.number().optional().describe("Number of days per aging bucket (default: 30)."),
  date_macro: z.string().optional().describe("Date shorthand. Overrides start/end dates."),
});

type ToolParams = z.infer<typeof toolSchema>;

const toolHandler = async (args: any) => {
  const params = (args.params ?? {}) as ToolParams;
  const response = await getQuickbooksReport("AgedReceivables", params);

  if (response.isError) {
    return {
      content: [{ type: "text" as const, text: `Error generating A/R Aging report: ${response.error}` }],
    };
  }

  return {
    content: [
      { type: "text" as const, text: `Aged Receivables Report:` },
      { type: "text" as const, text: JSON.stringify(response.result) },
    ],
  };
};

export const ReportAgedReceivablesTool: ToolDefinition<typeof toolSchema> = {
  name: toolName,
  description: toolDescription,
  schema: toolSchema,
  handler: toolHandler,
};
