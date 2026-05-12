import { getQuickbooksReport } from "../handlers/get-quickbooks-report.handler.js";
import { ToolDefinition } from "../types/tool-definition.js";
import { z } from "zod";

const toolName = "report_aged_payables";
const toolDescription = "Generate an Aged Payables (A/P Aging) report from QuickBooks Online. Shows outstanding vendor bills grouped by aging period (current, 1-30, 31-60, 61-90, 91+ days).";

const toolSchema = z.object({
  start_date: z.string().optional().describe("Start date (YYYY-MM-DD)."),
  end_date: z.string().optional().describe("Report as-of date (YYYY-MM-DD). Defaults to today."),
  vendor: z.string().optional().describe("Filter to a specific vendor by ID."),
  aging_period: z.number().optional().describe("Number of days per aging bucket (default: 30)."),
  date_macro: z.string().optional().describe("Date shorthand. Overrides start/end dates."),
});

type ToolParams = z.infer<typeof toolSchema>;

const toolHandler = async (args: any) => {
  const params = (args.params ?? {}) as ToolParams;
  const response = await getQuickbooksReport("AgedPayables", params);

  if (response.isError) {
    return {
      content: [{ type: "text" as const, text: `Error generating A/P Aging report: ${response.error}` }],
    };
  }

  return {
    content: [
      { type: "text" as const, text: `Aged Payables Report:` },
      { type: "text" as const, text: JSON.stringify(response.result) },
    ],
  };
};

export const ReportAgedPayablesTool: ToolDefinition<typeof toolSchema> = {
  name: toolName,
  description: toolDescription,
  schema: toolSchema,
  handler: toolHandler,
};
