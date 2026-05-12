import { listQuickbooksProjects } from "../handlers/list-quickbooks-projects.handler.js";
import { ToolDefinition } from "../types/tool-definition.js";
import { z } from "zod";

const toolName = "search_projects";
const toolDescription = "Search / list projects in QuickBooks Online. Projects require QBO Plus or Advanced. Filter by status, customer, or name. Read-only via REST API.";

const toolSchema = z.object({
  status: z.string().optional().describe("Filter by project status (e.g. 'InProgress', 'Completed')."),
  customerRef: z.string().optional().describe("Filter by customer ID (QBO internal ID)."),
  nameContains: z.string().optional().describe("Search projects by name (partial match)."),
  maxResults: z.number().optional().describe("Number of results to return (default: 100, max: 1000)."),
  startPosition: z.number().optional().describe("Pagination offset (1-indexed, default: 1)."),
});

type ToolParams = z.infer<typeof toolSchema>;

const toolHandler = async (args: any) => {
  const params = (args.params ?? {}) as ToolParams;
  const response = await listQuickbooksProjects(params);

  if (response.isError) {
    return {
      content: [{ type: "text" as const, text: `Error searching projects: ${response.error}` }],
    };
  }

  const data = response.result;
  const projects = data?.QueryResponse?.Project ?? [];

  return {
    content: [
      { type: "text" as const, text: `Found ${projects.length} project(s):` },
      ...projects.map((p: any) => ({ type: "text" as const, text: JSON.stringify(p) })),
    ],
  };
};

export const SearchProjectsTool: ToolDefinition<typeof toolSchema> = {
  name: toolName,
  description: toolDescription,
  schema: toolSchema,
  handler: toolHandler,
};
