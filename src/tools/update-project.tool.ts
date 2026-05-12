import { updateQuickbooksProject } from "../handlers/update-quickbooks-project.handler.js";
import { ToolDefinition } from "../types/tool-definition.js";
import { z } from "zod";

const toolName = "update_project";
const toolDescription = "Update an existing project in QuickBooks Online. Can update name, description, or status. NOTE: Requires Silver+ Intuit partner tier (Premium GraphQL API).";

const toolSchema = z.object({
  id: z.string().describe("The QBO project ID to update."),
  name: z.string().optional().describe("New project name."),
  description: z.string().optional().describe("New project description."),
  status: z.enum(["IN_PROGRESS", "COMPLETED"]).optional().describe("New project status."),
});

type ToolParams = z.infer<typeof toolSchema>;

const toolHandler = async (args: { [key: string]: ToolParams }) => {
  const params = args.params as ToolParams;
  const response = await updateQuickbooksProject(params);

  if (response.isError) {
    return {
      content: [{ type: "text" as const, text: `Error updating project: ${response.error}\n\nNote: Updating projects requires the Premium GraphQL API (project-management.project scope) and Silver+ Intuit App Partner tier. Currently read-only project access is available via search_projects and get_project.` }],
    };
  }

  return {
    content: [
      { type: "text" as const, text: `Project updated:` },
      { type: "text" as const, text: JSON.stringify(response.result) },
    ],
  };
};

export const UpdateProjectTool: ToolDefinition<typeof toolSchema> = {
  name: toolName,
  description: toolDescription,
  schema: toolSchema,
  handler: toolHandler,
};
