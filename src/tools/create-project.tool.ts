import { createQuickbooksProject } from "../handlers/create-quickbooks-project.handler.js";
import { ToolDefinition } from "../types/tool-definition.js";
import { z } from "zod";

const toolName = "create_project";
const toolDescription = "Create a new project in QuickBooks Online. A project must be linked to an existing customer. NOTE: Requires Silver+ Intuit partner tier (Premium GraphQL API).";

const toolSchema = z.object({
  name: z.string().describe("Project name."),
  customerId: z.string().describe("The QBO customer ID to link this project to."),
  description: z.string().optional().describe("Optional project description."),
});

type ToolParams = z.infer<typeof toolSchema>;

const toolHandler = async (args: { [key: string]: ToolParams }) => {
  const params = args.params as ToolParams;
  const response = await createQuickbooksProject(params);

  if (response.isError) {
    return {
      content: [{ type: "text" as const, text: `Error creating project: ${response.error}\n\nNote: Creating projects requires the Premium GraphQL API (project-management.project scope) and Silver+ Intuit App Partner tier. Currently read-only project access is available via search_projects and get_project.` }],
    };
  }

  return {
    content: [
      { type: "text" as const, text: `Project created:` },
      { type: "text" as const, text: JSON.stringify(response.result) },
    ],
  };
};

export const CreateProjectTool: ToolDefinition<typeof toolSchema> = {
  name: toolName,
  description: toolDescription,
  schema: toolSchema,
  handler: toolHandler,
};
