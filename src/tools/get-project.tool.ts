import { getQuickbooksProject } from "../handlers/get-quickbooks-project.handler.js";
import { ToolDefinition } from "../types/tool-definition.js";
import { z } from "zod";

const toolName = "get_project";
const toolDescription = "Get a single project by ID from QuickBooks Online, including its status, description, and linked customer.";

const toolSchema = z.object({
  id: z.string().describe("The QBO project ID."),
});

type ToolParams = z.infer<typeof toolSchema>;

const toolHandler = async (args: { [key: string]: ToolParams }) => {
  const params = args.params as ToolParams;
  const response = await getQuickbooksProject(params.id);

  if (response.isError) {
    return {
      content: [{ type: "text" as const, text: `Error getting project: ${response.error}` }],
    };
  }

  return {
    content: [
      { type: "text" as const, text: `Project:` },
      { type: "text" as const, text: JSON.stringify(response.result) },
    ],
  };
};

export const GetProjectTool: ToolDefinition<typeof toolSchema> = {
  name: toolName,
  description: toolDescription,
  schema: toolSchema,
  handler: toolHandler,
};
