import { quickbooksClient } from "../clients/quickbooks-client.js";
import { ToolResponse } from "../types/tool-response.js";
import { formatError } from "../helpers/format-error.js";

/**
 * Create a new project via the QBO GraphQL API.
 */

const CREATE_PROJECT_MUTATION = `
  mutation CreateProject($input: CreateProjectInput!) {
    createProject(input: $input) {
      id
      name
      description
      status
      customer {
        id
        displayName
      }
    }
  }
`;

export interface CreateProjectInput {
    name: string;
    customerId: string;
    description?: string;
}

export async function createQuickbooksProject(
    input: CreateProjectInput
): Promise<ToolResponse<any>> {
    try {
        const variables = {
            input: {
                name: input.name,
                customer: { id: input.customerId },
                ...(input.description ? { description: input.description } : {}),
            },
        };

        const data = await quickbooksClient.graphqlQuery(CREATE_PROJECT_MUTATION, variables);

        return {
            result: (data as any)?.createProject ?? data,
            isError: false,
            error: null,
        };
    } catch (error) {
        return {
            result: null,
            isError: true,
            error: formatError(error),
        };
    }
}
