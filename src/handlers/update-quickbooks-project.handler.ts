import { quickbooksClient } from "../clients/quickbooks-client.js";
import { ToolResponse } from "../types/tool-response.js";
import { formatError } from "../helpers/format-error.js";

/**
 * Update an existing project via the QBO GraphQL API.
 */

const UPDATE_PROJECT_MUTATION = `
  mutation UpdateProject($input: UpdateProjectInput!) {
    updateProject(input: $input) {
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

export interface UpdateProjectInput {
    id: string;
    name?: string;
    description?: string;
    status?: string;
}

export async function updateQuickbooksProject(
    input: UpdateProjectInput
): Promise<ToolResponse<any>> {
    try {
        const { id, ...fields } = input;
        const variables = {
            input: {
                id,
                ...fields,
            },
        };

        const data = await quickbooksClient.graphqlQuery(UPDATE_PROJECT_MUTATION, variables);

        return {
            result: (data as any)?.updateProject ?? data,
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
