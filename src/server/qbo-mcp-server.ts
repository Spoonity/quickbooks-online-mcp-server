import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export class QuickbooksMCPServer {
  private static instance: McpServer | null = null;

  private constructor() {}

  /** Singleton — used in stdio mode. */
  public static GetServer(): McpServer {
    if (QuickbooksMCPServer.instance === null) {
      QuickbooksMCPServer.instance = QuickbooksMCPServer.GetServerInstance();
    }
    return QuickbooksMCPServer.instance;
  }

  /** Factory — creates a new instance. Used in HTTP mode for per-session isolation. */
  public static GetServerInstance(): McpServer {
    return new McpServer({
      name: "QuickBooks Online MCP Server",
      version: "1.0.0",
    });
  }
}