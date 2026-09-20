/**
 * POST /mcp (rewritten to /api/mcp). Stateless MCP server over Streamable HTTP for
 * Copilot Studio and other MCP clients. A fresh McpServer + transport is created per
 * request; no session state is kept between invocations.
 */
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createDefaultDeps } from "../src/analyze.js";
import { requireApiKey } from "../src/http/auth.js";
import { HttpError, applyCors, readJsonBody, sendJson } from "../src/http/json.js";
import { SERVICE_NAME, SERVICE_VERSION } from "../src/http/version.js";
import { registerTools } from "../src/mcp/tools.js";

function jsonRpcError(res: VercelResponse, status: number, code: number, message: string): void {
  sendJson(res, status, { jsonrpc: "2.0", error: { code, message }, id: null });
}

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  applyCors(res);

  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    res.end();
    return;
  }

  if (req.method !== "POST") {
    // Stateless mode: no standalone SSE stream (GET) and no sessions to delete (DELETE).
    res.setHeader("allow", "POST, OPTIONS");
    jsonRpcError(res, 405, -32000, "Method not allowed. This MCP server is stateless; send JSON-RPC via POST.");
    return;
  }

  const auth = requireApiKey(req.headers);
  if (!auth.ok) {
    jsonRpcError(res, auth.status, auth.status === 401 ? -32001 : -32603, auth.message);
    return;
  }

  let body: unknown;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    const status = err instanceof HttpError ? err.status : 400;
    jsonRpcError(res, status, -32700, err instanceof Error ? err.message : "parse error");
    return;
  }

  const server = new McpServer({ name: SERVICE_NAME, version: SERVICE_VERSION });
  registerTools(server, createDefaultDeps());

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });

  res.on("close", () => {
    void transport.close();
    void server.close();
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, body);
  } catch (err) {
    console.error(JSON.stringify({ evt: "mcp_error", message: err instanceof Error ? err.message : String(err) }));
    if (!res.headersSent) jsonRpcError(res, 500, -32603, "internal error");
  }
}
