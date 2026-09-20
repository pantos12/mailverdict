/**
 * Standalone HTTP server for container hosting (Azure Container Apps, Docker, etc.).
 * Reuses the exact Vercel function handlers so both deployment targets behave the same.
 *
 * Routes: GET /health, POST /v1/analyze, POST /mcp, GET / (landing page).
 * The /api/* aliases are kept so the Vercel rewrites in vercel.json also work here.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import type { VercelRequest, VercelResponse } from "@vercel/node";
import analyze from "../api/analyze.js";
import health from "../api/health.js";
import mcp from "../api/mcp.js";
import { sendJson } from "./http/json.js";

type Handler = (req: VercelRequest, res: VercelResponse) => void | Promise<void>;

const ROUTES: Record<string, Handler> = {
  "/health": health,
  "/api/health": health,
  "/v1/analyze": analyze,
  "/api/analyze": analyze,
  "/mcp": mcp,
  "/api/mcp": mcp,
};

const PUBLIC_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", "public");

export async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const path = new URL(req.url ?? "/", "http://localhost").pathname.replace(/\/+$/, "") || "/";
  const handler = ROUTES[path];
  if (handler) {
    await handler(req as VercelRequest, res as VercelResponse);
    return;
  }
  if (path === "/" && (req.method === "GET" || req.method === "HEAD")) {
    try {
      const html = await readFile(resolve(PUBLIC_DIR, "index.html"));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(req.method === "HEAD" ? undefined : html);
    } catch {
      sendJson(res, 404, { error: "not found" });
    }
    return;
  }
  sendJson(res, 404, { error: "not found" });
}

export function startServer(port = Number(process.env.PORT ?? 8080)): ReturnType<typeof createServer> {
  const server = createServer((req, res) => {
    route(req, res).catch((err: unknown) => {
      console.error(JSON.stringify({ evt: "unhandled", message: err instanceof Error ? err.message : String(err) }));
      if (!res.headersSent) sendJson(res, 500, { error: "internal error" });
      else res.end();
    });
  });
  server.listen(port, () => console.log(JSON.stringify({ evt: "listening", port })));
  return server;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) startServer();
