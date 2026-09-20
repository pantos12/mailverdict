/**
 * Small HTTP helpers for Vercel Node functions: JSON body reading with a size cap,
 * JSON responses, CORS, and secret-safe error sanitization.
 */
import type { IncomingMessage, ServerResponse } from "node:http";

export const MAX_BODY_BYTES = 3 * 1024 * 1024; // 3 MB

export class HttpError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = "HttpError";
  }
}

export type BodyRequest = IncomingMessage & { body?: unknown };

/**
 * Read and parse a JSON body. Vercel usually pre-parses `req.body`; when it does
 * not (raw stream), we read up to MAX_BODY_BYTES and parse ourselves.
 */
export async function readJsonBody(req: BodyRequest): Promise<unknown> {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === "string") return parseJson(req.body);
    if (Buffer.isBuffer(req.body)) return parseJson(req.body.toString("utf8"));
    return req.body;
  }
  const text = await readTextBody(req);
  if (text.length === 0) return undefined;
  return parseJson(text);
}

/** True when the request declares a non-JSON email body (`message/rfc822` or `text/plain`). */
export function isRawEmailContentType(req: IncomingMessage): boolean {
  const ct = String(req.headers["content-type"] ?? "").toLowerCase();
  return ct.startsWith("message/rfc822") || ct.startsWith("text/plain");
}

/** Read the request body as UTF-8 text (uses a pre-parsed `req.body` when present). */
export async function readTextBody(req: BodyRequest): Promise<string> {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === "string") return req.body;
    if (Buffer.isBuffer(req.body)) return req.body.toString("utf8");
    return JSON.stringify(req.body);
  }

  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : (chunk as Buffer);
    total += buf.length;
    if (total > MAX_BODY_BYTES) {
      throw new HttpError(413, `request body exceeds ${MAX_BODY_BYTES} bytes`);
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function parseJson(text: string): unknown {
  if (text.trim().length === 0) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, "request body is not valid JSON");
  }
}

export function sendJson(res: ServerResponse, status: number, obj: unknown): void {
  const payload = JSON.stringify(obj);
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("content-length", Buffer.byteLength(payload).toString());
  res.end(payload);
}

export const CORS_ALLOW_HEADERS = [
  "content-type",
  "x-api-key",
  "authorization",
  "mcp-session-id",
  "mcp-protocol-version",
].join(", ");

export function corsHeaders(): Record<string, string> {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": CORS_ALLOW_HEADERS,
    "access-control-expose-headers": "mcp-session-id, mcp-protocol-version",
    "access-control-max-age": "86400",
  };
}

export function applyCors(res: ServerResponse): void {
  for (const [name, value] of Object.entries(corsHeaders())) res.setHeader(name, value);
}

/** Env var names that look like secrets; their values are scrubbed from error text. */
const SECRET_ENV_PATTERN = /KEY|SECRET|TOKEN|PASSWORD/i;

/**
 * Produce an error message safe to return to clients: strips any env secret values,
 * bearer tokens and common key prefixes, and truncates.
 */
export function sanitizeErrorMessage(err: unknown, env: NodeJS.ProcessEnv = process.env): string {
  let text = err instanceof Error ? err.message : String(err);
  for (const [name, value] of Object.entries(env)) {
    if (!SECRET_ENV_PATTERN.test(name) || !value || value.length < 8) continue;
    text = text.split(value).join("[redacted]");
  }
  text = text.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [redacted]");
  text = text.replace(/\bsk[-_][A-Za-z0-9._-]{8,}/g, "[redacted]");
  return text.length > 300 ? `${text.slice(0, 297)}...` : text;
}
