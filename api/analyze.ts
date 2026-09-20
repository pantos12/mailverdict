/**
 * POST /v1/analyze (rewritten to /api/analyze). Plain REST for Power Automate and curl.
 *
 * Body: AnalyzeRequest ({ raw } | { fields: {...} }, optional policy) or the flat
 * Power Automate shape ({ subject, from, body, html, headers, ... }) which is wrapped.
 */
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { analyzeEmail, createDefaultDeps, validateAnalyzeRequest } from "../src/analyze.js";
import { requireApiKey } from "../src/http/auth.js";
import { HttpError, applyCors, readJsonBody, sanitizeErrorMessage, sendJson } from "../src/http/json.js";

const FLAT_FIELD_KEYS = ["subject", "from", "replyTo", "to", "body", "html", "headers"] as const;

/**
 * Accept the flat Power Automate shape: if top-level email fields are present and
 * neither `raw` nor `fields` is, wrap them into `{ fields: {...} }`.
 */
export function normalizeAnalyzeBody(body: unknown): unknown {
  if (body === null || typeof body !== "object" || Array.isArray(body)) return body;
  const obj = body as Record<string, unknown>;
  if ("raw" in obj || "fields" in obj) return body;

  const fields: Record<string, unknown> = {};
  for (const key of FLAT_FIELD_KEYS) {
    if (obj[key] !== undefined) fields[key] = obj[key];
  }
  if (Object.keys(fields).length === 0) return body;

  const wrapped: Record<string, unknown> = { fields };
  if (obj.policy !== undefined) wrapped.policy = obj.policy;
  return wrapped;
}

function validationMessage(err: unknown): string {
  if (err && typeof err === "object" && "issues" in err && Array.isArray((err as { issues: unknown }).issues)) {
    const issues = (err as { issues: Array<{ path?: unknown[]; message?: string }> }).issues;
    return issues
      .slice(0, 5)
      .map((i) => `${(i.path ?? []).join(".") || "body"}: ${i.message ?? "invalid"}`)
      .join("; ");
  }
  return err instanceof Error ? err.message : "invalid request";
}

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  applyCors(res);

  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    res.end();
    return;
  }
  if (req.method !== "POST") {
    res.setHeader("allow", "POST, OPTIONS");
    sendJson(res, 405, { error: "method not allowed; use POST" });
    return;
  }

  const auth = requireApiKey(req.headers);
  if (!auth.ok) {
    sendJson(res, auth.status, { error: auth.message });
    return;
  }

  let body: unknown;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    const status = err instanceof HttpError ? err.status : 400;
    sendJson(res, status, { error: err instanceof Error ? err.message : "bad request" });
    return;
  }

  let request;
  try {
    request = validateAnalyzeRequest(normalizeAnalyzeBody(body));
  } catch (err) {
    sendJson(res, 400, { error: `invalid request: ${validationMessage(err)}` });
    return;
  }

  const started = Date.now();
  try {
    const verdict = await analyzeEmail(request, createDefaultDeps());
    console.log(
      JSON.stringify({
        evt: "analyze",
        label: verdict.label,
        probability: verdict.probability,
        attackType: verdict.attackType,
        explained: verdict.explained,
        latencyMs: verdict.latencyMs,
      }),
    );
    sendJson(res, 200, verdict);
  } catch (err) {
    const message = sanitizeErrorMessage(err);
    console.error(JSON.stringify({ evt: "analyze_error", latencyMs: Date.now() - started, message }));
    sendJson(res, 502, { error: `upstream analysis failed: ${message}` });
  }
}
