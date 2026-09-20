/**
 * MCP tool registrations for MailVerdict. Kept separate from the HTTP transport so
 * tools can be exercised with an in-memory transport in tests.
 */
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { AnalyzeDeps } from "../analyze.js";
import { analyzeEmail as defaultAnalyzeEmail } from "../analyze.js";
import { DEFAULT_POLICY, type AnalyzeRequest, type Verdict, type VerdictPolicy } from "../types.js";
import { formatVerdictMarkdown, formatVerdictSummary } from "./format.js";

export type AnalyzeFn = (req: AnalyzeRequest, deps: AnalyzeDeps) => Promise<Verdict>;

export interface RegisterToolsOptions {
  /** Override the analysis function (tests). Defaults to analyzeEmail from src/analyze. */
  analyze?: AnalyzeFn;
  env?: NodeJS.ProcessEnv;
}

export const analyzeEmailInputShape = {
  raw: z.string().optional().describe("Full RFC 822 email source (.eml). Preferred: includes headers for SPF/DKIM/DMARC."),
  subject: z.string().optional().describe("Subject line (when raw is not available)."),
  from: z.string().optional().describe("From header value, e.g. 'Acme Billing <billing@acme.com>'."),
  replyTo: z.string().optional().describe("Reply-To header value."),
  to: z.string().optional().describe("Recipient address."),
  body: z.string().optional().describe("Plain-text body."),
  html: z.string().optional().describe("HTML body."),
  headers: z.record(z.string(), z.string()).optional().describe("Additional raw headers as name -> value."),
};

const indicatorSchema = z.object({
  key: z.string(),
  label: z.string(),
  weight: z.number(),
  source: z.enum(["header", "url", "attachment", "jev"]),
});

const attackTypeSchema = z.enum([
  "none",
  "credential_harvest",
  "payment_fraud",
  "malware_delivery",
  "executive_impersonation",
  "scam_other",
]);

export const verdictSchema = z.object({
  label: z.enum(["PHISHING", "SUSPICIOUS", "LEGITIMATE"]),
  probability: z.number().min(0).max(1),
  indicators: z.array(indicatorSchema).default([]),
  attackType: attackTypeSchema.default("none"),
  signals: z.object({
    is_phishing: z.number().default(0),
    requests_credentials: z.number().default(0),
    requests_payment: z.number().default(0),
    impersonates_brand_or_person: z.number().default(0),
    urgency_pressure: z.number().default(0),
    attack_type: attackTypeSchema.default("none"),
    attack_type_confidence: z.number().default(0),
  }),
  explained: z.boolean().default(false),
  explanation: z.string().optional(),
  model: z.object({ jev: z.string(), explainer: z.string().optional() }).default({ jev: "unknown" }),
  usage: z.object({ jevInputTokens: z.number(), explainerTokens: z.number().optional() }).default({ jevInputTokens: 0 }),
  latencyMs: z.number().default(0),
});

/** Convert the flat MCP tool input into the AnalyzeRequest contract. */
export function toAnalyzeRequest(input: z.infer<z.ZodObject<typeof analyzeEmailInputShape>>): AnalyzeRequest {
  if (input.raw && input.raw.trim().length > 0) return { raw: input.raw };
  const { subject, from, replyTo, to, body, html, headers } = input;
  const fields: NonNullable<AnalyzeRequest["fields"]> = {};
  if (subject !== undefined) fields.subject = subject;
  if (from !== undefined) fields.from = from;
  if (replyTo !== undefined) fields.replyTo = replyTo;
  if (to !== undefined) fields.to = to;
  if (body !== undefined) fields.body = body;
  if (html !== undefined) fields.html = html;
  if (headers !== undefined) fields.headers = headers;
  return { fields };
}

function envNumber(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 && n <= 1 ? n : fallback;
}

function envBool(env: NodeJS.ProcessEnv, name: string, fallback: boolean): boolean {
  const raw = env[name]?.trim().toLowerCase();
  if (raw === undefined || raw === "") return fallback;
  return raw === "true" || raw === "1" || raw === "yes";
}

/** Effective policy: env overrides (VERDICT_*) on top of DEFAULT_POLICY. */
export function policyFromEnv(env: NodeJS.ProcessEnv = process.env): VerdictPolicy {
  return {
    highThreshold: envNumber(env, "VERDICT_HIGH_THRESHOLD", DEFAULT_POLICY.highThreshold),
    lowThreshold: envNumber(env, "VERDICT_LOW_THRESHOLD", DEFAULT_POLICY.lowThreshold),
    explainSuspicious: envBool(env, "VERDICT_EXPLAIN_SUSPICIOUS", DEFAULT_POLICY.explainSuspicious),
    explainPhishing: envBool(env, "VERDICT_EXPLAIN_PHISHING", DEFAULT_POLICY.explainPhishing),
  };
}

function toolError(message: string): CallToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

export function registerTools(server: McpServer, deps: AnalyzeDeps, opts: RegisterToolsOptions = {}): void {
  const analyze = opts.analyze ?? defaultAnalyzeEmail;
  const env = opts.env ?? process.env;

  server.registerTool(
    "analyze_email",
    {
      title: "Analyze email for phishing",
      description:
        "Judge whether an email is phishing. Pass the full raw .eml source in `raw` when available; " +
        "otherwise pass subject/from/body fields. Returns a calibrated phishing probability, a verdict label " +
        "(PHISHING / SUSPICIOUS / LEGITIMATE), attack type and ranked indicators.",
      inputSchema: analyzeEmailInputShape,
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async (args) => {
      const request = toAnalyzeRequest(args);
      const hasContent = request.raw !== undefined || Object.keys(request.fields ?? {}).length > 0;
      if (!hasContent) return toolError("Provide `raw` email source or at least one of subject/from/body/html.");
      try {
        const verdict = await analyze(request, deps);
        return {
          content: [{ type: "text", text: formatVerdictSummary(verdict) }],
          structuredContent: verdict as unknown as Record<string, unknown>,
        };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return toolError(`Analysis failed: ${message}`);
      }
    },
  );

  server.registerTool(
    "explain_verdict",
    {
      title: "Format a verdict as a markdown card",
      description:
        "Render a MailVerdict verdict object (as returned by analyze_email) into a markdown card with " +
        "probability, indicators, signals and explanation. Pure formatting, no model call.",
      inputSchema: { verdict: verdictSchema.describe("Verdict object from analyze_email structuredContent.") },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    async ({ verdict }) => ({
      content: [{ type: "text", text: formatVerdictMarkdown(verdict as Verdict) }],
    }),
  );

  server.registerTool(
    "get_policy",
    {
      title: "Get verdict policy",
      description:
        "Return the thresholds currently in effect: probability >= highThreshold is PHISHING, " +
        "<= lowThreshold is LEGITIMATE, in between is SUSPICIOUS; plus when the LLM explainer runs.",
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    async () => {
      const policy = policyFromEnv(env);
      return {
        content: [{ type: "text", text: JSON.stringify(policy, null, 2) }],
        structuredContent: { ...policy },
      };
    },
  );
}
