/**
 * MailVerdict pipeline: parse -> Jev -> policy/label -> indicators -> (optional) explanation.
 *
 * Public surface used by the API/MCP layer:
 *   analyzeEmail, createDefaultDeps, validateAnalyzeRequest, AnalyzeDeps
 */
import { z } from "zod";
import { parseEmail } from "./email/parse.js";
import { createOpenRouterExplainer, type Explainer } from "./explain/openrouter.js";
import { createJevClient, type JevClient } from "./jev/client.js";
import type { AnalyzeRequest, Verdict } from "./types.js";
import { deriveIndicators } from "./verdict/indicators.js";
import { labelFor, resolvePolicy, shouldExplain } from "./verdict/policy.js";

export interface AnalyzeDeps {
  jev: JevClient;
  explainer?: Explainer;
  /** Clock for latency measurement; defaults to Date.now. */
  now?: () => number;
  /** Environment used for policy defaults; defaults to process.env. */
  env?: NodeJS.ProcessEnv;
  /** Called when the optional explainer fails; the verdict is still returned. */
  onExplainerError?: (error: unknown) => void;
}

export const MAX_RAW_BYTES = 2 * 1024 * 1024;

const policySchema = z
  .object({
    highThreshold: z.number().min(0).max(1).optional(),
    lowThreshold: z.number().min(0).max(1).optional(),
    explainSuspicious: z.boolean().optional(),
    explainPhishing: z.boolean().optional(),
  })
  .strict();

const fieldsSchema = z
  .object({
    subject: z.string().optional(),
    from: z.string().optional(),
    replyTo: z.string().optional(),
    to: z.string().optional(),
    body: z.string().optional(),
    html: z.string().optional(),
    headers: z.record(z.string(), z.string()).optional(),
  })
  .strict();

export const analyzeRequestSchema = z
  .object({
    raw: z
      .string()
      .min(1, "raw must not be empty")
      .refine((s) => Buffer.byteLength(s, "utf8") <= MAX_RAW_BYTES, { message: "raw exceeds 2 MB" })
      .optional(),
    fields: fieldsSchema.optional(),
    policy: policySchema.optional(),
  })
  .strict()
  .refine((v) => (v.raw !== undefined) !== (v.fields !== undefined), {
    message: "Provide exactly one of `raw` or `fields`",
  });

/** Validates untrusted input at the system boundary. Throws ZodError on failure. */
export function validateAnalyzeRequest(input: unknown): AnalyzeRequest {
  const parsed = analyzeRequestSchema.parse(input);
  const out: AnalyzeRequest = {};
  if (parsed.raw !== undefined) out.raw = parsed.raw;
  if (parsed.fields !== undefined) out.fields = parsed.fields;
  if (parsed.policy !== undefined) out.policy = parsed.policy;
  return out;
}

export async function analyzeEmail(req: AnalyzeRequest, deps: AnalyzeDeps): Promise<Verdict> {
  const now = deps.now ?? Date.now;
  const started = now();
  const policy = resolvePolicy(req.policy, deps.env ?? process.env);

  const email = await parseEmail(req);
  const jev = await deps.jev.evaluate(email);
  const probability = jev.signals.is_phishing;
  const label = labelFor(probability, policy);
  const indicators = deriveIndicators(email, jev.signals);

  const verdict: Verdict = {
    label,
    probability,
    indicators,
    attackType: jev.signals.attack_type,
    signals: jev.signals,
    explained: false,
    model: { jev: jev.model },
    usage: { jevInputTokens: jev.inputTokens },
    latencyMs: 0,
  };

  if (deps.explainer && shouldExplain(label, policy)) {
    try {
      const explanation = await deps.explainer.explain(email, jev.signals, indicators, label);
      verdict.explained = true;
      verdict.explanation = explanation.text;
      verdict.model.explainer = explanation.model;
      verdict.usage.explainerTokens = explanation.tokens;
    } catch (error) {
      // The verdict is Jev's; a failed prose explanation must not fail the analysis.
      deps.onExplainerError?.(error);
    }
  }

  verdict.latencyMs = Math.max(0, now() - started);
  return verdict;
}

export function createDefaultDeps(env: NodeJS.ProcessEnv = process.env): AnalyzeDeps {
  const typesafeKey = env.TYPESAFE_API_KEY?.trim();
  if (!typesafeKey) {
    throw new Error(
      "TYPESAFE_API_KEY is not set. MailVerdict needs a TypeSafe API key for Jev; add it to your environment or .env file.",
    );
  }
  const deps: AnalyzeDeps = {
    jev: createJevClient({ apiKey: typesafeKey, model: env.TYPESAFE_MODEL?.trim() || undefined }),
    env,
  };
  const openRouterKey = env.OPENROUTER_API_KEY?.trim();
  if (openRouterKey) {
    deps.explainer = createOpenRouterExplainer({ apiKey: openRouterKey, model: env.OPENROUTER_MODEL?.trim() || undefined });
  }
  return deps;
}
