/**
 * JevClient: wraps the TypeSafe SDK and maps System One answers to JevSignals.
 */
import { TypeSafeClient, type RetryPolicy, type SystemOneResult } from "@typesafe-ai/sdk";
import type { AttackType, JevSignals, ParsedEmail } from "../types.js";
import { buildQuestions, buildState, type JevQuestions } from "./questions.js";

export interface JevEvaluation {
  signals: JevSignals;
  model: string;
  inputTokens: number;
}

export interface JevClient {
  evaluate(email: ParsedEmail): Promise<JevEvaluation>;
}

export interface JevClientOptions {
  apiKey: string;
  /** Model override; the SDK default (`jev-latest`) is used when omitted. */
  model?: string;
  /** Per-attempt timeout in ms. Default 30_000. */
  timeoutMs?: number;
  /** Retry overrides; defaults retry 429 / 5xx (incl. 529) with backoff. */
  retry?: Partial<RetryPolicy>;
}

const ATTACK_TYPES: ReadonlySet<string> = new Set<AttackType>([
  "none",
  "credential_harvest",
  "payment_fraud",
  "malware_delivery",
  "executive_impersonation",
  "scam_other",
]);

const RETRYABLE_STATUSES: ReadonlySet<number> = new Set([
  408,
  429,
  ...Array.from({ length: 100 }, (_, i) => 500 + i), // 500-599, which includes 529 (overloaded)
]);

export const DEFAULT_RETRY: Partial<RetryPolicy> = {
  maxRetries: 3,
  backoffInitialMs: 750,
  backoffMaxMs: 8_000,
  httpStatuses: RETRYABLE_STATUSES,
  respectRetryAfter: true,
};

export function createJevClient(opts: JevClientOptions): JevClient {
  if (!opts.apiKey || opts.apiKey.trim().length === 0) {
    throw new Error("createJevClient: apiKey is required");
  }
  const client = new TypeSafeClient({
    apiKey: opts.apiKey,
    timeout: opts.timeoutMs ?? 30_000,
    retry: { ...DEFAULT_RETRY, ...opts.retry },
  });
  const questions = buildQuestions();

  return {
    async evaluate(email: ParsedEmail): Promise<JevEvaluation> {
      const request = opts.model
        ? { state: buildState(email), questions, model: opts.model }
        : { state: buildState(email), questions };
      const result = await client.systemOne(request);
      return {
        signals: mapAnswers(result),
        model: result.model,
        inputTokens: result.usage.input_tokens,
      };
    },
  };
}

/** Map a System One result onto the stable JevSignals contract, clamping every value to its range. */
export function mapAnswers(result: Pick<SystemOneResult<JevQuestions>, "answers">): JevSignals {
  const a = result.answers;
  const rawType: string = a.attack_type.choice;
  return {
    is_phishing: clamp01(a.is_phishing.noul),
    requests_credentials: clamp01(a.requests_credentials.noul),
    requests_payment: clamp01(a.requests_payment.noul),
    impersonates_brand_or_person: clamp01(a.impersonates_brand_or_person.noul),
    urgency_pressure: clamp(a.urgency_pressure.score, 0, 2),
    attack_type: ATTACK_TYPES.has(rawType) ? (rawType as AttackType) : "scam_other",
    attack_type_confidence: clamp01(a.attack_type.confidence),
  };
}

function clamp(n: number, lo: number, hi: number): number {
  if (!Number.isFinite(n)) return lo;
  return Math.min(hi, Math.max(lo, n));
}

function clamp01(n: number): number {
  return clamp(n, 0, 1);
}
