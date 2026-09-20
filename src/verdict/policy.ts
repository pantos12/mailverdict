/**
 * Verdict policy resolution and labeling.
 *
 * Precedence: explicit partial (per request) > environment > DEFAULT_POLICY.
 */
import { DEFAULT_POLICY, type VerdictLabel, type VerdictPolicy } from "../types.js";

export const ENV_HIGH_THRESHOLD = "VERDICT_HIGH_THRESHOLD";
export const ENV_LOW_THRESHOLD = "VERDICT_LOW_THRESHOLD";
export const ENV_EXPLAIN_SUSPICIOUS = "VERDICT_EXPLAIN_SUSPICIOUS";
export const ENV_EXPLAIN_PHISHING = "VERDICT_EXPLAIN_PHISHING";

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

export function resolvePolicy(partial?: Partial<VerdictPolicy>, env: NodeJS.ProcessEnv = process.env): VerdictPolicy {
  const fromEnv: Partial<VerdictPolicy> = {};
  const high = parseNumberEnv(env[ENV_HIGH_THRESHOLD], ENV_HIGH_THRESHOLD);
  const low = parseNumberEnv(env[ENV_LOW_THRESHOLD], ENV_LOW_THRESHOLD);
  const explainSuspicious = parseBoolEnv(env[ENV_EXPLAIN_SUSPICIOUS], ENV_EXPLAIN_SUSPICIOUS);
  const explainPhishing = parseBoolEnv(env[ENV_EXPLAIN_PHISHING], ENV_EXPLAIN_PHISHING);
  if (high !== undefined) fromEnv.highThreshold = high;
  if (low !== undefined) fromEnv.lowThreshold = low;
  if (explainSuspicious !== undefined) fromEnv.explainSuspicious = explainSuspicious;
  if (explainPhishing !== undefined) fromEnv.explainPhishing = explainPhishing;

  const policy: VerdictPolicy = { ...DEFAULT_POLICY, ...fromEnv, ...stripUndefined(partial ?? {}) };
  validatePolicy(policy);
  return policy;
}

export function validatePolicy(policy: VerdictPolicy): void {
  const { highThreshold: high, lowThreshold: low } = policy;
  if (typeof high !== "number" || !Number.isFinite(high)) throw new PolicyError("highThreshold must be a finite number");
  if (typeof low !== "number" || !Number.isFinite(low)) throw new PolicyError("lowThreshold must be a finite number");
  if (low < 0) throw new PolicyError(`lowThreshold must be >= 0 (got ${low})`);
  if (high > 1) throw new PolicyError(`highThreshold must be <= 1 (got ${high})`);
  if (!(low < high)) throw new PolicyError(`lowThreshold (${low}) must be strictly less than highThreshold (${high})`);
  if (typeof policy.explainSuspicious !== "boolean") throw new PolicyError("explainSuspicious must be a boolean");
  if (typeof policy.explainPhishing !== "boolean") throw new PolicyError("explainPhishing must be a boolean");
}

export function labelFor(probability: number, policy: VerdictPolicy): VerdictLabel {
  if (!Number.isFinite(probability)) throw new PolicyError(`probability must be a finite number (got ${probability})`);
  if (probability >= policy.highThreshold) return "PHISHING";
  if (probability <= policy.lowThreshold) return "LEGITIMATE";
  return "SUSPICIOUS";
}

export function shouldExplain(label: VerdictLabel, policy: VerdictPolicy): boolean {
  if (label === "SUSPICIOUS") return policy.explainSuspicious;
  if (label === "PHISHING") return policy.explainPhishing;
  return false;
}

function parseNumberEnv(value: string | undefined, name: string): number | undefined {
  if (value === undefined || value.trim() === "") return undefined;
  const n = Number(value);
  if (!Number.isFinite(n)) throw new PolicyError(`${name} must be a number (got "${value}")`);
  return n;
}

function parseBoolEnv(value: string | undefined, name: string): boolean | undefined {
  if (value === undefined || value.trim() === "") return undefined;
  const v = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(v)) return true;
  if (["0", "false", "no", "off"].includes(v)) return false;
  throw new PolicyError(`${name} must be a boolean (got "${value}")`);
}

function stripUndefined<T extends object>(obj: T): Partial<T> {
  const out: Partial<T> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) (out as Record<string, unknown>)[k] = v;
  }
  return out;
}
