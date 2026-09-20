import { describe, expect, it } from "vitest";
import { DEFAULT_POLICY } from "../../src/types.js";
import { PolicyError, labelFor, resolvePolicy, shouldExplain } from "../../src/verdict/policy.js";

describe("resolvePolicy", () => {
  it("returns DEFAULT_POLICY when nothing is provided", () => {
    expect(resolvePolicy(undefined, {})).toEqual(DEFAULT_POLICY);
  });

  it("applies env overrides", () => {
    const policy = resolvePolicy(undefined, {
      VERDICT_HIGH_THRESHOLD: "0.8",
      VERDICT_LOW_THRESHOLD: "0.2",
      VERDICT_EXPLAIN_SUSPICIOUS: "false",
      VERDICT_EXPLAIN_PHISHING: "true",
    });
    expect(policy).toEqual({ highThreshold: 0.8, lowThreshold: 0.2, explainSuspicious: false, explainPhishing: true });
  });

  it("lets the request partial win over env, and ignores undefined partial fields", () => {
    const policy = resolvePolicy(
      { highThreshold: 0.95, explainPhishing: undefined },
      { VERDICT_HIGH_THRESHOLD: "0.8", VERDICT_LOW_THRESHOLD: "0.3", VERDICT_EXPLAIN_PHISHING: "1" },
    );
    expect(policy).toEqual({ highThreshold: 0.95, lowThreshold: 0.3, explainSuspicious: true, explainPhishing: true });
  });

  it("ignores blank env values", () => {
    expect(resolvePolicy(undefined, { VERDICT_HIGH_THRESHOLD: "  ", VERDICT_LOW_THRESHOLD: "" })).toEqual(DEFAULT_POLICY);
  });

  it.each([
    [{ lowThreshold: 0.9, highThreshold: 0.9 }, /strictly less/],
    [{ lowThreshold: 0.95 }, /strictly less/],
    [{ lowThreshold: -0.1 }, />= 0/],
    [{ highThreshold: 1.5 }, /<= 1/],
    [{ highThreshold: Number.NaN }, /finite/],
  ])("rejects invalid thresholds %j", (partial, message) => {
    expect(() => resolvePolicy(partial, {})).toThrow(PolicyError);
    expect(() => resolvePolicy(partial, {})).toThrow(message);
  });

  it("rejects non-numeric / non-boolean env values", () => {
    expect(() => resolvePolicy(undefined, { VERDICT_HIGH_THRESHOLD: "high" })).toThrow(/VERDICT_HIGH_THRESHOLD/);
    expect(() => resolvePolicy(undefined, { VERDICT_EXPLAIN_SUSPICIOUS: "maybe" })).toThrow(/VERDICT_EXPLAIN_SUSPICIOUS/);
  });

  it("accepts the boundary case low=0, high=1", () => {
    expect(resolvePolicy({ lowThreshold: 0, highThreshold: 1 }, {})).toMatchObject({ lowThreshold: 0, highThreshold: 1 });
  });
});

describe("labelFor", () => {
  const policy = { ...DEFAULT_POLICY, highThreshold: 0.9, lowThreshold: 0.1 };

  it.each([
    [0.95, "PHISHING"],
    [0.9, "PHISHING"],
    [0.899, "SUSPICIOUS"],
    [0.5, "SUSPICIOUS"],
    [0.101, "SUSPICIOUS"],
    [0.1, "LEGITIMATE"],
    [0, "LEGITIMATE"],
  ])("p=%d -> %s", (p, label) => {
    expect(labelFor(p, policy)).toBe(label);
  });

  it("rejects non-finite probabilities", () => {
    expect(() => labelFor(Number.NaN, policy)).toThrow(PolicyError);
  });
});

describe("shouldExplain", () => {
  it("follows the policy flags per band", () => {
    expect(shouldExplain("SUSPICIOUS", DEFAULT_POLICY)).toBe(true);
    expect(shouldExplain("PHISHING", DEFAULT_POLICY)).toBe(false);
    expect(shouldExplain("LEGITIMATE", DEFAULT_POLICY)).toBe(false);
    expect(shouldExplain("PHISHING", { ...DEFAULT_POLICY, explainPhishing: true })).toBe(true);
    expect(shouldExplain("SUSPICIOUS", { ...DEFAULT_POLICY, explainSuspicious: false })).toBe(false);
  });
});
