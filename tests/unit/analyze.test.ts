import { describe, expect, it, vi } from "vitest";
import { ZodError } from "zod";
import { analyzeEmail, createDefaultDeps, validateAnalyzeRequest, type AnalyzeDeps } from "../../src/analyze.js";
import type { Explainer } from "../../src/explain/openrouter.js";
import type { JevClient } from "../../src/jev/client.js";
import type { JevSignals } from "../../src/types.js";
import { makeSignals } from "../helpers/fixtures.js";

const RAW = [
  "Authentication-Results: mx; spf=fail; dkim=none; dmarc=fail",
  "From: Bank <alerts@bank.example>",
  "Reply-To: <help@bank-secure-verify.net>",
  "To: user@corp.example",
  "Subject: Verify your account",
  "",
  "Verify now at https://bank-secure-verify.net/login or your account will be closed today.",
].join("\r\n");

function fakeJev(signals: JevSignals): JevClient & { evaluate: ReturnType<typeof vi.fn> } {
  return { evaluate: vi.fn().mockResolvedValue({ signals, model: "jev-fake", inputTokens: 777 }) };
}

function fakeExplainer(): Explainer & { explain: ReturnType<typeof vi.fn> } {
  return { explain: vi.fn().mockResolvedValue({ text: "Looks risky; do not click.", model: "llm-fake", tokens: 55 }) };
}

function fakeClock(...ticks: number[]): () => number {
  let i = 0;
  return () => ticks[Math.min(i++, ticks.length - 1)] ?? 0;
}

describe("analyzeEmail", () => {
  it("runs parse -> jev -> label -> indicators and assembles the verdict (PHISHING, no explainer call)", async () => {
    const jev = fakeJev(makeSignals({ is_phishing: 0.97, requests_credentials: 0.9, urgency_pressure: 2, attack_type: "credential_harvest", attack_type_confidence: 0.9 }));
    const explainer = fakeExplainer();
    const verdict = await analyzeEmail({ raw: RAW }, { jev, explainer, now: fakeClock(1_000, 1_250), env: {} });

    expect(jev.evaluate).toHaveBeenCalledTimes(1);
    expect(jev.evaluate.mock.calls[0]?.[0]).toMatchObject({ subject: "Verify your account", signals: { replyToMismatch: true } });
    expect(explainer.explain).not.toHaveBeenCalled();
    expect(verdict.label).toBe("PHISHING");
    expect(verdict.probability).toBe(0.97);
    expect(verdict.attackType).toBe("credential_harvest");
    expect(verdict.explained).toBe(false);
    expect(verdict.explanation).toBeUndefined();
    expect(verdict.model).toEqual({ jev: "jev-fake" });
    expect(verdict.usage).toEqual({ jevInputTokens: 777 });
    expect(verdict.latencyMs).toBe(250);
    expect(verdict.indicators.map((i) => i.key)).toEqual(
      expect.arrayContaining(["spf_fail", "dmarc_fail", "reply_to_mismatch", "requests_credentials", "urgency_pressure"]),
    );
    expect(verdict.indicators[0]?.weight).toBeGreaterThanOrEqual(verdict.indicators.at(-1)?.weight ?? 0);
  });

  it("invokes the explainer only in the SUSPICIOUS band by default and records its model/usage", async () => {
    const jev = fakeJev(makeSignals({ is_phishing: 0.55 }));
    const explainer = fakeExplainer();
    const verdict = await analyzeEmail({ raw: RAW }, { jev, explainer, env: {} });

    expect(verdict.label).toBe("SUSPICIOUS");
    expect(explainer.explain).toHaveBeenCalledTimes(1);
    const [email, signals, indicators, label] = explainer.explain.mock.calls[0] ?? [];
    expect(email).toMatchObject({ subject: "Verify your account" });
    expect(signals).toMatchObject({ is_phishing: 0.55 });
    expect(Array.isArray(indicators)).toBe(true);
    expect(label).toBe("SUSPICIOUS");
    expect(verdict.explained).toBe(true);
    expect(verdict.explanation).toBe("Looks risky; do not click.");
    expect(verdict.model).toEqual({ jev: "jev-fake", explainer: "llm-fake" });
    expect(verdict.usage).toEqual({ jevInputTokens: 777, explainerTokens: 55 });
    expect(verdict.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it("does not explain LEGITIMATE verdicts", async () => {
    const explainer = fakeExplainer();
    const verdict = await analyzeEmail({ raw: RAW }, { jev: fakeJev(makeSignals({ is_phishing: 0.02 })), explainer, env: {} });
    expect(verdict.label).toBe("LEGITIMATE");
    expect(explainer.explain).not.toHaveBeenCalled();
    expect(verdict.explained).toBe(false);
  });

  it("honours request policy: explainPhishing=true triggers the explainer for PHISHING", async () => {
    const explainer = fakeExplainer();
    const verdict = await analyzeEmail(
      { raw: RAW, policy: { explainPhishing: true } },
      { jev: fakeJev(makeSignals({ is_phishing: 0.99 })), explainer, env: {} },
    );
    expect(verdict.label).toBe("PHISHING");
    expect(explainer.explain).toHaveBeenCalledTimes(1);
    expect(verdict.explained).toBe(true);
  });

  it("honours request thresholds over env thresholds", async () => {
    const verdict = await analyzeEmail(
      { raw: RAW, policy: { highThreshold: 0.5 } },
      { jev: fakeJev(makeSignals({ is_phishing: 0.6 })), env: { VERDICT_HIGH_THRESHOLD: "0.95" } },
    );
    expect(verdict.label).toBe("PHISHING");
  });

  it("works without an explainer in the SUSPICIOUS band", async () => {
    const verdict = await analyzeEmail({ raw: RAW }, { jev: fakeJev(makeSignals({ is_phishing: 0.5 })), env: {} });
    expect(verdict.label).toBe("SUSPICIOUS");
    expect(verdict.explained).toBe(false);
    expect(verdict.model.explainer).toBeUndefined();
  });

  it("still returns the verdict when the explainer fails, and reports the error", async () => {
    const explainer: Explainer = { explain: vi.fn().mockRejectedValue(new Error("llm down")) };
    const onExplainerError = vi.fn();
    const verdict = await analyzeEmail({ raw: RAW }, { jev: fakeJev(makeSignals({ is_phishing: 0.5 })), explainer, env: {}, onExplainerError });
    expect(verdict.label).toBe("SUSPICIOUS");
    expect(verdict.explained).toBe(false);
    expect(onExplainerError).toHaveBeenCalledWith(expect.objectContaining({ message: "llm down" }));
  });

  it("propagates Jev failures", async () => {
    const jev: JevClient = { evaluate: vi.fn().mockRejectedValue(new Error("jev unavailable")) };
    await expect(analyzeEmail({ raw: RAW }, { jev, env: {} })).rejects.toThrow("jev unavailable");
  });

  it("accepts fields-only requests", async () => {
    const jev = fakeJev(makeSignals());
    const verdict = await analyzeEmail({ fields: { subject: "Lunch?", from: "Bob <bob@corp.example>", body: "Pizza at noon?" } }, { jev, env: {} });
    expect(verdict.label).toBe("LEGITIMATE");
    expect(jev.evaluate.mock.calls[0]?.[0]).toMatchObject({ subject: "Lunch?", from: { address: "bob@corp.example" } });
  });
});

describe("validateAnalyzeRequest", () => {
  it("accepts raw-only and fields-only requests", () => {
    expect(validateAnalyzeRequest({ raw: "From: a@b.c\r\n\r\nhi" })).toEqual({ raw: "From: a@b.c\r\n\r\nhi" });
    const fields = { subject: "s", body: "b", headers: { "X-Test": "1" } };
    expect(validateAnalyzeRequest({ fields, policy: { highThreshold: 0.8 } })).toEqual({ fields, policy: { highThreshold: 0.8 } });
  });

  it.each([
    [{}],
    [{ raw: "x", fields: { subject: "s" } }],
    [{ raw: "" }],
    [{ raw: 12 }],
    [{ fields: { subject: 1 } }],
    [{ fields: { subject: "s" }, policy: { highThreshold: "0.9" } }],
    [{ fields: { subject: "s" }, policy: { highThreshold: 1.5 } }],
    [{ fields: { subject: "s" }, unknown: true }],
    ["not an object"],
    [null],
  ])("rejects %j", (input) => {
    expect(() => validateAnalyzeRequest(input)).toThrow(ZodError);
  });

  it("rejects raw larger than 2 MB", () => {
    expect(() => validateAnalyzeRequest({ raw: "a".repeat(2 * 1024 * 1024 + 1) })).toThrow(/2 MB/);
    expect(() => validateAnalyzeRequest({ raw: "a".repeat(2 * 1024 * 1024) })).not.toThrow();
  });
});

describe("createDefaultDeps", () => {
  it("throws a clear error when TYPESAFE_API_KEY is missing", () => {
    expect(() => createDefaultDeps({})).toThrow(/TYPESAFE_API_KEY/);
    expect(() => createDefaultDeps({ TYPESAFE_API_KEY: "   " })).toThrow(/TYPESAFE_API_KEY/);
  });

  it("creates a jev client without an explainer when OPENROUTER_API_KEY is absent", () => {
    const deps: AnalyzeDeps = createDefaultDeps({ TYPESAFE_API_KEY: "ts-key" });
    expect(typeof deps.jev.evaluate).toBe("function");
    expect(deps.explainer).toBeUndefined();
  });

  it("adds an explainer when OPENROUTER_API_KEY is present", () => {
    const deps = createDefaultDeps({ TYPESAFE_API_KEY: "ts-key", OPENROUTER_API_KEY: "or-key" });
    expect(deps.explainer).toBeDefined();
    expect(typeof deps.explainer?.explain).toBe("function");
  });
});
