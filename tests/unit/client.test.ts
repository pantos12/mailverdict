import { beforeEach, describe, expect, it, vi } from "vitest";
import { makeEmail } from "../helpers/fixtures.js";

const systemOne = vi.fn();
const ctor = vi.fn();

vi.mock("@typesafe-ai/sdk", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@typesafe-ai/sdk")>();
  return {
    ...actual,
    TypeSafeClient: class {
      constructor(config: unknown) {
        ctor(config);
      }
      systemOne = systemOne;
    },
  };
});

const { createJevClient, mapAnswers, DEFAULT_RETRY } = await import("../../src/jev/client.js");

function fakeResult(overrides: Record<string, unknown> = {}) {
  return {
    model: "jev-2025-08",
    usage: { input_tokens: 1234, output_tokens: 12 },
    answers: {
      is_phishing: { type: "noul", noul: 0.93 },
      requests_credentials: { type: "noul", noul: 0.8 },
      requests_payment: { type: "noul", noul: 0.05 },
      impersonates_brand_or_person: { type: "noul", noul: 0.71 },
      urgency_pressure: { type: "score", score: 1.6, confidence: 0.7, legend: {}, probabilities: {} },
      attack_type: {
        type: "choice",
        choice: "credential_harvest",
        confidence: 0.88,
        probabilities: { credential_harvest: 0.88, none: 0.05, payment_fraud: 0.02, malware_delivery: 0.02, executive_impersonation: 0.02, scam_other: 0.01 },
      },
      ...overrides,
    },
  };
}

describe("createJevClient", () => {
  beforeEach(() => {
    systemOne.mockReset();
    ctor.mockReset();
  });

  it("requires an api key", () => {
    expect(() => createJevClient({ apiKey: "" })).toThrow(/apiKey/);
  });

  it("configures the SDK with retries covering 429 and 5xx (incl. 529)", () => {
    createJevClient({ apiKey: "k", model: "jev-test" });
    expect(ctor).toHaveBeenCalledTimes(1);
    const config = ctor.mock.calls[0]?.[0] as { apiKey: string; retry: { maxRetries: number; httpStatuses: Set<number> }; timeout: number };
    expect(config.apiKey).toBe("k");
    expect(config.retry.maxRetries).toBeGreaterThanOrEqual(2);
    expect(config.retry.httpStatuses.has(429)).toBe(true);
    expect(config.retry.httpStatuses.has(529)).toBe(true);
    expect(config.retry.httpStatuses.has(500)).toBe(true);
    expect(config.retry.httpStatuses.has(400)).toBe(false);
    expect(config.timeout).toBeGreaterThan(0);
    expect(DEFAULT_RETRY.httpStatuses?.has(529)).toBe(true);
  });

  it("sends state + questions (+ model) to systemOne and maps answers to JevSignals", async () => {
    systemOne.mockResolvedValue(fakeResult());
    const client = createJevClient({ apiKey: "k", model: "jev-test" });
    const email = makeEmail({ subject: "Verify now" });
    const result = await client.evaluate(email);

    expect(systemOne).toHaveBeenCalledTimes(1);
    const request = systemOne.mock.calls[0]?.[0] as { state: { headers: { subject: string } }; questions: Record<string, unknown>; model?: string };
    expect(request.model).toBe("jev-test");
    expect(request.state.headers.subject).toBe("Verify now");
    expect(Object.keys(request.questions).sort()).toEqual(
      ["attack_type", "impersonates_brand_or_person", "is_phishing", "requests_credentials", "requests_payment", "urgency_pressure"].sort(),
    );

    expect(result.model).toBe("jev-2025-08");
    expect(result.inputTokens).toBe(1234);
    expect(result.signals).toEqual({
      is_phishing: 0.93,
      requests_credentials: 0.8,
      requests_payment: 0.05,
      impersonates_brand_or_person: 0.71,
      urgency_pressure: 1.6,
      attack_type: "credential_harvest",
      attack_type_confidence: 0.88,
    });
  });

  it("omits model from the request when not configured", async () => {
    systemOne.mockResolvedValue(fakeResult());
    await createJevClient({ apiKey: "k" }).evaluate(makeEmail());
    const request = systemOne.mock.calls[0]?.[0] as Record<string, unknown>;
    expect("model" in request).toBe(false);
  });

  it("propagates SDK errors", async () => {
    systemOne.mockRejectedValue(new Error("rate limited"));
    await expect(createJevClient({ apiKey: "k" }).evaluate(makeEmail())).rejects.toThrow("rate limited");
  });
});

describe("mapAnswers", () => {
  it("clamps out-of-range values and falls back for unknown attack types", () => {
    const signals = mapAnswers(
      fakeResult({
        is_phishing: { type: "noul", noul: 1.4 },
        urgency_pressure: { type: "score", score: -0.5, confidence: 0.1, legend: {}, probabilities: {} },
        attack_type: { type: "choice", choice: "something_new", confidence: 2, probabilities: {} },
      }) as unknown as Parameters<typeof mapAnswers>[0],
    );
    expect(signals.is_phishing).toBe(1);
    expect(signals.urgency_pressure).toBe(0);
    expect(signals.attack_type).toBe("scam_other");
    expect(signals.attack_type_confidence).toBe(1);
  });
});
