import { describe, expect, it } from "vitest";
import { formatPercent, formatVerdictMarkdown, formatVerdictSummary } from "../../src/mcp/format.js";
import type { Verdict } from "../../src/types.js";

const verdict: Verdict = {
  label: "PHISHING",
  probability: 0.934,
  attackType: "credential_harvest",
  indicators: [
    { key: "reply_to_mismatch", label: "Reply-To domain differs from From", weight: 0.6, source: "header" },
    { key: "url_mismatch", label: "Link text points to a different domain", weight: 0.9, source: "url" },
    { key: "spf_fail", label: "SPF failed", weight: 0.7, source: "header" },
  ],
  signals: {
    is_phishing: 0.93,
    requests_credentials: 0.88,
    requests_payment: 0.05,
    impersonates_brand_or_person: 0.8,
    urgency_pressure: 2,
    attack_type: "credential_harvest",
    attack_type_confidence: 0.81,
  },
  explained: true,
  explanation: "The message impersonates a bank and links to a look-alike domain.",
  model: { jev: "jev-1", explainer: "openai/gpt-4o-mini" },
  usage: { jevInputTokens: 512, explainerTokens: 120 },
  latencyMs: 640,
};

describe("formatPercent", () => {
  it("rounds and clamps", () => {
    expect(formatPercent(0.934)).toBe("93%");
    expect(formatPercent(1.4)).toBe("100%");
    expect(formatPercent(-1)).toBe("0%");
  });
});

describe("formatVerdictSummary", () => {
  it("produces the expected layout with indicators sorted by weight", () => {
    const text = formatVerdictSummary(verdict);
    const lines = text.split("\n");
    expect(lines[0]).toBe("Verdict: PHISHING (93% probability) — credential_harvest");
    expect(lines[1]).toBe("Top indicators:");
    expect(lines[2]).toBe("• Link text points to a different domain");
    expect(lines[3]).toBe("• SPF failed");
    expect(lines[4]).toBe("• Reply-To domain differs from From");
    expect(lines[5]).toBe("Explanation: The message impersonates a bank and links to a look-alike domain.");
  });

  it("handles no indicators and no explanation", () => {
    const text = formatVerdictSummary({ ...verdict, indicators: [], explanation: undefined, explained: false });
    expect(text).toBe("Verdict: PHISHING (93% probability) — credential_harvest\nTop indicators:\n• none");
  });

  it("caps indicators at five", () => {
    const many = Array.from({ length: 8 }, (_, i) => ({
      key: `k${i}`,
      label: `Indicator ${i}`,
      weight: i / 10,
      source: "jev" as const,
    }));
    const text = formatVerdictSummary({ ...verdict, indicators: many, explanation: undefined });
    expect(text.split("\n").filter((l) => l.startsWith("• "))).toHaveLength(5);
  });
});

describe("formatVerdictMarkdown", () => {
  it("renders a markdown card with heading, indicators, signals table and explanation", () => {
    const md = formatVerdictMarkdown(verdict);
    expect(md).toContain("## Verdict: PHISHING");
    expect(md).toContain("**Phishing probability:** 93%");
    expect(md).toContain("- **Link text points to a different domain** (url, weight 0.90)");
    expect(md).toContain("| Requests credentials | 0.88 |");
    expect(md).toContain("> The message impersonates a bank");
    expect(md).toContain("Judge: jev-1 · Explainer: openai/gpt-4o-mini · 640 ms");
  });

  it("omits explanation section when absent", () => {
    const md = formatVerdictMarkdown({ ...verdict, explanation: undefined, model: { jev: "jev-1" } });
    expect(md).not.toContain("### Explanation");
    expect(md).toContain("_None detected._".length > 0 ? "Judge: jev-1 · 640 ms" : "");
  });
});
