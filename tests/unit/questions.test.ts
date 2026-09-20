import { describe, expect, it } from "vitest";
import { BODY_CHAR_LIMIT, MAX_URLS_IN_STATE, buildQuestions, buildState } from "../../src/jev/questions.js";
import { makeEmail } from "../helpers/fixtures.js";

describe("buildState", () => {
  it("produces a compact JSON-serializable state with headers, auth, signals, urls, attachments and body", () => {
    const email = makeEmail({
      replyTo: { name: "Help", address: "help@other.example" },
      returnPath: "bounce@other.example",
      urls: [{ href: "https://a.example/x", domain: "a.example", anchorText: "click", textMismatch: true }],
      attachments: [{ filename: "a.pdf", contentType: "application/pdf", size: 10 }],
      signals: { replyToDomain: "other.example", replyToMismatch: true, returnPathMismatch: true, distinctUrlDomains: ["a.example"] },
    });
    const state = buildState(email);
    expect(state.headers).toEqual({
      subject: "Hello",
      from: { name: "Alice", address: "alice@x.example", domain: "x.example" },
      reply_to: { name: "Help", address: "help@other.example", domain: "other.example" },
      return_path: "bounce@other.example",
      to: ["bob@y.example"],
      date: "2025-09-01T10:00:00.000Z",
    });
    expect(state.authentication).toEqual({ spf: "pass", dkim: "pass", dmarc: "pass" });
    expect(state.signals).toEqual({
      reply_to_mismatch: true,
      return_path_mismatch: true,
      display_name_looks_like_email: false,
      distinct_url_domains: ["a.example"],
      has_dangerous_attachment: false,
      has_html: false,
    });
    expect(state.urls).toEqual([{ href: "https://a.example/x", domain: "a.example", anchor_text: "click", anchor_text_mismatch: true }]);
    expect(state.attachments).toEqual([{ filename: "a.pdf", content_type: "application/pdf", size: 10 }]);
    expect(state.body).toEqual({ text: "Just checking in.", truncated: false, original_chars: 17 });
    expect(JSON.parse(JSON.stringify(state))).toEqual(state);
  });

  it("uses null for absent optional header parts", () => {
    const state = buildState(makeEmail({ replyTo: undefined, returnPath: undefined, date: undefined, from: {} }));
    expect(state.headers.reply_to).toBeNull();
    expect(state.headers.return_path).toBeNull();
    expect(state.headers.date).toBeNull();
    expect(state.headers.from).toEqual({ name: null, address: null, domain: "x.example" });
    expect(state.urls).toEqual([]);
  });

  it("truncates long bodies to the character budget and flags it", () => {
    const text = "x".repeat(BODY_CHAR_LIMIT + 5_000);
    const state = buildState(makeEmail({ text }));
    expect(state.body.truncated).toBe(true);
    expect(state.body.original_chars).toBe(BODY_CHAR_LIMIT + 5_000);
    expect(state.body.text.startsWith("x".repeat(BODY_CHAR_LIMIT))).toBe(true);
    expect(state.body.text.length).toBeLessThan(BODY_CHAR_LIMIT + 50);
    expect(state.body.text).toContain("truncated");
  });

  it("caps the url list", () => {
    const urls = Array.from({ length: MAX_URLS_IN_STATE + 10 }, (_, i) => ({
      href: `https://d${i}.example/`,
      domain: `d${i}.example`,
      textMismatch: false,
    }));
    expect(buildState(makeEmail({ urls })).urls).toHaveLength(MAX_URLS_IN_STATE);
  });
});

describe("buildQuestions", () => {
  it("defines one question per JevSignals key with the right SDK types", () => {
    const q = buildQuestions();
    expect(Object.keys(q).sort()).toEqual(
      ["attack_type", "impersonates_brand_or_person", "is_phishing", "requests_credentials", "requests_payment", "urgency_pressure"].sort(),
    );
    expect(q.is_phishing.type).toBe("noul");
    expect(q.is_phishing.criteria?.true).toMatch(/deceive|credentials/i);
    expect(q.is_phishing.criteria?.false).toMatch(/legitimate/i);
    expect(String(q.is_phishing.instructions)).toMatch(/SPF\/DKIM\/DMARC/);
    expect(q.requests_credentials.type).toBe("noul");
    expect(q.requests_payment.type).toBe("noul");
    expect(q.impersonates_brand_or_person.type).toBe("noul");
    expect(q.urgency_pressure.type).toBe("score");
    expect(q.urgency_pressure.criteria).toHaveLength(3);
    expect(q.attack_type.type).toBe("choice");
    expect(Object.keys(q.attack_type.criteria).sort()).toEqual(
      ["credential_harvest", "executive_impersonation", "malware_delivery", "none", "payment_fraud", "scam_other"].sort(),
    );
  });
});
