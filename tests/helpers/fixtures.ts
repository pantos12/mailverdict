import type { JevSignals, ParsedEmail } from "../../src/types.js";

type EmailOverrides = Partial<Omit<ParsedEmail, "signals">> & { signals?: Partial<ParsedEmail["signals"]> };

export function makeEmail(overrides: EmailOverrides = {}): ParsedEmail {
  const base: ParsedEmail = {
    messageId: "<m1@x.example>",
    date: "2025-09-01T10:00:00.000Z",
    subject: "Hello",
    from: { name: "Alice", address: "alice@x.example" },
    to: ["bob@y.example"],
    auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
    text: "Just checking in.",
    hasHtml: false,
    urls: [],
    attachments: [],
    signals: {
      fromDomain: "x.example",
      replyToDomain: null,
      replyToMismatch: false,
      returnPathMismatch: false,
      displayNameLooksLikeEmail: false,
      distinctUrlDomains: [],
      hasDangerousAttachment: false,
    },
  };
  return { ...base, ...overrides, signals: { ...base.signals, ...(overrides.signals ?? {}) } };
}

export function makeSignals(overrides: Partial<JevSignals> = {}): JevSignals {
  return {
    is_phishing: 0.05,
    requests_credentials: 0.1,
    requests_payment: 0.1,
    impersonates_brand_or_person: 0.1,
    urgency_pressure: 0.2,
    attack_type: "none",
    attack_type_confidence: 0.9,
    ...overrides,
  };
}
