import { describe, expect, it } from "vitest";
import { deriveIndicators, lookalikeBrand } from "../../src/verdict/indicators.js";
import { makeEmail, makeSignals } from "../helpers/fixtures.js";

const keys = (list: { key: string }[]): string[] => list.map((i) => i.key);

describe("deriveIndicators", () => {
  it("returns no indicators for a clean email with calm signals", () => {
    expect(deriveIndicators(makeEmail(), makeSignals())).toEqual([]);
  });

  it("emits header indicators for auth failures and mismatches", () => {
    const email = makeEmail({
      from: { name: "IT Desk it@corp.example", address: "x@gmail.com" },
      auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
      signals: { fromDomain: "gmail.com", replyToDomain: "evil.example", replyToMismatch: true, returnPathMismatch: true, displayNameLooksLikeEmail: true },
    });
    const list = deriveIndicators(email, makeSignals());
    expect(keys(list)).toEqual(expect.arrayContaining(["spf_fail", "dkim_fail", "dmarc_fail", "reply_to_mismatch", "return_path_mismatch", "display_name_spoof"]));
    expect(list.every((i) => i.source === "header")).toBe(true);
    const replyTo = list.find((i) => i.key === "reply_to_mismatch");
    expect(replyTo?.label).toContain("evil.example");
    expect(replyTo?.label).toContain("gmail.com");
  });

  it("emits softfail as a weaker header indicator", () => {
    const list = deriveIndicators(makeEmail({ auth: { spf: "softfail", dkim: "pass", dmarc: "pass" } }), makeSignals());
    expect(keys(list)).toEqual(["spf_softfail"]);
    expect(list[0]?.weight).toBeLessThan(0.35);
  });

  it("emits url indicators: anchor mismatch, ip literal, punycode, lookalike, many domains", () => {
    const email = makeEmail({
      urls: [
        { href: "https://evil.example/login", domain: "evil.example", anchorText: "www.paypal.com", textMismatch: true },
        { href: "http://203.0.113.5/x", domain: null, textMismatch: false },
        { href: "https://xn--pple-43d.com/", domain: "xn--pple-43d.com", textMismatch: false },
        { href: "https://micr0soft-login.net/", domain: "micr0soft-login.net", textMismatch: false },
        { href: "https://a.example/", domain: "a.example", textMismatch: false },
      ],
      signals: { distinctUrlDomains: ["evil.example", "xn--pple-43d.com", "micr0soft-login.net", "a.example"] },
    });
    const list = deriveIndicators(email, makeSignals());
    expect(keys(list)).toEqual(expect.arrayContaining(["anchor_text_mismatch", "ip_literal_url", "punycode_domain", "lookalike_domain", "many_distinct_domains"]));
    expect(list.filter((i) => i.key === "lookalike_domain")).toHaveLength(1);
    expect(list.find((i) => i.key === "lookalike_domain")?.label).toMatch(/microsoft/);
    expect(list.every((i) => i.source === "url")).toBe(true);
  });

  it("flags a lookalike sender domain", () => {
    const list = deriveIndicators(makeEmail({ signals: { fromDomain: "paypa1.com" } }), makeSignals());
    expect(keys(list)).toEqual(["lookalike_domain"]);
    expect(list[0]?.label).toMatch(/paypa1\.com.*paypal/);
  });

  it("emits the attachment indicator", () => {
    const email = makeEmail({
      attachments: [{ filename: "pay.exe", contentType: "application/octet-stream", size: 1 }],
      signals: { hasDangerousAttachment: true },
    });
    const list = deriveIndicators(email, makeSignals());
    expect(list).toEqual([expect.objectContaining({ key: "dangerous_attachment", source: "attachment" })]);
    expect(list[0]?.label).toContain("pay.exe");
  });

  it("emits jev indicators only above thresholds", () => {
    const below = deriveIndicators(makeEmail(), makeSignals({ requests_credentials: 0.6, requests_payment: 0.6, impersonates_brand_or_person: 0.6, urgency_pressure: 1.49 }));
    expect(below).toEqual([]);
    const above = deriveIndicators(makeEmail(), makeSignals({ requests_credentials: 0.61, requests_payment: 0.7, impersonates_brand_or_person: 0.9, urgency_pressure: 1.5 }));
    expect(keys(above).sort()).toEqual(["impersonation", "requests_credentials", "requests_payment", "urgency_pressure"]);
    expect(above.every((i) => i.source === "jev")).toBe(true);
  });

  it("sorts by weight descending and keeps weights within 0..1", () => {
    const email = makeEmail({
      auth: { spf: "fail", dkim: "pass", dmarc: "pass" },
      signals: { hasDangerousAttachment: true, returnPathMismatch: true },
    });
    const list = deriveIndicators(email, makeSignals({ urgency_pressure: 2 }));
    const weights = list.map((i) => i.weight);
    expect(weights).toEqual([...weights].sort((a, b) => b - a));
    expect(weights.every((w) => w > 0 && w <= 1)).toBe(true);
    expect(list[0]?.key).toBe("dangerous_attachment");
  });
});

describe("lookalikeBrand", () => {
  it.each([
    ["paypa1.com", "paypal"],
    ["micr0soft.com", "microsoft"],
    ["arnazon-deals.net", "amazon"],
    ["app1e-id.com", "apple"],
  ])("%s imitates %s", (domain, brand) => {
    expect(lookalikeBrand(domain)).toBe(brand);
  });

  it.each(["paypal.com", "microsoft.com", "example.com", "web3-news.org", "shop24.de"])("%s is not a lookalike", (domain) => {
    expect(lookalikeBrand(domain)).toBeNull();
  });
});
