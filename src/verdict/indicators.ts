/**
 * Deterministic, human-readable indicators derived from the parsed email and Jev's signals.
 * Sorted strongest first. Weights are heuristics for display ordering, not the verdict.
 */
import { getDomainWithoutSuffix } from "tldts";
import type { Indicator, JevSignals, ParsedEmail } from "../types.js";

export const MANY_DOMAINS_THRESHOLD = 4;
export const JEV_NOUL_THRESHOLD = 0.6;
export const JEV_URGENCY_THRESHOLD = 1.5;

/** Brands commonly impersonated; compared against a homoglyph-normalized domain label. */
export const COMMON_BRANDS: readonly string[] = [
  "paypal", "microsoft", "office365", "outlook", "onedrive", "sharepoint", "apple", "icloud", "amazon", "google",
  "gmail", "netflix", "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc", "barclays", "dhl", "fedex", "ups",
  "usps", "docusign", "dropbox", "adobe", "linkedin", "facebook", "instagram", "whatsapp", "irs", "hmrc", "coinbase",
  "binance", "meta", "zoom", "okta", "salesforce", "americanexpress", "capitalone", "venmo", "zelle",
];

const HOMOGLYPHS: Record<string, string> = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g" };
const IPV4_HOST_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

export function deriveIndicators(email: ParsedEmail, signals: JevSignals): Indicator[] {
  const out: Indicator[] = [...headerIndicators(email), ...urlIndicators(email), ...attachmentIndicators(email), ...jevIndicators(signals)];
  return out.sort((a, b) => b.weight - a.weight || a.key.localeCompare(b.key));
}

function headerIndicators(email: ParsedEmail): Indicator[] {
  const out: Indicator[] = [];
  const { auth, signals: s } = email;
  const add = (key: string, label: string, weight: number): void => {
    out.push({ key, label, weight, source: "header" });
  };
  if (auth.spf === "fail") add("spf_fail", "SPF check failed: the sending server is not authorized for the From domain", 0.35);
  if (auth.spf === "softfail") add("spf_softfail", "SPF soft-failed: the sending server is probably not authorized for the From domain", 0.15);
  if (auth.dkim === "fail") add("dkim_fail", "DKIM signature failed: the message was altered or forged", 0.3);
  if (auth.dmarc === "fail") add("dmarc_fail", "DMARC failed: the From domain's policy rejects this message", 0.5);
  if (s.replyToMismatch) {
    add("reply_to_mismatch", `Replies go to a different domain (${s.replyToDomain}) than the sender (${s.fromDomain})`, 0.5);
  }
  if (s.returnPathMismatch) {
    add("return_path_mismatch", `Bounce address (Return-Path) domain differs from the sender domain ${s.fromDomain}`, 0.3);
  }
  if (s.displayNameLooksLikeEmail) {
    add("display_name_spoof", `Display name "${email.from.name ?? ""}" contains an address or domain that differs from the real sender`, 0.5);
  }
  return out;
}

function urlIndicators(email: ParsedEmail): Indicator[] {
  const out: Indicator[] = [];
  const add = (key: string, label: string, weight: number): void => {
    if (!out.some((i) => i.key === key)) out.push({ key, label, weight, source: "url" });
  };
  for (const u of email.urls) {
    if (u.textMismatch) {
      add("anchor_text_mismatch", `Link text "${truncate(u.anchorText ?? "", 60)}" points to a different site (${u.domain ?? u.href})`, 0.6);
    }
    const host = hostnameOf(u.href);
    if (host && (IPV4_HOST_RE.test(host) || host.startsWith("["))) {
      add("ip_literal_url", `A link uses a raw IP address instead of a domain name (${host})`, 0.5);
    }
    if (host && host.split(".").some((label) => label.startsWith("xn--"))) {
      add("punycode_domain", `A link uses an internationalized (punycode) domain that can disguise lookalike characters (${host})`, 0.45);
    }
    const brand = u.domain ? lookalikeBrand(u.domain) : null;
    if (brand) add("lookalike_domain", `Link domain ${u.domain} imitates ${brand} with substituted characters`, 0.7);
  }
  const fromBrand = email.signals.fromDomain ? lookalikeBrand(email.signals.fromDomain) : null;
  if (fromBrand) add("lookalike_domain", `Sender domain ${email.signals.fromDomain} imitates ${fromBrand} with substituted characters`, 0.7);
  const n = email.signals.distinctUrlDomains.length;
  if (n >= MANY_DOMAINS_THRESHOLD) add("many_distinct_domains", `Links point to ${n} different domains`, 0.25);
  return out;
}

function attachmentIndicators(email: ParsedEmail): Indicator[] {
  if (!email.signals.hasDangerousAttachment) return [];
  const names = email.attachments.map((a) => a.filename).join(", ");
  return [{ key: "dangerous_attachment", label: `Attachment type can run code or hide malware (${truncate(names, 80)})`, weight: 0.7, source: "attachment" }];
}

function jevIndicators(s: JevSignals): Indicator[] {
  const out: Indicator[] = [];
  const add = (key: string, label: string, weight: number): void => {
    out.push({ key, label, weight, source: "jev" });
  };
  if (s.requests_credentials > JEV_NOUL_THRESHOLD) add("requests_credentials", "Asks you to sign in, verify, or provide account credentials", 0.6);
  if (s.requests_payment > JEV_NOUL_THRESHOLD) add("requests_payment", "Asks for a payment, transfer, gift cards, or a change to payment details", 0.55);
  if (s.impersonates_brand_or_person > JEV_NOUL_THRESHOLD) add("impersonation", "Appears to impersonate a brand, institution, or person", 0.6);
  if (s.urgency_pressure >= JEV_URGENCY_THRESHOLD) add("urgency_pressure", "Uses strong urgency or threats to rush you into acting", 0.4);
  return out;
}

/** Returns the brand a domain label imitates via digit/homoglyph substitution, or null. */
export function lookalikeBrand(domain: string): string | null {
  const label = (getDomainWithoutSuffix(domain) ?? domain.split(".")[0] ?? "").toLowerCase();
  if (!label) return null;
  const normalized = label
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/[0-9]/g, (d) => HOMOGLYPHS[d] ?? d);
  if (normalized === label) return null;
  for (const brand of COMMON_BRANDS) {
    if (normalized.includes(brand) && !label.includes(brand)) return brand;
  }
  return null;
}

function hostnameOf(href: string): string | null {
  try {
    return new URL(href).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}
