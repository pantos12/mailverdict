/**
 * Shared contracts for MailVerdict.
 *
 * Pipeline:  raw email -> ParsedEmail -> Jev signals -> Verdict (+ optional Explanation)
 * Jev (TypeSafe System One) is the judge. The LLM only writes prose in the review band.
 */

export type AuthResult = "pass" | "fail" | "softfail" | "neutral" | "none" | "unknown";

export interface ExtractedUrl {
  href: string;
  /** registrable domain, e.g. "paypa1-secure.com" */
  domain: string | null;
  /** visible anchor text if the URL came from an <a> tag */
  anchorText?: string;
  /** anchor text looks like a URL/domain but points somewhere else */
  textMismatch: boolean;
}

export interface AttachmentInfo {
  filename: string;
  contentType: string;
  size: number;
}

export interface ParsedEmail {
  messageId?: string;
  date?: string;
  subject: string;
  from: { name?: string; address?: string };
  replyTo?: { name?: string; address?: string };
  returnPath?: string;
  to: string[];
  /** SPF / DKIM / DMARC as parsed from Authentication-Results headers */
  auth: { spf: AuthResult; dkim: AuthResult; dmarc: AuthResult };
  /** plain-text body (HTML converted/stripped). Truncated to fit Jev state budget. */
  text: string;
  hasHtml: boolean;
  urls: ExtractedUrl[];
  attachments: AttachmentInfo[];
  /** derived signals computed deterministically in code */
  signals: {
    fromDomain: string | null;
    replyToDomain: string | null;
    replyToMismatch: boolean;
    returnPathMismatch: boolean;
    displayNameLooksLikeEmail: boolean;
    distinctUrlDomains: string[];
    hasDangerousAttachment: boolean;
  };
}

/** Independent questions asked of Jev in a single call. Keys are stable API. */
export interface JevSignals {
  is_phishing: number;             // noul 0..1
  requests_credentials: number;    // noul
  requests_payment: number;        // noul  (wire, gift card, invoice change)
  impersonates_brand_or_person: number; // noul
  urgency_pressure: number;        // score 0..2  (0 calm, 1 some pressure, 2 extreme)
  attack_type: AttackType;         // choice
  attack_type_confidence: number;  // 0..1
}

export type AttackType =
  | "none"
  | "credential_harvest"
  | "payment_fraud"
  | "malware_delivery"
  | "executive_impersonation"
  | "scam_other";

export type VerdictLabel = "PHISHING" | "SUSPICIOUS" | "LEGITIMATE";

export interface Indicator {
  /** short machine key e.g. "reply_to_mismatch" */
  key: string;
  /** human-readable one-liner */
  label: string;
  /** 0..1 how strongly this indicator points to phishing */
  weight: number;
  source: "header" | "url" | "attachment" | "jev";
}

export interface Verdict {
  label: VerdictLabel;
  /** calibrated probability of phishing, from Jev (0..1) */
  probability: number;
  /** sorted, strongest first */
  indicators: Indicator[];
  attackType: AttackType;
  signals: JevSignals;
  /** true when the LLM explainer was invoked (review band only) */
  explained: boolean;
  explanation?: string;
  model: { jev: string; explainer?: string };
  usage: { jevInputTokens: number; explainerTokens?: number };
  /** ms wall-clock for the whole pipeline */
  latencyMs: number;
}

export interface VerdictPolicy {
  /** >= high => PHISHING */
  highThreshold: number;
  /** <= low => LEGITIMATE */
  lowThreshold: number;
  /** call the LLM explainer for the SUSPICIOUS band */
  explainSuspicious: boolean;
  /** also explain PHISHING verdicts (costs an LLM call) */
  explainPhishing: boolean;
}

export const DEFAULT_POLICY: VerdictPolicy = {
  highThreshold: 0.9,
  lowThreshold: 0.1,
  explainSuspicious: true,
  explainPhishing: false,
};

/** Input accepted by the public API / MCP tool. Exactly one of raw or fields. */
export interface AnalyzeRequest {
  /** full RFC 822 source (.eml) — preferred; gives us headers */
  raw?: string;
  /** fallback when only the visible parts are available (e.g. Power Automate body) */
  fields?: {
    subject?: string;
    from?: string;
    replyTo?: string;
    to?: string;
    body?: string;
    html?: string;
    headers?: Record<string, string>;
  };
  policy?: Partial<VerdictPolicy>;
}
