/**
 * Jev (TypeSafe System One) state and questions.
 *
 * The state is a compact JSON object built from ParsedEmail; the questions are
 * independent and keyed exactly like JevSignals in src/types.ts.
 */
import { choice, noul, score } from "@typesafe-ai/sdk";
import type { AttackType, ParsedEmail } from "../types.js";

/** Jev's state budget is ~32k tokens; ~12k chars of body leaves ample room for metadata. */
export const BODY_CHAR_LIMIT = 12_000;
export const MAX_URLS_IN_STATE = 40;
export const MAX_ATTACHMENTS_IN_STATE = 20;

export type JevState = {
  headers: {
    subject: string;
    from: { name: string | null; address: string | null; domain: string | null };
    reply_to: { name: string | null; address: string | null; domain: string | null } | null;
    return_path: string | null;
    to: string[];
    date: string | null;
  };
  authentication: ParsedEmail["auth"];
  signals: {
    reply_to_mismatch: boolean;
    return_path_mismatch: boolean;
    display_name_looks_like_email: boolean;
    distinct_url_domains: string[];
    has_dangerous_attachment: boolean;
    has_html: boolean;
  };
  urls: Array<{ href: string; domain: string | null; anchor_text: string | null; anchor_text_mismatch: boolean }>;
  attachments: Array<{ filename: string; content_type: string; size: number }>;
  body: { text: string; truncated: boolean; original_chars: number };
};

export function buildState(email: ParsedEmail): JevState {
  const truncated = email.text.length > BODY_CHAR_LIMIT;
  return {
    headers: {
      subject: email.subject,
      from: { name: email.from.name ?? null, address: email.from.address ?? null, domain: email.signals.fromDomain },
      reply_to: email.replyTo
        ? { name: email.replyTo.name ?? null, address: email.replyTo.address ?? null, domain: email.signals.replyToDomain }
        : null,
      return_path: email.returnPath ?? null,
      to: email.to.slice(0, 20),
      date: email.date ?? null,
    },
    authentication: email.auth,
    signals: {
      reply_to_mismatch: email.signals.replyToMismatch,
      return_path_mismatch: email.signals.returnPathMismatch,
      display_name_looks_like_email: email.signals.displayNameLooksLikeEmail,
      distinct_url_domains: email.signals.distinctUrlDomains,
      has_dangerous_attachment: email.signals.hasDangerousAttachment,
      has_html: email.hasHtml,
    },
    urls: email.urls.slice(0, MAX_URLS_IN_STATE).map((u) => ({
      href: u.href.slice(0, 300),
      domain: u.domain,
      anchor_text: u.anchorText ? u.anchorText.slice(0, 120) : null,
      anchor_text_mismatch: u.textMismatch,
    })),
    attachments: email.attachments.slice(0, MAX_ATTACHMENTS_IN_STATE).map((a) => ({
      filename: a.filename,
      content_type: a.contentType,
      size: a.size,
    })),
    body: {
      text: truncated ? `${email.text.slice(0, BODY_CHAR_LIMIT)}\n[... truncated ...]` : email.text,
      truncated,
      original_chars: email.text.length,
    },
  };
}

const EVIDENCE_GUIDANCE =
  "Weigh technical evidence heavily: SPF/DKIM/DMARC failures, a Reply-To or Return-Path whose registrable " +
  "domain differs from the From domain, lookalike or misspelled brand domains, display names that contain a " +
  "different email address or domain, link anchor text that shows one domain while the href points to another, " +
  "and dangerous attachment types. Marketing and transactional mail from the genuine sender with passing " +
  "authentication and consistent domains is legitimate even if it contains links or asks the user to log in on " +
  "the sender's own domain.";

const ATTACK_TYPE_CRITERIA: Record<AttackType, string> = {
  none: "Not an attack. Ordinary personal, business, transactional, or marketing email.",
  credential_harvest:
    "Tries to get the recipient to enter a password, MFA code, or account details, typically via a link to a fake login page.",
  payment_fraud:
    "Tries to obtain money: wire transfer, changed bank details on an invoice, gift cards, fake refunds, or fake overdue payments.",
  malware_delivery:
    "Tries to get the recipient to open a dangerous attachment or download and run a file or enable macros.",
  executive_impersonation:
    "Pretends to be an executive, manager, colleague, or vendor to get the recipient to act (BEC), often with urgency and secrecy, without a link.",
  scam_other:
    "Other deception: lottery, romance, advance-fee, extortion, fake job offers, tech support scams, or unclear malicious intent.",
};

export function buildQuestions() {
  return {
    is_phishing: noul(
      `Is this email a phishing or social-engineering attack against the recipient? ${EVIDENCE_GUIDANCE}`,
      {
        true:
          "Phishing: the sender attempts to deceive the recipient into revealing credentials, paying money, " +
          "changing payment details, or installing malware by impersonating a brand, colleague, or institution, " +
          "or by other social engineering such as fabricated urgency, threats, or too-good-to-be-true offers.",
        false:
          "Legitimate: expected business, personal, transactional (receipts, shipping, password resets the user " +
          "requested), or marketing mail from the real sender, with header authentication and domains consistent " +
          "with the claimed identity, and no deceptive request.",
      },
    ),
    requests_credentials: noul(
      "Does the email ask the recipient to enter, confirm, verify, or reset a password, login, MFA code, or account details, or to sign in via a provided link?",
      {
        true: "Yes: the email steers the recipient toward entering credentials or account details.",
        false: "No: no request to sign in, verify, or supply credentials.",
      },
    ),
    requests_payment: noul(
      "Does the email ask the recipient to pay, transfer money, buy gift cards, update bank or invoice payment details, or approve a financial transaction?",
      {
        true: "Yes: a payment, transfer, gift card purchase, or change of payment details is requested.",
        false: "No: no financial action is requested.",
      },
    ),
    impersonates_brand_or_person: noul(
      `Does the sender pretend to be a well-known brand, institution, or a specific person (executive, colleague, vendor) that they are not? ${EVIDENCE_GUIDANCE}`,
      {
        true:
          "Yes: the claimed identity (display name, brand, logo, signature) does not match the sending domain, " +
          "authentication results, or link destinations, or a lookalike domain is used.",
        false: "No: the sender is who they claim to be, or no identity is claimed.",
      },
    ),
    urgency_pressure: score(
      "How much urgency, fear, or pressure does the email apply to make the recipient act quickly?",
      [
        "Calm: no deadline or threat; the recipient can act whenever convenient.",
        "Some pressure: a deadline, reminder, or mild consequence is mentioned.",
        "Extreme pressure: immediate action demanded, threats of account closure, legal action, loss of money, or secrecy is required.",
      ],
    ),
    attack_type: choice(
      "If this email is an attack, which category best describes it? Choose 'none' for legitimate email.",
      ATTACK_TYPE_CRITERIA,
    ),
  };
}

export type JevQuestions = ReturnType<typeof buildQuestions>;
