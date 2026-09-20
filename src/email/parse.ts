/**
 * Email parsing: raw RFC 822 (.eml) or loose fields -> ParsedEmail.
 *
 * Everything here is deterministic. No network, no model calls.
 */
import { simpleParser, type AddressObject, type HeaderValue, type ParsedMail } from "mailparser";
import { getDomain, parse as parseHost } from "tldts";
import type {
  AnalyzeRequest,
  AttachmentInfo,
  AuthResult,
  ExtractedUrl,
  ParsedEmail,
} from "../types.js";

type Fields = NonNullable<AnalyzeRequest["fields"]>;
interface Address {
  name?: string;
  address?: string;
}
interface AuthHeaders {
  authenticationResults: string[];
  arcAuthenticationResults: string[];
  receivedSpf: string[];
}
interface Assembly {
  messageId?: string;
  date?: string;
  subject: string;
  from: Address;
  replyTo?: Address;
  returnPath?: string;
  to: string[];
  authHeaders: AuthHeaders;
  text?: string;
  html?: string;
  attachments: AttachmentInfo[];
}

const KNOWN_AUTH_VALUES: ReadonlySet<string> = new Set(["pass", "fail", "softfail", "neutral", "none"]);
const DANGEROUS_EXTENSIONS: ReadonlySet<string> = new Set([
  "exe", "scr", "js", "vbs", "hta", "iso", "img", "lnk", "bat", "cmd", "docm", "xlsm", "html", "htm", "one",
]);
const ANCHOR_RE = /<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi;
const BARE_URL_RE = /https?:\/\/[^\s<>"'`)\]]+/gi;
const LOOKS_LIKE_URL_RE = /^(?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:[/?#]\S*)?$/i;
const DOMAIN_TOKEN_RE = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi;

export async function parseEmail(req: AnalyzeRequest): Promise<ParsedEmail> {
  if (typeof req.raw === "string") return parseRaw(req.raw);
  if (req.fields) return parseFields(req.fields);
  throw new Error("AnalyzeRequest must contain either `raw` or `fields`");
}

async function parseRaw(raw: string): Promise<ParsedEmail> {
  const mail: ParsedMail = await simpleParser(raw, { skipTextToHtml: true, skipImageLinks: true });
  const header = (name: string): string[] => headerStrings(mail.headers.get(name));
  const html = typeof mail.html === "string" ? mail.html : undefined;
  return assemble({
    messageId: mail.messageId,
    date: mail.date instanceof Date && !Number.isNaN(mail.date.getTime()) ? mail.date.toISOString() : undefined,
    subject: mail.subject ?? "",
    from: firstAddress(mail.from) ?? {},
    replyTo: firstAddress(mail.replyTo),
    returnPath: extractReturnPath(mail.headers.get("return-path")),
    to: addressList(mail.to),
    authHeaders: {
      authenticationResults: header("authentication-results"),
      arcAuthenticationResults: header("arc-authentication-results"),
      receivedSpf: header("received-spf"),
    },
    text: mail.text,
    html,
    attachments: mail.attachments.map((a) => ({
      filename: a.filename ?? "(unnamed)",
      contentType: a.contentType,
      size: a.size,
    })),
  });
}

function parseFields(fields: Fields): ParsedEmail {
  const headers = lowercaseKeys(fields.headers ?? {});
  const header = (name: string): string[] => {
    const v = headers[name];
    return v ? [v] : [];
  };
  return assemble({
    messageId: headers["message-id"],
    date: headers["date"],
    subject: fields.subject ?? "",
    from: parseAddressString(fields.from) ?? {},
    replyTo: parseAddressString(fields.replyTo),
    returnPath: headers["return-path"] ? stripAngles(headers["return-path"]) : undefined,
    to: (fields.to ?? "")
      .split(",")
      .map((s) => parseAddressString(s)?.address)
      .filter((s): s is string => Boolean(s)),
    authHeaders: {
      authenticationResults: header("authentication-results"),
      arcAuthenticationResults: header("arc-authentication-results"),
      receivedSpf: header("received-spf"),
    },
    text: fields.body,
    html: fields.html,
    attachments: [],
  });
}

function assemble(a: Assembly): ParsedEmail {
  const text = a.text && a.text.trim().length > 0 ? a.text : a.html ? htmlToText(a.html) : "";
  const urls = extractUrls(a.html, text);
  const fromDomain = domainOfAddress(a.from.address);
  const replyToDomain = domainOfAddress(a.replyTo?.address);
  const returnPathDomain = domainOfAddress(a.returnPath);
  return {
    messageId: a.messageId,
    date: a.date,
    subject: a.subject,
    from: a.from,
    replyTo: a.replyTo,
    returnPath: a.returnPath,
    to: a.to,
    auth: parseAuth(a.authHeaders),
    text,
    hasHtml: Boolean(a.html),
    urls,
    attachments: a.attachments,
    signals: {
      fromDomain,
      replyToDomain,
      replyToMismatch: Boolean(fromDomain && replyToDomain && fromDomain !== replyToDomain),
      returnPathMismatch: Boolean(fromDomain && returnPathDomain && fromDomain !== returnPathDomain),
      displayNameLooksLikeEmail: displayNameLooksLikeEmail(a.from, fromDomain),
      distinctUrlDomains: [...new Set(urls.map((u) => u.domain).filter((d): d is string => d !== null))],
      hasDangerousAttachment: a.attachments.some((att) => isDangerousFilename(att.filename)),
    },
  };
}

// ---------------------------------------------------------------- headers

function headerStrings(value: HeaderValue | undefined): string[] {
  if (value === undefined) return [];
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) {
    return value.map((v) => (typeof v === "string" ? v : v.value)).filter((s) => s.length > 0);
  }
  if (value instanceof Date) return [value.toISOString()];
  if ("value" in value && typeof value.value === "string") return [value.value];
  return [];
}

function firstAddress(obj: AddressObject | AddressObject[] | undefined): Address | undefined {
  const first = Array.isArray(obj) ? obj[0] : obj;
  const entry = first?.value[0];
  if (!entry) return undefined;
  return { name: entry.name || undefined, address: entry.address?.toLowerCase() };
}

function addressList(obj: AddressObject | AddressObject[] | undefined): string[] {
  const list = Array.isArray(obj) ? obj : obj ? [obj] : [];
  return list.flatMap((o) => o.value.map((v) => v.address?.toLowerCase())).filter((s): s is string => Boolean(s));
}

function extractReturnPath(value: HeaderValue | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value === "string") return stripAngles(value) || undefined;
  if (!Array.isArray(value) && !(value instanceof Date) && "value" in value && Array.isArray(value.value)) {
    return value.value[0]?.address?.toLowerCase();
  }
  const [first] = headerStrings(value);
  return first ? stripAngles(first) || undefined : undefined;
}

function stripAngles(s: string): string {
  return s.trim().replace(/^<|>$/g, "").toLowerCase();
}

function lowercaseKeys(rec: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(rec)) out[k.toLowerCase()] = v;
  return out;
}

export function parseAddressString(input: string | undefined): Address | undefined {
  if (!input || input.trim().length === 0) return undefined;
  const m = /^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$/.exec(input);
  if (m) {
    const name = m[1]?.trim();
    return { name: name || undefined, address: m[2]?.trim().toLowerCase() };
  }
  const trimmed = input.trim();
  return trimmed.includes("@") ? { address: trimmed.toLowerCase() } : { name: trimmed };
}

// ---------------------------------------------------------------- auth

function normalizeAuth(raw: string): AuthResult {
  const v = raw.toLowerCase();
  return KNOWN_AUTH_VALUES.has(v) ? (v as AuthResult) : "unknown";
}

export function parseAuth(h: AuthHeaders): ParsedEmail["auth"] {
  const result: ParsedEmail["auth"] = { spf: "unknown", dkim: "unknown", dmarc: "unknown" };
  for (const line of [...h.authenticationResults, ...h.arcAuthenticationResults]) {
    for (const m of line.matchAll(/\b(spf|dkim|dmarc)\s*=\s*([a-z]+)/gi)) {
      const mech = (m[1] ?? "").toLowerCase() as keyof ParsedEmail["auth"];
      if (result[mech] === "unknown") result[mech] = normalizeAuth(m[2] ?? "");
    }
  }
  if (result.spf === "unknown") {
    for (const line of h.receivedSpf) {
      const first = line.trim().split(/[\s;(]/)[0];
      if (first) {
        result.spf = normalizeAuth(first);
        break;
      }
    }
  }
  return result;
}

// ---------------------------------------------------------------- urls & html

export function extractUrls(html: string | undefined, text: string): ExtractedUrl[] {
  const seen = new Set<string>();
  const out: ExtractedUrl[] = [];
  const push = (href: string, anchorText?: string): void => {
    const cleaned = cleanUrl(href);
    if (!cleaned || seen.has(cleaned)) return;
    seen.add(cleaned);
    const domain = getDomain(cleaned);
    const entry: ExtractedUrl = { href: cleaned, domain, textMismatch: anchorMismatch(anchorText, domain) };
    if (anchorText !== undefined && anchorText.length > 0) entry.anchorText = anchorText;
    out.push(entry);
  };
  if (html) {
    for (const m of html.matchAll(ANCHOR_RE)) {
      const href = decodeEntities(m[1] ?? m[2] ?? m[3] ?? "");
      push(href, htmlToText(m[4] ?? "").trim());
    }
    for (const m of htmlToText(html).matchAll(BARE_URL_RE)) push(m[0]);
  }
  for (const m of text.matchAll(BARE_URL_RE)) push(m[0]);
  return out;
}

function cleanUrl(href: string): string | null {
  const trimmed = href.trim().replace(/[.,;:!?)\]]+$/, "");
  return /^https?:\/\//i.test(trimmed) ? trimmed : null;
}

function anchorMismatch(anchorText: string | undefined, hrefDomain: string | null): boolean {
  if (!anchorText || !hrefDomain) return false;
  const token = anchorText.trim();
  if (!LOOKS_LIKE_URL_RE.test(token)) return false;
  const textDomain = getDomain(/^https?:\/\//i.test(token) ? token : `http://${token}`);
  return textDomain !== null && textDomain !== hrefDomain;
}

export function htmlToText(html: string): string {
  const withBreaks = html
    .replace(/<(script|style|head)\b[\s\S]*?<\/\1>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|li|tr|h[1-6]|blockquote|table|section)>/gi, "\n")
    .replace(/<[^>]+>/g, " ");
  return decodeEntities(withBreaks)
    .split("\n")
    .map((line) => line.replace(/[ \t\r\f\v ]+/g, " ").trim())
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function decodeEntities(s: string): string {
  const named: Record<string, string> = {
    amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", "#39": "'",
  };
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+|#39);/gi, (whole, ent: string) => {
    const key = ent.toLowerCase();
    if (key in named) return named[key] ?? whole;
    if (key.startsWith("#x")) return safeFromCodePoint(parseInt(key.slice(2), 16), whole);
    if (key.startsWith("#")) return safeFromCodePoint(parseInt(key.slice(1), 10), whole);
    return whole;
  });
}

function safeFromCodePoint(cp: number, fallback: string): string {
  return Number.isFinite(cp) && cp >= 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : fallback;
}

// ---------------------------------------------------------------- signals

export function domainOfAddress(address: string | undefined): string | null {
  if (!address) return null;
  const at = address.lastIndexOf("@");
  if (at < 0) return null;
  const host = address.slice(at + 1).trim().toLowerCase();
  return host ? getDomain(host) : null;
}

function displayNameLooksLikeEmail(from: Address, fromDomain: string | null): boolean {
  const name = from.name?.trim();
  if (!name) return false;
  if (name.includes("@")) return name.toLowerCase() !== (from.address ?? "").toLowerCase();
  for (const m of name.matchAll(DOMAIN_TOKEN_RE)) {
    const parsed = parseHost(m[0]);
    if (parsed.isIcann && parsed.domain && parsed.domain !== fromDomain) return true;
  }
  return false;
}

export function isDangerousFilename(filename: string): boolean {
  const parts = filename.trim().toLowerCase().split(".");
  if (parts.length < 2) return false;
  const ext = parts[parts.length - 1] ?? "";
  if (DANGEROUS_EXTENSIONS.has(ext)) return true;
  if (ext === "zip") return parts.slice(0, -1).some((p) => DANGEROUS_EXTENSIONS.has(p));
  return false;
}
