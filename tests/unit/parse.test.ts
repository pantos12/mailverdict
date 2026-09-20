import { describe, expect, it } from "vitest";
import { isDangerousFilename, parseEmail } from "../../src/email/parse.js";

const CRLF = "\r\n";
const eml = (headers: string[], body: string): string => headers.join(CRLF) + CRLF + CRLF + body;

const AUTH_FAIL_EML = eml(
  [
    "Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=bounce.evil.net; dkim=none (message not signed); dmarc=fail (p=REJECT) header.from=paypal.com",
    "Return-Path: <bounce@evil.net>",
    "From: PayPal Support <service@paypal.com>",
    "Reply-To: PayPal Help <help@paypal-verify-center.com>",
    "To: victim@corp.example",
    "Subject: Your account is limited",
    "Date: Mon, 01 Sep 2025 10:00:00 +0000",
    "Message-ID: <abc123@evil.net>",
    "Content-Type: text/plain; charset=utf-8",
  ],
  "Please verify your account at https://paypa1-secure.com/login within 24 hours.",
);

const ANCHOR_MISMATCH_EML = eml(
  [
    "Authentication-Results: mx.example.com; spf=pass; dkim=pass header.d=newsletter.example; dmarc=pass",
    "From: Newsletter <news@newsletter.example>",
    "To: victim@corp.example",
    "Subject: Sign in",
    "Content-Type: text/html; charset=utf-8",
  ],
  '<html><body><p>Hello,<br>Sign in at <a href="https://login.evil-host.net/x?y=1">https://www.microsoft.com/login</a> ' +
    'or read <a href="https://www.microsoft.com/news">our news</a>.</p><script>alert(1)</script></body></html>',
);

const ATTACHMENT_EML = [
  'Content-Type: multipart/mixed; boundary="b1"',
  "From: Accounts <ap@vendor.example>",
  "To: victim@corp.example",
  "Subject: Invoice",
  "",
  "--b1",
  "Content-Type: text/plain",
  "",
  "See attached.",
  "--b1",
  'Content-Type: application/octet-stream; name="invoice.pdf.exe"',
  'Content-Disposition: attachment; filename="invoice.pdf.exe"',
  "Content-Transfer-Encoding: base64",
  "",
  "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "--b1--",
].join(CRLF);

describe("parseEmail (raw)", () => {
  it("parses Authentication-Results into spf/dkim/dmarc and detects header mismatches", async () => {
    const email = await parseEmail({ raw: AUTH_FAIL_EML });
    expect(email.auth).toEqual({ spf: "fail", dkim: "none", dmarc: "fail" });
    expect(email.from).toEqual({ name: "PayPal Support", address: "service@paypal.com" });
    expect(email.replyTo?.address).toBe("help@paypal-verify-center.com");
    expect(email.returnPath).toBe("bounce@evil.net");
    expect(email.to).toEqual(["victim@corp.example"]);
    expect(email.subject).toBe("Your account is limited");
    expect(email.messageId).toBe("<abc123@evil.net>");
    expect(email.date).toBe("2025-09-01T10:00:00.000Z");
    expect(email.signals.fromDomain).toBe("paypal.com");
    expect(email.signals.replyToDomain).toBe("paypal-verify-center.com");
    expect(email.signals.replyToMismatch).toBe(true);
    expect(email.signals.returnPathMismatch).toBe(true);
    expect(email.signals.displayNameLooksLikeEmail).toBe(false);
    expect(email.hasHtml).toBe(false);
    expect(email.urls).toEqual([
      { href: "https://paypa1-secure.com/login", domain: "paypa1-secure.com", textMismatch: false },
    ]);
    expect(email.signals.distinctUrlDomains).toEqual(["paypa1-secure.com"]);
  });

  it("falls back to Received-SPF and ARC-Authentication-Results", async () => {
    const raw = eml(
      [
        "Received-SPF: softfail (mx: transitioning domain does not designate 1.2.3.4 as permitted sender)",
        "ARC-Authentication-Results: i=1; mx.example.com; dkim=pass header.d=x.example; dmarc=pass",
        "From: a@x.example",
        "To: b@y.example",
        "Subject: hi",
      ],
      "hello",
    );
    const email = await parseEmail({ raw });
    expect(email.auth).toEqual({ spf: "softfail", dkim: "pass", dmarc: "pass" });
  });

  it("extracts anchors from HTML, flags anchor/href mismatch, and strips HTML to text", async () => {
    const email = await parseEmail({ raw: ANCHOR_MISMATCH_EML });
    expect(email.hasHtml).toBe(true);
    expect(email.text).toContain("Sign in at");
    expect(email.text).not.toContain("<a");
    expect(email.text).not.toContain("alert(1)");
    const mismatch = email.urls.find((u) => u.href.startsWith("https://login.evil-host.net"));
    expect(mismatch).toBeDefined();
    expect(mismatch?.anchorText).toBe("https://www.microsoft.com/login");
    expect(mismatch?.domain).toBe("evil-host.net");
    expect(mismatch?.textMismatch).toBe(true);
    const ok = email.urls.find((u) => u.href === "https://www.microsoft.com/news");
    expect(ok?.anchorText).toBe("our news");
    expect(ok?.textMismatch).toBe(false);
    expect(email.signals.distinctUrlDomains.sort()).toEqual(["evil-host.net", "microsoft.com"]);
    expect(email.signals.replyToMismatch).toBe(false);
  });

  it("collects attachments and flags dangerous double extensions", async () => {
    const email = await parseEmail({ raw: ATTACHMENT_EML });
    expect(email.attachments).toHaveLength(1);
    expect(email.attachments[0]).toMatchObject({ filename: "invoice.pdf.exe", contentType: "application/octet-stream" });
    expect(email.attachments[0]?.size).toBeGreaterThan(0);
    expect(email.signals.hasDangerousAttachment).toBe(true);
    expect(email.text).toBe("See attached.");
  });

  it("flags a display name that carries a different email address", async () => {
    const raw = eml(
      ['From: "ceo@corp.example" <random123@gmail.com>', "To: cfo@corp.example", "Subject: urgent"],
      "Need gift cards.",
    );
    const email = await parseEmail({ raw });
    expect(email.signals.displayNameLooksLikeEmail).toBe(true);
    expect(email.signals.fromDomain).toBe("gmail.com");
  });

  it("yields unknown auth results when no auth headers are present", async () => {
    const email = await parseEmail({ raw: eml(["From: a@x.example", "Subject: x"], "body") });
    expect(email.auth).toEqual({ spf: "unknown", dkim: "unknown", dmarc: "unknown" });
    expect(email.replyTo).toBeUndefined();
    expect(email.signals.replyToMismatch).toBe(false);
  });
});

describe("parseEmail (fields fallback)", () => {
  it("builds a ParsedEmail from loose fields and header map", async () => {
    const email = await parseEmail({
      fields: {
        subject: "Payroll update",
        from: "HR Team <hr@corp-payroll.co>",
        replyTo: "hr-desk@corp.example",
        to: "alice@corp.example, bob@corp.example",
        body: "Update your details at http://198.51.100.7/hr now.",
        headers: {
          "Authentication-Results": "mx; spf=pass; dkim=fail; dmarc=none",
          "Return-Path": "<bounce@corp-payroll.co>",
        },
      },
    });
    expect(email.from).toEqual({ name: "HR Team", address: "hr@corp-payroll.co" });
    expect(email.to).toEqual(["alice@corp.example", "bob@corp.example"]);
    expect(email.auth).toEqual({ spf: "pass", dkim: "fail", dmarc: "none" });
    expect(email.returnPath).toBe("bounce@corp-payroll.co");
    expect(email.signals.replyToMismatch).toBe(true);
    expect(email.signals.returnPathMismatch).toBe(false);
    expect(email.urls[0]?.href).toBe("http://198.51.100.7/hr");
    expect(email.urls[0]?.domain).toBeNull();
    expect(email.attachments).toEqual([]);
    expect(email.hasHtml).toBe(false);
  });

  it("derives text from html when only html is supplied", async () => {
    const email = await parseEmail({
      fields: { subject: "s", from: "a@x.example", html: "<div>Hi &amp; welcome</div><p>Click <a href='https://x.example/go'>here</a></p>" },
    });
    expect(email.hasHtml).toBe(true);
    expect(email.text).toBe("Hi & welcome\nClick here");
    expect(email.urls).toEqual([{ href: "https://x.example/go", domain: "x.example", anchorText: "here", textMismatch: false }]);
  });

  it("rejects a request with neither raw nor fields", async () => {
    await expect(parseEmail({})).rejects.toThrow(/raw.*fields/);
  });
});

describe("isDangerousFilename", () => {
  it.each(["run.exe", "a.SCR", "doc.docm", "page.html", "note.one", "payload.exe.zip", "x.js"])("%s is dangerous", (name) => {
    expect(isDangerousFilename(name)).toBe(true);
  });
  it.each(["report.pdf", "photo.jpg", "archive.zip", "README", "data.csv"])("%s is safe", (name) => {
    expect(isDangerousFilename(name)).toBe(false);
  });
});
