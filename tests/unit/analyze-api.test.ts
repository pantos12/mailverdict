import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Verdict } from "../../src/types.js";

const analyzeEmail = vi.fn();
const validateAnalyzeRequest = vi.fn();
const createDefaultDeps = vi.fn(() => ({ fake: true }));

vi.mock("../../src/analyze.js", () => ({ analyzeEmail, validateAnalyzeRequest, createDefaultDeps }));

const { default: handler, normalizeAnalyzeBody } = await import("../../api/analyze.js");

const verdict: Verdict = {
  label: "SUSPICIOUS",
  probability: 0.42,
  indicators: [],
  attackType: "none",
  signals: {
    is_phishing: 0.42,
    requests_credentials: 0.1,
    requests_payment: 0,
    impersonates_brand_or_person: 0.2,
    urgency_pressure: 1,
    attack_type: "none",
    attack_type_confidence: 0.5,
  },
  explained: false,
  model: { jev: "jev-1" },
  usage: { jevInputTokens: 100 },
  latencyMs: 12,
};

interface FakeRes {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  headersSent: boolean;
  setHeader(name: string, value: string): void;
  end(chunk?: string): void;
  on(): void;
}

function makeReq(opts: { method?: string; headers?: Record<string, string>; body?: unknown }) {
  const req = new EventEmitter() as EventEmitter & { method: string; headers: Record<string, string>; body: unknown };
  req.method = opts.method ?? "POST";
  req.headers = opts.headers ?? {};
  req.body = opts.body;
  return req;
}

function makeRes(): FakeRes {
  return {
    statusCode: 200,
    headers: {},
    body: "",
    headersSent: false,
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
    },
    end(chunk) {
      this.body = chunk ?? "";
      this.headersSent = true;
    },
    on() {},
  };
}

const call = (req: unknown, res: unknown) => handler(req as never, res as never);
const json = (res: FakeRes) => JSON.parse(res.body) as Record<string, unknown>;

describe("normalizeAnalyzeBody", () => {
  it("wraps the flat Power Automate shape into fields", () => {
    expect(normalizeAnalyzeBody({ subject: "Hi", from: "a@b.c", body: "text", extra: 1 })).toEqual({
      fields: { subject: "Hi", from: "a@b.c", body: "text" },
    });
  });

  it("keeps policy alongside wrapped fields", () => {
    expect(normalizeAnalyzeBody({ html: "<p>x</p>", policy: { highThreshold: 0.8 } })).toEqual({
      fields: { html: "<p>x</p>" },
      policy: { highThreshold: 0.8 },
    });
  });

  it("leaves canonical shapes and non-objects untouched", () => {
    expect(normalizeAnalyzeBody({ raw: "From: x" })).toEqual({ raw: "From: x" });
    expect(normalizeAnalyzeBody({ fields: { subject: "s" } })).toEqual({ fields: { subject: "s" } });
    expect(normalizeAnalyzeBody("nope")).toBe("nope");
    expect(normalizeAnalyzeBody(null)).toBeNull();
    expect(normalizeAnalyzeBody({ unrelated: 1 })).toEqual({ unrelated: 1 });
  });
});

describe("POST /api/analyze", () => {
  const authHeaders = { "x-api-key": "test-key-000" };

  beforeEach(() => {
    vi.stubEnv("MAILVERDICT_API_KEY", "test-key-000");
    vi.stubEnv("TYPESAFE_API_KEY", "ts-live-supersecret-value");
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    analyzeEmail.mockReset();
    validateAnalyzeRequest.mockReset();
    validateAnalyzeRequest.mockImplementation((input: unknown) => input);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it("returns the verdict for a valid request and logs one JSON line without content", async () => {
    analyzeEmail.mockResolvedValue(verdict);
    const res = makeRes();
    await call(makeReq({ headers: authHeaders, body: { raw: "From: a@b.c\nSubject: hi\n\nbody" } }), res);
    expect(res.statusCode).toBe(200);
    expect(json(res)).toMatchObject({ label: "SUSPICIOUS", probability: 0.42 });
    expect(analyzeEmail).toHaveBeenCalledWith({ raw: "From: a@b.c\nSubject: hi\n\nbody" }, { fake: true });
    const logged = (console.log as unknown as { mock: { calls: unknown[][] } }).mock.calls;
    expect(logged).toHaveLength(1);
    const line = JSON.parse(logged[0]?.[0] as string) as Record<string, unknown>;
    expect(line).toMatchObject({ evt: "analyze", label: "SUSPICIOUS", probability: 0.42, latencyMs: 12 });
    expect(JSON.stringify(line)).not.toContain("body");
  });

  it("wraps the flat Power Automate shape before validation", async () => {
    analyzeEmail.mockResolvedValue(verdict);
    const res = makeRes();
    await call(makeReq({ headers: authHeaders, body: { subject: "Invoice", from: "x@y.z", body: "pay now" } }), res);
    expect(res.statusCode).toBe(200);
    expect(validateAnalyzeRequest).toHaveBeenCalledWith({ fields: { subject: "Invoice", from: "x@y.z", body: "pay now" } });
  });

  it("parses a string body", async () => {
    analyzeEmail.mockResolvedValue(verdict);
    const res = makeRes();
    await call(makeReq({ headers: authHeaders, body: JSON.stringify({ raw: "x" }) }), res);
    expect(res.statusCode).toBe(200);
    expect(validateAnalyzeRequest).toHaveBeenCalledWith({ raw: "x" });
  });

  it("treats a message/rfc822 body as { raw } (Power Automate Export email)", async () => {
    analyzeEmail.mockResolvedValue(verdict);
    const res = makeRes();
    const eml = 'From: a@b.c\r\nSubject: {"not":"json"}\r\n\r\nBody with "quotes" and\nnewlines';
    await call(makeReq({ headers: { ...authHeaders, "content-type": "message/rfc822" }, body: Buffer.from(eml) }), res);
    expect(res.statusCode).toBe(200);
    expect(validateAnalyzeRequest).toHaveBeenCalledWith({ raw: eml });
  });

  it("streams a message/rfc822 body when it is not pre-parsed", async () => {
    analyzeEmail.mockResolvedValue(verdict);
    const res = makeRes();
    const req = makeReq({ headers: { ...authHeaders, "content-type": "message/rfc822; charset=utf-8" } });
    const eml = "From: a@b.c\r\n\r\nhello";
    (req as unknown as { [Symbol.asyncIterator]: () => AsyncIterator<Buffer> })[Symbol.asyncIterator] = async function* () {
      yield Buffer.from(eml);
    };
    await call(req, res);
    expect(res.statusCode).toBe(200);
    expect(validateAnalyzeRequest).toHaveBeenCalledWith({ raw: eml });
  });

  it("returns 401 without a key and does not analyze", async () => {
    const res = makeRes();
    await call(makeReq({ body: { raw: "x" } }), res);
    expect(res.statusCode).toBe(401);
    expect(analyzeEmail).not.toHaveBeenCalled();
  });

  it("returns 500 when the server key is not configured", async () => {
    vi.stubEnv("MAILVERDICT_API_KEY", "");
    const res = makeRes();
    await call(makeReq({ headers: authHeaders, body: { raw: "x" } }), res);
    expect(res.statusCode).toBe(500);
  });

  it("returns 400 when validation throws (zod-style issues)", async () => {
    validateAnalyzeRequest.mockImplementation(() => {
      throw { issues: [{ path: ["fields", "subject"], message: "Expected string" }] };
    });
    const res = makeRes();
    await call(makeReq({ headers: authHeaders, body: { fields: { subject: 5 } } }), res);
    expect(res.statusCode).toBe(400);
    expect(json(res).error).toBe("invalid request: fields.subject: Expected string");
    expect(analyzeEmail).not.toHaveBeenCalled();
  });

  it("returns 400 for a malformed JSON string body", async () => {
    const res = makeRes();
    await call(makeReq({ headers: authHeaders, body: "{not json" }), res);
    expect(res.statusCode).toBe(400);
  });

  it("returns 502 with a sanitized message when the pipeline fails", async () => {
    analyzeEmail.mockRejectedValue(
      new Error("Jev 401: bad key ts-live-supersecret-value sent as Bearer ts-live-supersecret-value"),
    );
    const res = makeRes();
    await call(makeReq({ headers: authHeaders, body: { raw: "x" } }), res);
    expect(res.statusCode).toBe(502);
    const error = String(json(res).error);
    expect(error).toContain("upstream analysis failed");
    expect(error).not.toContain("ts-live-supersecret-value");
    expect(error).toContain("[redacted]");
  });

  it("returns 405 for GET and 204 for OPTIONS with CORS headers", async () => {
    const getRes = makeRes();
    await call(makeReq({ method: "GET" }), getRes);
    expect(getRes.statusCode).toBe(405);

    const optRes = makeRes();
    await call(makeReq({ method: "OPTIONS" }), optRes);
    expect(optRes.statusCode).toBe(204);
    expect(optRes.headers["access-control-allow-headers"]).toContain("x-api-key");
    expect(optRes.headers["access-control-allow-headers"]).toContain("mcp-session-id");
  });
});
