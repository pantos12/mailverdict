import { describe, expect, it } from "vitest";
import { extractPresentedKey, requireApiKey, safeEqual } from "../../src/http/auth.js";

const env = { MAILVERDICT_API_KEY: "s3cret-key-1234" } as NodeJS.ProcessEnv;

describe("requireApiKey", () => {
  it("accepts x-api-key", () => {
    expect(requireApiKey({ "x-api-key": "s3cret-key-1234" }, env)).toEqual({ ok: true });
  });

  it("accepts header names case-insensitively and array values", () => {
    expect(requireApiKey({ "X-API-KEY": ["s3cret-key-1234"] }, env)).toEqual({ ok: true });
  });

  it("accepts Authorization: Bearer", () => {
    expect(requireApiKey({ authorization: "Bearer s3cret-key-1234" }, env)).toEqual({ ok: true });
    expect(requireApiKey({ Authorization: "bearer   s3cret-key-1234 " }, env)).toEqual({ ok: true });
  });

  it("rejects a missing key with 401", () => {
    const result = requireApiKey({}, env);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.status).toBe(401);
  });

  it("rejects a wrong key with 401 (including length mismatch)", () => {
    const wrong = requireApiKey({ "x-api-key": "s3cret-key-1235" }, env);
    expect(wrong).toMatchObject({ ok: false, status: 401 });
    const short = requireApiKey({ "x-api-key": "nope" }, env);
    expect(short).toMatchObject({ ok: false, status: 401 });
  });

  it("rejects non-bearer authorization schemes", () => {
    expect(requireApiKey({ authorization: "Basic abc" }, env)).toMatchObject({ ok: false, status: 401 });
  });

  it("returns 500 when the server has no key configured", () => {
    const result = requireApiKey({ "x-api-key": "anything" }, {} as NodeJS.ProcessEnv);
    expect(result).toEqual({ ok: false, status: 500, message: "server not configured" });
    expect(requireApiKey({ "x-api-key": "x" }, { MAILVERDICT_API_KEY: "" } as NodeJS.ProcessEnv)).toMatchObject({
      status: 500,
    });
  });
});

describe("helpers", () => {
  it("extractPresentedKey prefers x-api-key over bearer", () => {
    expect(extractPresentedKey({ "x-api-key": "a", authorization: "Bearer b" })).toBe("a");
    expect(extractPresentedKey({ authorization: "Bearer b" })).toBe("b");
    expect(extractPresentedKey({})).toBeUndefined();
  });

  it("safeEqual compares correctly", () => {
    expect(safeEqual("abc", "abc")).toBe(true);
    expect(safeEqual("abc", "abd")).toBe(false);
    expect(safeEqual("abc", "abcd")).toBe(false);
  });
});
