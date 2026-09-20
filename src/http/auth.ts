/**
 * API-key authentication for the public HTTP + MCP endpoints.
 *
 * Accepts either `x-api-key: <key>` or `Authorization: Bearer <key>` and compares
 * against MAILVERDICT_API_KEY using a constant-time comparison.
 */
import { timingSafeEqual } from "node:crypto";

export type HeaderMap = Record<string, string | string[] | undefined>;

export type AuthResult =
  | { ok: true }
  | { ok: false; status: number; message: string };

export const API_KEY_ENV = "MAILVERDICT_API_KEY";

function headerValue(headers: HeaderMap, name: string): string | undefined {
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== wanted) continue;
    if (Array.isArray(value)) return value[0];
    return value;
  }
  return undefined;
}

/** Extract the presented key from x-api-key or Authorization: Bearer. */
export function extractPresentedKey(headers: HeaderMap): string | undefined {
  const direct = headerValue(headers, "x-api-key");
  if (direct && direct.trim().length > 0) return direct.trim();

  const authz = headerValue(headers, "authorization");
  if (!authz) return undefined;
  const match = /^\s*Bearer\s+(.+?)\s*$/i.exec(authz);
  return match?.[1];
}

/** Constant-time string equality; never short-circuits on length. */
export function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    // Burn comparable time, then reject.
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

export function requireApiKey(headers: HeaderMap, env: NodeJS.ProcessEnv = process.env): AuthResult {
  const expected = env[API_KEY_ENV];
  if (!expected || expected.length === 0) {
    return { ok: false, status: 500, message: "server not configured" };
  }

  const presented = extractPresentedKey(headers);
  if (!presented) {
    return { ok: false, status: 401, message: "missing API key (use x-api-key or Authorization: Bearer)" };
  }

  if (!safeEqual(presented, expected)) {
    return { ok: false, status: 401, message: "invalid API key" };
  }

  return { ok: true };
}
