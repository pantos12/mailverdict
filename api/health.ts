import type { VercelRequest, VercelResponse } from "@vercel/node";
import { applyCors, sendJson } from "../src/http/json.js";
import { SERVICE_NAME, SERVICE_VERSION } from "../src/http/version.js";

export default function handler(_req: VercelRequest, res: VercelResponse): void {
  applyCors(res);
  const env = process.env;
  sendJson(res, 200, {
    ok: true,
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    jevConfigured: Boolean(env.TYPESAFE_API_KEY),
    explainerConfigured: Boolean(env.OPENROUTER_API_KEY),
  });
}
