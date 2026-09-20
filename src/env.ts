/**
 * Tiny .env loader (no dotenv dependency). Existing process.env values are never overridden.
 */
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

export function parseDotEnv(content: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    const key = m[1] ?? "";
    let value = (m[2] ?? "").trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      const quote = value[0];
      value = value.slice(1, -1);
      if (quote === '"') value = value.replace(/\\n/g, "\n").replace(/\\"/g, '"');
    } else {
      const hash = value.indexOf(" #");
      if (hash >= 0) value = value.slice(0, hash).trim();
    }
    out[key] = value;
  }
  return out;
}

/** Load `.env` (or the given path) into `env` without overriding already-set keys. Returns loaded keys. */
export function loadDotEnv(path = ".env", env: NodeJS.ProcessEnv = process.env): string[] {
  const full = resolve(path);
  if (!existsSync(full)) return [];
  const parsed = parseDotEnv(readFileSync(full, "utf8"));
  const loaded: string[] = [];
  for (const [k, v] of Object.entries(parsed)) {
    if (env[k] === undefined) {
      env[k] = v;
      loaded.push(k);
    }
  }
  return loaded;
}
