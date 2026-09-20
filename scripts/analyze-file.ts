/**
 * CLI: npm run analyze -- path/to/email.eml
 * Prints the Verdict as pretty JSON. Reads TYPESAFE_API_KEY / OPENROUTER_API_KEY from env or .env.
 */
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { analyzeEmail, createDefaultDeps, validateAnalyzeRequest } from "../src/analyze.js";
import { loadDotEnv } from "../src/env.js";

async function main(argv: string[]): Promise<number> {
  const file = argv[0];
  if (!file) {
    process.stderr.write("Usage: npm run analyze -- path/to/email.eml\n");
    return 2;
  }
  loadDotEnv();
  const raw = await readFile(resolve(file), "utf8");
  const request = validateAnalyzeRequest({ raw });
  const deps = createDefaultDeps();
  deps.onExplainerError = (err) => {
    process.stderr.write(`explainer failed: ${err instanceof Error ? err.message : String(err)}\n`);
  };
  const verdict = await analyzeEmail(request, deps);
  process.stdout.write(`${JSON.stringify(verdict, null, 2)}\n`);
  return 0;
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
