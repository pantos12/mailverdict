/**
 * MailVerdict evaluation harness.
 *
 * Runs every fixture in tests/fixtures/emails through `analyzeEmail` and reports:
 *   - a per-email table (file, expected, got, probability, ms)
 *   - a confusion matrix (SUSPICIOUS is treated as "review", not as a miss or a hit)
 *   - precision / recall / F1 for PHISHING at the policy thresholds
 *   - review rate (share of emails that landed in the SUSPICIOUS band)
 *   - a 5-bucket calibration table (bucket, n, mean predicted, observed phishing rate)
 *
 * Usage:
 *   npm run eval
 *   npx tsx scripts/eval.ts [--fixtures tests/fixtures] [--concurrency 4] [--json out.json]
 *
 * Requires TYPESAFE_API_KEY (read from the environment or from a .env file in the
 * project root; a tiny inline parser is used, no dotenv dependency). The LLM explainer
 * is disabled for the whole run (policy.explainSuspicious = false), so OPENROUTER_API_KEY
 * is not needed and the run costs only Jev tokens (~24 emails x ~3k tokens ~= $0.003).
 *
 * Exit code: 0 on success, 1 if PHISHING recall < 0.8 (or the run could not start).
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { analyzeEmail, createDefaultDeps } from "../src/analyze.js";
import {
  DEFAULT_POLICY,
  type AttackType,
  type Verdict,
  type VerdictLabel,
} from "../src/types.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RECALL_FLOOR = 0.8;
const CALIBRATION_BUCKETS = [
  [0.0, 0.2],
  [0.2, 0.4],
  [0.4, 0.6],
  [0.6, 0.8],
  [0.8, 1.0000001],
] as const;

interface LabelEntry {
  file: string;
  label: VerdictLabel;
  attackType: AttackType;
}

interface RowResult {
  file: string;
  expected: VerdictLabel;
  expectedAttack: AttackType;
  got: VerdictLabel | "ERROR";
  probability: number | null;
  attackType: AttackType | null;
  ms: number;
  jevTokens: number;
  error?: string;
}

interface CliArgs {
  fixturesDir: string;
  concurrency: number;
  jsonOut?: string;
}

// ---------------------------------------------------------------------------
// Tiny .env loader (KEY=VALUE, '#' comments, optional quotes; never overrides env)
// ---------------------------------------------------------------------------

function loadDotEnv(path: string): void {
  if (!existsSync(path)) return;
  for (const rawLine of readFileSync(path, "utf8").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim().replace(/^export\s+/, "");
    let value = line.slice(eq + 1).trim();
    const quoted = value.match(/^(['"])(.*)\1$/);
    if (quoted) value = quoted[2] ?? "";
    else value = value.replace(/\s+#.*$/, "");
    if (!(key in process.env)) process.env[key] = value;
  }
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = { fixturesDir: resolve(ROOT, "tests/fixtures"), concurrency: 4 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = argv[i + 1];
    if (a === "--fixtures" && next) args.fixturesDir = resolve(ROOT, next), i++;
    else if (a === "--concurrency" && next) args.concurrency = Math.max(1, Number(next) || 1), i++;
    else if (a === "--json" && next) args.jsonOut = resolve(ROOT, next), i++;
  }
  return args;
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

async function runOne(
  entry: LabelEntry,
  fixturesDir: string,
  deps: ReturnType<typeof createDefaultDeps>,
): Promise<RowResult> {
  const raw = readFileSync(resolve(fixturesDir, "emails", entry.file), "utf8");
  const started = performance.now();
  try {
    const verdict: Verdict = await analyzeEmail(
      {
        raw,
        // Explainer off: the eval measures the classifier, not the prose, and costs no LLM tokens.
        policy: { ...DEFAULT_POLICY, explainSuspicious: false, explainPhishing: false },
      },
      deps,
    );
    return {
      file: entry.file,
      expected: entry.label,
      expectedAttack: entry.attackType,
      got: verdict.label,
      probability: verdict.probability,
      attackType: verdict.attackType,
      ms: Math.round(performance.now() - started),
      jevTokens: verdict.usage.jevInputTokens,
    };
  } catch (err) {
    return {
      file: entry.file,
      expected: entry.label,
      expectedAttack: entry.attackType,
      got: "ERROR",
      probability: null,
      attackType: null,
      ms: Math.round(performance.now() - started),
      jevTokens: 0,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

async function runAll(entries: LabelEntry[], args: CliArgs): Promise<RowResult[]> {
  const deps = createDefaultDeps();
  const results: RowResult[] = new Array(entries.length);
  let cursor = 0;
  const worker = async () => {
    while (cursor < entries.length) {
      const i = cursor++;
      const entry = entries[i];
      if (entry) results[i] = await runOne(entry, args.fixturesDir, deps);
    }
  };
  await Promise.all(Array.from({ length: Math.min(args.concurrency, entries.length) }, worker));
  return results;
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

const pad = (s: string | number, n: number, right = false) => {
  const str = String(s);
  return right ? str.padStart(n) : str.padEnd(n);
};
const pct = (x: number) => (Number.isFinite(x) ? `${(x * 100).toFixed(1)}%` : "n/a");
const fmtProb = (p: number | null) => (p === null ? "  -  " : p.toFixed(3));

function printPerEmailTable(rows: RowResult[]): void {
  const w = Math.max(...rows.map((r) => r.file.length), 4);
  console.log(`\n${pad("file", w)}  ${pad("expected", 10)}  ${pad("got", 10)}  ${pad("prob", 6)}  ${pad("ms", 6, true)}  ok`);
  console.log("-".repeat(w + 45));
  for (const r of rows) {
    const ok = r.got === r.expected ? "yes" : r.got === "SUSPICIOUS" ? "review" : "NO";
    console.log(
      `${pad(r.file, w)}  ${pad(r.expected, 10)}  ${pad(r.got, 10)}  ${fmtProb(r.probability)}  ${pad(r.ms, 6, true)}  ${ok}` +
        (r.error ? `  (${r.error})` : ""),
    );
  }
}

function printConfusion(rows: RowResult[]): void {
  const cols: Array<VerdictLabel | "ERROR"> = ["PHISHING", "SUSPICIOUS", "LEGITIMATE", "ERROR"];
  const rowsExp: VerdictLabel[] = ["PHISHING", "LEGITIMATE"];
  console.log("\nConfusion matrix (rows = expected, cols = got; SUSPICIOUS = review)");
  console.log(`${pad("", 12)}${cols.map((c) => pad(c, 12, true)).join("")}`);
  for (const e of rowsExp) {
    const counts = cols.map((c) => rows.filter((r) => r.expected === e && r.got === c).length);
    console.log(`${pad(e, 12)}${counts.map((n) => pad(n, 12, true)).join("")}`);
  }
}

interface Metrics {
  precision: number;
  recall: number;
  f1: number;
  reviewRate: number;
  recallIncludingReview: number;
  attackTypeAccuracy: number;
  errors: number;
}

function computeMetrics(rows: RowResult[]): Metrics {
  const tp = rows.filter((r) => r.expected === "PHISHING" && r.got === "PHISHING").length;
  const fp = rows.filter((r) => r.expected === "LEGITIMATE" && r.got === "PHISHING").length;
  const fn = rows.filter((r) => r.expected === "PHISHING" && r.got !== "PHISHING").length;
  const caughtOrReview = rows.filter(
    (r) => r.expected === "PHISHING" && (r.got === "PHISHING" || r.got === "SUSPICIOUS"),
  ).length;
  const phishTotal = rows.filter((r) => r.expected === "PHISHING").length;
  const precision = tp + fp === 0 ? NaN : tp / (tp + fp);
  const recall = tp + fn === 0 ? NaN : tp / (tp + fn);
  const f1 = precision + recall === 0 || !Number.isFinite(precision + recall) ? NaN : (2 * precision * recall) / (precision + recall);
  const phishRows = rows.filter((r) => r.expected === "PHISHING" && r.got === "PHISHING");
  const attackHits = phishRows.filter((r) => r.attackType === r.expectedAttack).length;
  return {
    precision,
    recall,
    f1,
    reviewRate: rows.filter((r) => r.got === "SUSPICIOUS").length / rows.length,
    recallIncludingReview: phishTotal === 0 ? NaN : caughtOrReview / phishTotal,
    attackTypeAccuracy: phishRows.length === 0 ? NaN : attackHits / phishRows.length,
    errors: rows.filter((r) => r.got === "ERROR").length,
  };
}

function printMetrics(m: Metrics, rows: RowResult[]): void {
  const totalTokens = rows.reduce((s, r) => s + r.jevTokens, 0);
  const avgMs = rows.reduce((s, r) => s + r.ms, 0) / Math.max(rows.length, 1);
  console.log(`\nPHISHING @ thresholds high>=${DEFAULT_POLICY.highThreshold} low<=${DEFAULT_POLICY.lowThreshold}`);
  console.log(`  precision            ${pct(m.precision)}`);
  console.log(`  recall               ${pct(m.recall)}   (floor ${pct(RECALL_FLOOR)})`);
  console.log(`  F1                   ${pct(m.f1)}`);
  console.log(`  recall incl. review  ${pct(m.recallIncludingReview)}   (PHISHING or SUSPICIOUS)`);
  console.log(`  review rate          ${pct(m.reviewRate)}`);
  console.log(`  attack-type accuracy ${pct(m.attackTypeAccuracy)}   (on true positives)`);
  console.log(`  errors               ${m.errors}`);
  console.log(`  Jev input tokens     ${totalTokens} total, ${Math.round(totalTokens / Math.max(rows.length, 1))} avg/email`);
  console.log(`  est. Jev cost        $${((totalTokens / 1e6) * 0.042).toFixed(5)}  (at $0.042 / M input tokens)`);
  console.log(`  avg latency          ${Math.round(avgMs)} ms`);
}

function printCalibration(rows: RowResult[]): void {
  console.log("\nCalibration (predicted probability vs observed phishing rate)");
  console.log(`${pad("bucket", 12)}${pad("n", 5, true)}${pad("mean pred", 12, true)}${pad("observed", 12, true)}${pad("gap", 9, true)}`);
  for (const [lo, hi] of CALIBRATION_BUCKETS) {
    const inBucket = rows.filter((r) => r.probability !== null && r.probability >= lo && r.probability < hi);
    const n = inBucket.length;
    const meanPred = n ? inBucket.reduce((s, r) => s + (r.probability ?? 0), 0) / n : NaN;
    const observed = n ? inBucket.filter((r) => r.expected === "PHISHING").length / n : NaN;
    const label = `${lo.toFixed(1)}-${Math.min(hi, 1).toFixed(1)}`;
    console.log(
      `${pad(label, 12)}${pad(n, 5, true)}${pad(n ? meanPred.toFixed(3) : "-", 12, true)}${pad(n ? observed.toFixed(3) : "-", 12, true)}${pad(n ? (observed - meanPred).toFixed(3) : "-", 9, true)}`,
    );
  }
  console.log("(with 24 fixtures each bucket is small; treat gaps as directional, not statistical)");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<number> {
  loadDotEnv(resolve(ROOT, ".env"));
  const args = parseArgs(process.argv.slice(2));

  if (!process.env.TYPESAFE_API_KEY) {
    console.error("TYPESAFE_API_KEY is not set. Add it to .env or export it, then re-run.");
    return 1;
  }

  const labelsPath = resolve(args.fixturesDir, "labels.json");
  if (!existsSync(labelsPath)) {
    console.error(`labels.json not found at ${labelsPath}`);
    return 1;
  }
  const entries = JSON.parse(readFileSync(labelsPath, "utf8")) as LabelEntry[];
  console.log(`MailVerdict eval: ${entries.length} fixtures from ${args.fixturesDir} (concurrency ${args.concurrency}, explainer off)`);

  const rows = await runAll(entries, args);
  printPerEmailTable(rows);
  printConfusion(rows);
  const metrics = computeMetrics(rows);
  printMetrics(metrics, rows);
  printCalibration(rows);

  if (args.jsonOut) {
    writeFileSync(args.jsonOut, JSON.stringify({ policy: DEFAULT_POLICY, metrics, rows }, null, 2));
    console.log(`\nWrote ${args.jsonOut}`);
  }

  if (!Number.isFinite(metrics.recall) || metrics.recall < RECALL_FLOOR) {
    console.error(`\nFAIL: PHISHING recall ${pct(metrics.recall)} is below the ${pct(RECALL_FLOOR)} floor.`);
    return 1;
  }
  console.log("\nPASS");
  return 0;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(err);
    process.exit(1);
  },
);
