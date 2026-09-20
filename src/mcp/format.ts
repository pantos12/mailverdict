/**
 * Pure formatting of a Verdict into a human summary (tool text content) and a
 * markdown card (for Copilot Studio rendering). No LLM calls here.
 */
import type { Indicator, Verdict } from "../types.js";

export const MAX_SUMMARY_INDICATORS = 5;

export function formatPercent(probability: number): string {
  const clamped = Math.min(1, Math.max(0, probability));
  return `${Math.round(clamped * 100)}%`;
}

function topIndicators(indicators: Indicator[], limit: number): Indicator[] {
  return [...indicators].sort((a, b) => b.weight - a.weight).slice(0, limit);
}

/**
 * "Verdict: PHISHING (93% probability) — credential_harvest
 *  Top indicators:
 *  • …
 *  Explanation: …"
 */
export function formatVerdictSummary(verdict: Verdict): string {
  const lines: string[] = [];
  lines.push(`Verdict: ${verdict.label} (${formatPercent(verdict.probability)} probability) — ${verdict.attackType}`);
  lines.push("Top indicators:");
  const top = topIndicators(verdict.indicators, MAX_SUMMARY_INDICATORS);
  if (top.length === 0) {
    lines.push("• none");
  } else {
    for (const ind of top) lines.push(`• ${ind.label}`);
  }
  if (verdict.explanation && verdict.explanation.trim().length > 0) {
    lines.push(`Explanation: ${verdict.explanation.trim()}`);
  }
  return lines.join("\n");
}

const LABEL_HEADLINE: Record<Verdict["label"], string> = {
  PHISHING: "Do not click, reply, or open attachments.",
  SUSPICIOUS: "Treat with caution and verify through a known channel.",
  LEGITIMATE: "No strong phishing signals found.",
};

function fmtScore(value: number): string {
  return Number.isFinite(value) ? value.toFixed(2) : "n/a";
}

/** Markdown card with verdict, probability, indicators, signals and explanation. */
export function formatVerdictMarkdown(verdict: Verdict): string {
  const out: string[] = [];
  out.push(`## Verdict: ${verdict.label}`);
  out.push("");
  out.push(`**Phishing probability:** ${formatPercent(verdict.probability)} (calibrated)  `);
  out.push(`**Attack type:** ${verdict.attackType}  `);
  out.push(`**Guidance:** ${LABEL_HEADLINE[verdict.label]}`);
  out.push("");

  out.push("### Indicators");
  if (verdict.indicators.length === 0) {
    out.push("_None detected._");
  } else {
    for (const ind of topIndicators(verdict.indicators, 10)) {
      out.push(`- **${ind.label}** (${ind.source}, weight ${fmtScore(ind.weight)})`);
    }
  }
  out.push("");

  const s = verdict.signals;
  out.push("### Signals");
  out.push("| Signal | Value |");
  out.push("|---|---|");
  out.push(`| Requests credentials | ${fmtScore(s.requests_credentials)} |`);
  out.push(`| Requests payment | ${fmtScore(s.requests_payment)} |`);
  out.push(`| Impersonates brand/person | ${fmtScore(s.impersonates_brand_or_person)} |`);
  out.push(`| Urgency pressure (0-2) | ${fmtScore(s.urgency_pressure)} |`);
  out.push(`| Attack type confidence | ${fmtScore(s.attack_type_confidence)} |`);
  out.push("");

  if (verdict.explanation && verdict.explanation.trim().length > 0) {
    out.push("### Explanation");
    out.push(`> ${verdict.explanation.trim().replace(/\n/g, "\n> ")}`);
    out.push("");
  }

  const explainer = verdict.model.explainer ? ` · Explainer: ${verdict.model.explainer}` : "";
  out.push(`_Judge: ${verdict.model.jev}${explainer} · ${verdict.latencyMs} ms_`);
  return out.join("\n");
}
