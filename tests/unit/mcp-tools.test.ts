import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AnalyzeRequest, Verdict } from "../../src/types.js";

vi.mock("../../src/analyze.js", () => ({
  analyzeEmail: vi.fn(),
  validateAnalyzeRequest: vi.fn((x: unknown) => x),
  createDefaultDeps: vi.fn(() => ({})),
}));

const { policyFromEnv, registerTools, toAnalyzeRequest } = await import("../../src/mcp/tools.js");

const verdict: Verdict = {
  label: "PHISHING",
  probability: 0.93,
  attackType: "credential_harvest",
  indicators: [{ key: "url_mismatch", label: "Link text points to a different domain", weight: 0.9, source: "url" }],
  signals: {
    is_phishing: 0.93,
    requests_credentials: 0.9,
    requests_payment: 0,
    impersonates_brand_or_person: 0.8,
    urgency_pressure: 2,
    attack_type: "credential_harvest",
    attack_type_confidence: 0.85,
  },
  explained: false,
  model: { jev: "jev-1" },
  usage: { jevInputTokens: 300 },
  latencyMs: 210,
};

const fakeDeps = { marker: "fake" } as never;

async function connect(analyze = vi.fn(async () => verdict), env: NodeJS.ProcessEnv = {}) {
  const server = new McpServer({ name: "mailverdict-test", version: "0.0.0" });
  registerTools(server, fakeDeps, { analyze, env });
  const client = new Client({ name: "test-client", version: "0.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { client, server, analyze };
}

describe("MCP tools", () => {
  let handles: Awaited<ReturnType<typeof connect>> | undefined;

  beforeEach(() => {
    handles = undefined;
  });

  afterEach(async () => {
    await handles?.client.close();
    await handles?.server.close();
  });

  it("lists exactly the three tools", async () => {
    handles = await connect();
    const { tools } = await handles.client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(["analyze_email", "explain_verdict", "get_policy"]);
    const analyzeTool = tools.find((t) => t.name === "analyze_email");
    expect(analyzeTool?.inputSchema).toMatchObject({ type: "object" });
    expect(Object.keys((analyzeTool?.inputSchema as { properties: object }).properties)).toEqual(
      expect.arrayContaining(["raw", "subject", "from", "body", "html", "headers"]),
    );
  });

  it("analyze_email returns a text summary and structuredContent verdict", async () => {
    handles = await connect();
    const result = await handles.client.callTool({
      name: "analyze_email",
      arguments: { subject: "Reset your password", from: "it@paypa1-secure.com", body: "Click here now" },
    });
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent).toMatchObject({ label: "PHISHING", probability: 0.93 });
    const content = result.content as Array<{ type: string; text: string }>;
    expect(content[0]?.type).toBe("text");
    expect(content[0]?.text).toContain("Verdict: PHISHING (93% probability) — credential_harvest");
    expect(content[0]?.text).toContain("• Link text points to a different domain");
    expect(handles.analyze).toHaveBeenCalledWith(
      { fields: { subject: "Reset your password", from: "it@paypa1-secure.com", body: "Click here now" } },
      fakeDeps,
    );
  });

  it("analyze_email prefers raw over fields", async () => {
    handles = await connect();
    await handles.client.callTool({ name: "analyze_email", arguments: { raw: "From: x\n\nbody", subject: "ignored" } });
    expect(handles.analyze).toHaveBeenCalledWith({ raw: "From: x\n\nbody" }, fakeDeps);
  });

  it("analyze_email returns isError when nothing was provided or the pipeline fails", async () => {
    handles = await connect();
    const empty = await handles.client.callTool({ name: "analyze_email", arguments: {} });
    expect(empty.isError).toBe(true);
    expect(handles.analyze).not.toHaveBeenCalled();

    handles.analyze.mockRejectedValueOnce(new Error("Jev timeout"));
    const failed = await handles.client.callTool({ name: "analyze_email", arguments: { raw: "x" } });
    expect(failed.isError).toBe(true);
    expect((failed.content as Array<{ text: string }>)[0]?.text).toContain("Jev timeout");
  });

  it("explain_verdict renders markdown without calling analyze", async () => {
    handles = await connect();
    const result = await handles.client.callTool({ name: "explain_verdict", arguments: { verdict } });
    expect(result.isError).toBeFalsy();
    const text = (result.content as Array<{ text: string }>)[0]?.text ?? "";
    expect(text).toContain("## Verdict: PHISHING");
    expect(text).toContain("| Requests credentials | 0.90 |");
    expect(handles.analyze).not.toHaveBeenCalled();
  });

  it("get_policy reports env-derived thresholds", async () => {
    handles = await connect(undefined, { VERDICT_HIGH_THRESHOLD: "0.8", VERDICT_EXPLAIN_PHISHING: "true" });
    const result = await handles.client.callTool({ name: "get_policy", arguments: {} });
    expect(result.structuredContent).toEqual({
      highThreshold: 0.8,
      lowThreshold: 0.1,
      explainSuspicious: true,
      explainPhishing: true,
    });
  });
});

describe("helpers", () => {
  it("toAnalyzeRequest drops undefined fields", () => {
    expect(toAnalyzeRequest({ subject: "s", headers: { "X-Test": "1" } })).toEqual<AnalyzeRequest>({
      fields: { subject: "s", headers: { "X-Test": "1" } },
    });
    expect(toAnalyzeRequest({})).toEqual({ fields: {} });
  });

  it("policyFromEnv falls back to defaults on bad values", () => {
    expect(policyFromEnv({ VERDICT_HIGH_THRESHOLD: "abc", VERDICT_LOW_THRESHOLD: "2", VERDICT_EXPLAIN_SUSPICIOUS: "no" })).toEqual({
      highThreshold: 0.9,
      lowThreshold: 0.1,
      explainSuspicious: false,
      explainPhishing: false,
    });
  });
});
