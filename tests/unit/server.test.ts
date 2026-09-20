import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";

const health = vi.fn((_req: unknown, res: { end: (s: string) => void }) => res.end("health"));
const analyze = vi.fn((_req: unknown, res: { end: (s: string) => void }) => res.end("analyze"));
const mcp = vi.fn((_req: unknown, res: { end: (s: string) => void }) => res.end("mcp"));

vi.mock("../../api/health.js", () => ({ default: health }));
vi.mock("../../api/analyze.js", () => ({ default: analyze }));
vi.mock("../../api/mcp.js", () => ({ default: mcp }));

const { route } = await import("../../src/server.js");

function fakeReq(method: string, url: string) {
  const req = new EventEmitter() as EventEmitter & { method: string; url: string; headers: Record<string, string> };
  req.method = method;
  req.url = url;
  req.headers = {};
  return req;
}

function fakeRes() {
  return {
    statusCode: 200,
    headers: {} as Record<string, string>,
    body: "",
    headersSent: false,
    setHeader(name: string, value: string) {
      this.headers[name.toLowerCase()] = value;
    },
    writeHead(status: number, headers: Record<string, string>) {
      this.statusCode = status;
      Object.assign(this.headers, headers);
    },
    end(chunk?: string | Buffer) {
      this.body = chunk ? chunk.toString() : "";
      this.headersSent = true;
    },
  };
}

const call = (req: unknown, res: unknown) => route(req as never, res as never);

describe("container server routing", () => {
  it("dispatches public paths and their /api aliases to the Vercel handlers", async () => {
    for (const [path, expected] of [
      ["/health", "health"],
      ["/api/health", "health"],
      ["/v1/analyze", "analyze"],
      ["/api/analyze", "analyze"],
      ["/mcp", "mcp"],
      ["/api/mcp/", "mcp"],
    ] as const) {
      const res = fakeRes();
      await call(fakeReq("POST", path), res);
      expect(res.body, path).toBe(expected);
    }
  });

  it("serves the landing page at / and 404s elsewhere", async () => {
    const home = fakeRes();
    await call(fakeReq("GET", "/?utm=x"), home);
    expect(home.statusCode).toBe(200);
    expect(home.headers["content-type"]).toContain("text/html");
    expect(home.body).toContain("MailVerdict");

    const missing = fakeRes();
    await call(fakeReq("GET", "/nope"), missing);
    expect(missing.statusCode).toBe(404);
  });
});
