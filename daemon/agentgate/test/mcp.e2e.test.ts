import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateSigningKeyPair } from "@agentgate/core";
import { afterEach, describe, expect, it } from "vitest";
import { FakeServer, type FakeServerOptions } from "./fake-server.ts";
import { BIN, makeEnv, runCli } from "./helpers.ts";

/** M6: stdio MCP gateway (`agentgate mcp wrap`) against the demo MCP server + fake API. */

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const DEMO = join(ROOT, "examples", "mcp-demo", "server.mjs");
const T = 30_000;

let server: FakeServer | null = null;
const procs: ChildProcessWithoutNullStreams[] = [];
afterEach(async () => {
  for (const p of procs.splice(0)) p.kill("SIGKILL");
  await server?.stop();
  server = null;
});

type Msg = Record<string, any>;

/** Spawns a process speaking newline-delimited JSON-RPC and collects every output line. */
function jsonRpcProc(cmd: string, args: string[], env: Record<string, string>, cwd: string) {
  const p = spawn(cmd, args, { cwd, env: { ...(process.env as Record<string, string>), NO_COLOR: "1", ...env }, stdio: ["pipe", "pipe", "pipe"] });
  procs.push(p);
  const lines: string[] = [];
  let stderr = "";
  let buf = "";
  const waiters: Array<() => void> = [];
  p.stdout.setEncoding("utf8");
  p.stdout.on("data", (c: string) => {
    buf += c;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      lines.push(buf.slice(0, i));
      buf = buf.slice(i + 1);
    }
    waiters.splice(0).forEach((w) => w());
  });
  p.stderr.on("data", (d) => (stderr += d));
  const exited = new Promise<number | null>((r) => p.on("close", (code) => r(code)));
  const send = (m: Msg | string) => p.stdin.write(`${typeof m === "string" ? m : JSON.stringify(m)}\n`);
  const msgs = () => lines.map((l) => JSON.parse(l) as Msg);
  async function until<T>(pred: () => T | undefined, ms = 15_000): Promise<T> {
    const end = Date.now() + ms;
    for (;;) {
      const v = pred();
      if (v !== undefined && v !== false) return v;
      if (Date.now() > end) throw new Error(`timeout; stdout=${lines.join("\n")}\nstderr=${stderr}`);
      await new Promise<void>((r) => {
        waiters.push(r);
        setTimeout(r, 50);
      });
    }
  }
  const response = (id: number | string) => until(() => msgs().find((m) => m.id === id && m.method === undefined));
  return { p, send, lines, msgs, until, response, exited, stderr: () => stderr };
}

async function setup(opts: FakeServerOptions = {}, apiDown = false) {
  let serverUrl: string;
  let token = "x".repeat(24);
  let pem = generateSigningKeyPair().publicKeyPem;
  if (apiDown) {
    const srv = createServer();
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    serverUrl = `http://127.0.0.1:${(srv.address() as { port: number }).port}`;
    await new Promise<void>((r) => srv.close(() => r()));
  } else {
    server = await new FakeServer(opts).start();
    serverUrl = server.url;
    token = server.token;
    pem = server.keys.publicKeyPem;
  }
  const env = makeEnv({ server: serverUrl, token, publicKeyPem: pem, policy: null }); // built-in policy
  const log = join(env.work, "side-effects.log");
  const gw = jsonRpcProc(process.execPath, [BIN, "mcp", "wrap", "--name", "demo", "--", process.execPath, DEMO], {
    AGENTGATE_HOME: env.home,
    MCP_DEMO_LOG: log,
    AGENTGATE_MCP_PROGRESS_MS: "100",
  }, env.work);
  return { s: server, ...env, gw, log };
}

const effects = (log: string) => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean) : []);

async function init(gw: ReturnType<typeof jsonRpcProc>, clientName = "claude-ai") {
  gw.send({ jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: clientName, version: "1.2.3" } } });
  await gw.response(0);
  gw.send({ jsonrpc: "2.0", method: "notifications/initialized" });
}

const call = (id: number, name: string, args: Msg = {}, meta?: Msg) => ({
  jsonrpc: "2.0",
  id,
  method: "tools/call",
  params: { name, arguments: args, ...(meta ? { _meta: meta } : {}) },
});

describe("pass-through", () => {
  it("everything except tools/call is relayed byte-for-byte, in both directions", async () => {
    const t = await setup();
    const script: string[] = [
      JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "cursor", version: "1" } } }),
      JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      `{"jsonrpc":"2.0","id":2,  "method":"tools/list"}`,
      JSON.stringify({ jsonrpc: "2.0", id: "r", method: "resources/list", params: {} }),
      JSON.stringify({ jsonrpc: "2.0", id: 3, method: "ping" }),
      JSON.stringify({ jsonrpc: "2.0", id: 4, method: "future/method", params: { x: [1, { y: null }] } }),
      JSON.stringify({ jsonrpc: "2.0", id: 5, method: "demo/ask_client" }),
    ];
    // Reference: talk to the demo server directly.
    const direct = jsonRpcProc(process.execPath, [DEMO], { MCP_DEMO_LOG: t.log }, t.work);
    for (const l of script) direct.send(l);
    await direct.until(() => direct.msgs().filter((m) => m.id !== undefined).length >= 7 || undefined);
    for (const l of script) t.gw.send(l);
    await t.gw.until(() => t.gw.msgs().filter((m) => m.id !== undefined).length >= 7 || undefined);
    expect(t.gw.lines).toEqual(direct.lines); // identical bytes, including the server→client sampling request
    expect(t.gw.lines.some((l) => l.includes('"method":"sampling/createMessage"'))).toBe(true);
    // client → server response to the server's request passes through too (no crash / no reply)
    t.gw.send({ jsonrpc: "2.0", id: "srv-1", result: { role: "assistant", content: { type: "text", text: "hi" } } });
    // nothing was gated or reported
    expect(t.s!.count("POST", "/v1/actions")).toBe(0);
  }, T);

  it("unparseable client line is refused, not forwarded", async () => {
    const t = await setup();
    t.gw.send("{not json");
    const r = await t.gw.until(() => t.gw.msgs().find((m) => m.error?.code === -32700));
    expect(r.id).toBeNull();
  }, T);
});

describe("gating", () => {
  it("read-only tool → allowed by policy and forwarded; execution reported", async () => {
    const t = await setup();
    await init(t.gw);
    t.gw.send(call(10, "list_inbox"));
    const r = await t.gw.response(10);
    expect(r.result.content[0].text).toMatch(/Welcome to AgentGate/);
    expect(effects(t.log)).toHaveLength(1);
    const sub = t.s!.requests.find((q) => q.path === "/v1/actions")!.body as any;
    expect(sub.policy.decision).toBe("allow");
    expect(sub.action).toMatchObject({
      agent: { type: "claude-desktop", version: "1.2.3" },
      action: { category: "mcp", operation: "invoke", tool: "demo/list_inbox", arguments: { server: "demo", tool: "list_inbox", annotations: { readOnlyHint: true } } },
      resource: { type: "mcp_server", name: "demo" },
    });
    await t.gw.until(() => t.s!.executions.length >= 2 || undefined);
    expect(t.s!.executions.map((e) => e.status)).toEqual(["started", "completed"]);
  }, T);

  it("destructive tool → ask → approve → forwarded exactly once with identical arguments", async () => {
    const t = await setup();
    await init(t.gw);
    const args = { amount: 1500.5, to: "IBAN DE89 3704 0044 0532 0130 00", memo: { nested: ["ü", 1, null] } };
    t.gw.send(call(11, "transfer_funds", args));
    const r = await t.gw.response(11);
    expect(r.result.content[0].text).toMatch(/Transferred 1500.5/);
    const lines = effects(t.log);
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]!.split(" transfer_funds ")[1]!)).toEqual(args);
    expect(t.s!.approvals.size).toBe(1);
    const sub = t.s!.requests.find((q) => q.path === "/v1/actions")!.body as any;
    expect(sub.policy.decision).toBe("ask");
    expect(sub.action.risk.level).toBe("high");
  }, T);

  it("denied on the phone → isError result, upstream never called, reported blocked", async () => {
    const t = await setup({ onAsk: (c) => c.server.resolve(c, "denied", null) });
    await init(t.gw);
    t.gw.send(call(12, "delete_all_emails"));
    const r = await t.gw.response(12);
    expect(r.result).toEqual({ isError: true, content: [{ type: "text", text: "Blocked by AgentGate: denied on device" }] });
    expect(effects(t.log)).toHaveLength(0);
    await t.gw.until(() => t.s!.executions.find((e) => e.status === "blocked"));
  }, T);

  it("forged approval token → blocked, not forwarded", async () => {
    const rogue = generateSigningKeyPair();
    const t = await setup({ onAsk: (c) => c.server.resolve(c, "approved", c.server.sign(c, {}, rogue.privateKeyPem)) });
    await init(t.gw);
    t.gw.send(call(13, "send_email", { to: "a@b.c", subject: "s", body: "b" }));
    const r = await t.gw.response(13);
    expect(r.result.isError).toBe(true);
    expect(r.result.content[0].text).toMatch(/bad_signature/);
    expect(effects(t.log)).toHaveLength(0);
  }, T);

  it("API unreachable → every tool call blocked, nothing forwarded; other traffic still flows", async () => {
    const t = await setup({}, true);
    await init(t.gw);
    t.gw.send(call(14, "list_inbox"));
    t.gw.send(call(15, "transfer_funds", { amount: 1, to: "x" }));
    const [a, b] = [await t.gw.response(14), await t.gw.response(15)];
    for (const r of [a, b]) {
      expect(r.result.isError).toBe(true);
      expect(r.result.content[0].text).toMatch(/^Blocked by AgentGate: /);
    }
    expect(effects(t.log)).toHaveLength(0);
    t.gw.send({ jsonrpc: "2.0", id: 16, method: "ping" });
    expect((await t.gw.response(16)).result).toEqual({});
  }, T);

  it("progress notifications while waiting for approval", async () => {
    const t = await setup({ onAsk: (c) => setTimeout(() => c.server.resolve(c, "approved", c.server.sign(c)), 800) });
    await init(t.gw);
    t.gw.send(call(17, "delete_all_emails", {}, { progressToken: "p-17" }));
    await t.gw.response(17);
    const prog = t.gw.msgs().filter((m) => m.method === "notifications/progress");
    expect(prog.length).toBeGreaterThanOrEqual(2);
    expect(prog.every((m) => m.params.progressToken === "p-17" && /Waiting for approval on your phone/.test(m.params.message))).toBe(true);
    const idx = t.gw.msgs().findIndex((m) => m.id === 17);
    expect(t.gw.msgs().findIndex((m) => m.method === "notifications/progress")).toBeLessThan(idx);
  }, T);

  it("notifications/cancelled for a pending call → approval cancelled, never forwarded, no response", async () => {
    const t = await setup({ onAsk: () => {} });
    await init(t.gw);
    t.gw.send(call(18, "delete_all_emails"));
    await t.gw.until(() => t.s!.approvals.size === 1 || undefined);
    t.gw.send({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 18, reason: "user stopped" } });
    await t.gw.until(() => t.s!.cancels.length === 1 || undefined);
    expect([...t.s!.approvals.values()][0]!.approval.status).toBe("cancelled");
    await new Promise((r) => setTimeout(r, 400));
    expect(t.gw.msgs().find((m) => m.id === 18)).toBeUndefined();
    expect(effects(t.log)).toHaveLength(0);
  }, T);

  it("concurrent calls are correlated by JSON-RPC id", async () => {
    let n = 0;
    const t = await setup({ onAsk: (c) => setTimeout(() => c.server.resolve(c, ++n === 1 ? "approved" : "denied", n === 1 ? c.server.sign(c) : null), 300) });
    await init(t.gw);
    t.gw.send(call(21, "list_inbox", { __delay_ms: 400 }));
    t.gw.send(call(22, "delete_all_emails"));
    t.gw.send(call(23, "list_inbox"));
    t.gw.send(call(24, "transfer_funds", { amount: 5, to: "y" }));
    const [r21, r22, r23, r24] = (await Promise.all([21, 22, 23, 24].map((i) => t.gw.response(i)))) as Msg[];
    expect(r21!.result.content[0].text).toMatch(/Welcome/);
    expect(r23!.result.content[0].text).toMatch(/Welcome/);
    const destructive = [r22!, r24!];
    expect(destructive.filter((r) => r.result.isError === true)).toHaveLength(1);
    expect(destructive.filter((r) => r.result.isError !== true)).toHaveLength(1);
    expect(effects(t.log)).toHaveLength(3);
  }, T);

  it("upstream crash → pending requests get errors, gateway exits and ends the session", async () => {
    const t = await setup();
    await init(t.gw);
    t.gw.send(call(30, "list_inbox", { __delay_ms: 3000 }));
    t.gw.send({ jsonrpc: "2.0", id: 31, method: "resources/list" });
    await t.gw.response(31);
    await t.gw.until(() => t.s!.executions.some((e) => e.status === "started") || undefined);
    t.gw.send({ jsonrpc: "2.0", id: 32, method: "future/slow" });
    t.gw.send({ jsonrpc: "2.0", method: "demo/crash" });
    const r30 = await t.gw.response(30);
    expect(r30.error.message).toMatch(/upstream MCP server exited/);
    const code = await t.gw.exited;
    expect(code).not.toBe(0);
    expect(t.s!.endedSessions).toHaveLength(1);
    expect(t.s!.executions.at(-1)).toMatchObject({ status: "failed" });
  }, T);

  it("client closes stdin → session ended, upstream stopped, exit 0", async () => {
    const t = await setup();
    await init(t.gw);
    t.gw.send(call(40, "list_inbox"));
    await t.gw.response(40);
    t.gw.p.stdin.end();
    expect(await t.gw.exited).toBe(0);
    expect(t.s!.endedSessions).toHaveLength(1);
  }, T);

  it("parser differential: duplicate method keys hiding tools/call are refused", async () => {
    const t = await setup();
    await init(t.gw);
    t.gw.send(`{"jsonrpc":"2.0","id":50,"method":"tools/call","params":{"name":"delete_all_emails","arguments":{}},"method":"ping"}`);
    const r = await t.gw.response(50);
    expect(r.error.message).toMatch(/Ambiguous/);
    expect(effects(t.log)).toHaveLength(0);
  }, T);
});

// ── install / uninstall ─────────────────────────────────────────────────────

describe("mcp install / uninstall", () => {
  function envFor() {
    const e = makeEnv({ server: "http://127.0.0.1:1", token: "x".repeat(24), publicKeyPem: generateSigningKeyPair().publicKeyPem });
    const home = join(dirname(e.home), "userhome");
    mkdirSync(home, { recursive: true });
    return { ...e, userHome: home };
  }
  const cli = (e: ReturnType<typeof envFor>, args: string[]) => runCli(["mcp", ...args], { home: e.home, cwd: e.work, env: { HOME: e.userHome, CODEX_HOME: join(e.userHome, ".codex") } });

  const servers = {
    demo: { command: "node", args: ["/abs/server.mjs"], env: { MCP_DEMO_LOG: "/tmp/x.log" } },
    github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"], env: { GITHUB_TOKEN: "ghp_x" }, disabled: false },
    remote: { url: "https://mcp.example.com/sse" },
  };

  const jsonCases = [
    ["claude-desktop", (h: string) => join(h, "Library", "Application Support", "Claude", "claude_desktop_config.json"), [] as string[]],
    ["cursor", (h: string) => join(h, ".cursor", "mcp.json"), [] as string[]],
  ] as const;

  for (const [client, fileOf] of jsonCases) {
    it(`${client}: wrap selected stdio servers, keep others, restore byte-for-byte`, async () => {
      const e = envFor();
      const file = fileOf(e.userHome);
      mkdirSync(dirname(file), { recursive: true });
      const original = `${JSON.stringify({ globalShortcut: "Cmd+Space", mcpServers: servers }, null, 4)}\n`;
      writeFileSync(file, original);

      expect((await cli(e, ["install", "--client", client])).code).toBe(2); // needs --server / --all
      const r = await cli(e, ["install", "--client", client, "--all"]);
      expect(r.code).toBe(0);
      expect(r.stderr).toMatch(/remote: skipped — remote \(HTTP\/SSE\) server/);
      expect(r.stderr).toMatch(/Restart/);
      const after = JSON.parse(readFileSync(file, "utf8"));
      expect(after.globalShortcut).toBe("Cmd+Space");
      expect(after.mcpServers.remote).toEqual(servers.remote);
      expect(after.mcpServers.demo.command).toMatch(/daemon\/agentgate\/bin\/agentgate\.sh$/);
      expect(after.mcpServers.demo.args).toEqual(["mcp", "wrap", "--name", "demo", "--", "node", "/abs/server.mjs"]);
      expect(after.mcpServers.demo.env).toMatchObject({ MCP_DEMO_LOG: "/tmp/x.log", AGENTGATE_HOME: e.home, AGENTGATE_NODE: process.execPath, AGENTGATE_MCP_WRAPPED: "1" });
      expect(after.mcpServers.github.disabled).toBe(false);
      expect(readFileSync(file, "utf8")).toMatch(/\n {4}"mcpServers"/); // indentation kept

      // idempotent
      const again = await cli(e, ["install", "--client", client, "--all"]);
      expect(again.stderr).toMatch(/already wrapped/);
      expect(JSON.parse(readFileSync(file, "utf8"))).toEqual(after);

      const st = await cli(e, ["status"]);
      expect(st.stdout).toMatch(/demo\s+gated by AgentGate/);

      expect((await cli(e, ["uninstall", "--client", client])).code).toBe(0);
      expect(readFileSync(file, "utf8")).toBe(original);
    }, T);
  }

  it("claude-code (.mcp.json, project): partial uninstall after user edits restores just that entry", async () => {
    const e = envFor();
    const file = join(e.work, ".mcp.json");
    writeFileSync(file, JSON.stringify({ mcpServers: servers }, null, 2));
    expect((await cli(e, ["install", "--client", "claude-code", "--project", e.work, "--server", "demo", "--server", "github"])).code).toBe(0);
    const doc = JSON.parse(readFileSync(file, "utf8"));
    doc.mcpServers.newone = { command: "x" }; // user edit after install
    writeFileSync(file, JSON.stringify(doc, null, 2));
    expect((await cli(e, ["uninstall", "--client", "claude-code", "--project", e.work, "--server", "demo"])).code).toBe(0);
    const d2 = JSON.parse(readFileSync(file, "utf8"));
    expect(d2.mcpServers.demo).toEqual(servers.demo);
    expect(d2.mcpServers.github.env.AGENTGATE_MCP_WRAPPED).toBe("1");
    expect(d2.mcpServers.newone).toEqual({ command: "x" });
    expect((await cli(e, ["uninstall", "--client", "claude-code", "--project", e.work])).code).toBe(0);
    expect(JSON.parse(readFileSync(file, "utf8")).mcpServers).toEqual({ ...servers, newone: { command: "x" } });
  }, T);

  it("codex (config.toml): edits only the server table, keeps comments/other settings, restores byte-for-byte", async () => {
    const e = envFor();
    const file = join(e.userHome, ".codex", "config.toml");
    mkdirSync(dirname(file), { recursive: true });
    const original = `# my codex config
model = "gpt-5-codex"   # favourite
approval_policy = "on-request"

[mcp_servers.demo]
command = "node"
args = ["/abs/server.mjs"]
tool_timeout_sec = 300

[mcp_servers.demo.env]
MCP_DEMO_LOG = "/tmp/x.log"

# unrelated profile
[profiles.fast]
model = "o4-mini"

[mcp_servers."remote-one"]
url = "https://mcp.example.com/mcp"
`;
    writeFileSync(file, original);
    const r = await cli(e, ["install", "--client", "codex", "--all"]);
    expect(r.code).toBe(0);
    expect(r.stderr).toMatch(/remote-one: skipped/);
    const text = readFileSync(file, "utf8");
    expect(text.startsWith(`# my codex config\nmodel = "gpt-5-codex"   # favourite\napproval_policy = "on-request"\n\n`)).toBe(true);
    expect(text).toContain(`\n# unrelated profile\n[profiles.fast]\nmodel = "o4-mini"\n\n[mcp_servers."remote-one"]\nurl = "https://mcp.example.com/mcp"\n`);
    const { parse } = await import("smol-toml");
    const doc = parse(text) as any;
    expect(doc.mcp_servers.demo.args).toEqual(["mcp", "wrap", "--name", "demo", "--", "node", "/abs/server.mjs"]);
    expect(doc.mcp_servers.demo.tool_timeout_sec).toBe(300);
    expect(doc.mcp_servers.demo.env).toMatchObject({ MCP_DEMO_LOG: "/tmp/x.log", AGENTGATE_MCP_WRAPPED: "1" });
    expect((await cli(e, ["uninstall", "--client", "codex"])).code).toBe(0);
    expect(readFileSync(file, "utf8")).toBe(original);
  }, T);

  it("refuses malformed configs and inline TOML definitions instead of guessing", async () => {
    const e = envFor();
    const cur = join(e.userHome, ".cursor", "mcp.json");
    mkdirSync(dirname(cur), { recursive: true });
    writeFileSync(cur, `{"mcpServers": [1,2]}`);
    expect((await cli(e, ["install", "--client", "cursor", "--all"])).code).toBe(1);
    expect(readFileSync(cur, "utf8")).toBe(`{"mcpServers": [1,2]}`);
    const toml = join(e.userHome, ".codex", "config.toml");
    mkdirSync(dirname(toml), { recursive: true });
    const inline = `mcp_servers = { demo = { command = "node", args = ["x"] } }\n`;
    writeFileSync(toml, inline);
    const r = await cli(e, ["install", "--client", "codex", "--all"]);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/inline\/dotted/);
    expect(readFileSync(toml, "utf8")).toBe(inline);
    expect((await cli(e, ["install", "--client", "claude-desktop", "--all"])).code).toBe(1); // no config
  }, T);
});
