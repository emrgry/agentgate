import { existsSync, statSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { generateSigningKeyPair } from "@agentgate/core";
import { afterEach, describe, expect, it } from "vitest";
import { FakeServer, type FakeServerOptions } from "./fake-server.ts";
import { makeEnv, runCli } from "./helpers.ts";

/**
 * End-to-end: the real CLI (subprocess) against an in-process fake API.
 * The invariant under test: an `ask` action NEVER runs without a valid token.
 * The probe command is `touch <file>`; "did it execute?" == "does the file exist?".
 */

let server: FakeServer | null = null;
afterEach(async () => {
  await server?.stop();
  server = null;
});

async function setup(opts: FakeServerOptions = {}, policy?: string | null) {
  server = await new FakeServer(opts).start();
  const env = makeEnv({ server: server.url, token: server.token, publicKeyPem: server.keys.publicKeyPem, policy });
  return { s: server, ...env, probe: join(env.work, "executed.txt") };
}

async function closedPort(): Promise<number> {
  const srv = createServer();
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as { port: number }).port;
  await new Promise<void>((r) => srv.close(() => r()));
  return port;
}

const T = 30_000;

describe("fail closed", () => {
  it("server unreachable → ask action is not executed (exit 77)", async () => {
    const port = await closedPort();
    const keys = generateSigningKeyPair();
    const env = makeEnv({ server: `http://127.0.0.1:${port}`, token: "x".repeat(24), publicKeyPem: keys.publicKeyPem });
    const probe = join(env.work, "executed.txt");
    const r = await runCli(["request", "--", "touch", probe], { home: env.home, cwd: env.work });
    expect(r.code).toBe(77);
    expect(existsSync(probe)).toBe(false);
    expect(r.stderr).toMatch(/server unreachable/);
  }, T);

  it("server unreachable → even an allow action is blocked (no unaudited execution)", async () => {
    const port = await closedPort();
    const keys = generateSigningKeyPair();
    const env = makeEnv({ server: `http://127.0.0.1:${port}`, token: "x".repeat(24), publicKeyPem: keys.publicKeyPem });
    const r = await runCli(["request", "--", "echo", "should-not-print"], { home: env.home, cwd: env.work });
    expect(r.code).toBe(77);
    expect(r.stdout).not.toContain("should-not-print");
  }, T);

  it("WebSocket rejected → action is never submitted or executed", async () => {
    const { s, home, work, probe } = await setup({ wsRejectStatus: 503 });
    const r = await runCli(["request", "--", "touch", probe], { home, cwd: work });
    expect(r.code).toBe(77);
    expect(existsSync(probe)).toBe(false);
    expect(s.count("POST", "/v1/actions")).toBe(0); // WS is opened FIRST
    expect(s.endedSessions).toHaveLength(1);
  }, T);

  it("not logged in → blocked", async () => {
    const { home, work, probe } = await setup();
    const r = await runCli(["logout"], { home, cwd: work });
    expect(r.code).toBe(0);
    const r2 = await runCli(["request", "--", "touch", probe], { home, cwd: work });
    expect(r2.code).toBe(77);
    expect(existsSync(probe)).toBe(false);
  }, T);

  it("invalid local policy file → blocked (no fallback to default)", async () => {
    const { home, work, probe } = await setup({}, "rules: [ { match: {}, decision: maybe } ]\n");
    const r = await runCli(["request", "--", "touch", probe], { home, cwd: work });
    expect(r.code).toBe(77);
    expect(existsSync(probe)).toBe(false);
  }, T);
});

describe("approval flow", () => {
  it("approved with a valid token → executes, reports lifecycle, ends session", async () => {
    const { s, home, work, probe } = await setup();
    const r = await runCli(["request", "--", "touch", probe], { home, cwd: work });
    expect(r.stderr).toMatch(/Waiting for approval on your phone… \(apr_/);
    expect(r.stderr).toMatch(/approved by device dev_test_phone/);
    expect(r.code).toBe(0);
    expect(existsSync(probe)).toBe(true);
    expect(s.executions.map((e) => e.status)).toEqual(["started", "completed"]);
    expect(s.executions[1]!.exit_code).toBe(0);
    expect(s.endedSessions).toHaveLength(1);
    // nonce persisted under AGENTGATE_HOME
    expect(statSync(join(home, "nonces")).isDirectory()).toBe(true);
  }, T);

  it("denied on device → not executed (77), reported blocked", async () => {
    const { s, home, work, probe } = await setup({ onAsk: (c) => c.server.resolve(c, "denied", null) });
    const r = await runCli(["request", "--", "touch", probe], { home, cwd: work });
    expect(r.code).toBe(77);
    expect(existsSync(probe)).toBe(false);
    expect(r.stderr).toMatch(/denied on device/);
    expect(s.executions.map((e) => e.status)).toEqual(["blocked"]);
  }, T);

  for (const status of ["expired", "cancelled"] as const) {
    it(`${status} → not executed (77)`, async () => {
      const { home, work, probe } = await setup({ onAsk: (c) => c.server.resolve(c, status, null) });
      const r = await runCli(["request", "--", "touch", probe], { home, cwd: work });
      expect(r.code).toBe(77);
      expect(existsSync(probe)).toBe(false);
    }, T);
  }

  it("token signed by a different key (forged) → bad_signature, not executed", async () => {
    const rogue = generateSigningKeyPair();
    const { s, home, work, probe } = await setup({
      onAsk: (c) => c.server.resolve(c, "approved", c.server.sign(c, {}, rogue.privateKeyPem)),
    });
    const r = await runCli(["request", "--", "touch", probe], { home, cwd: work });
    expect(r.code).toBe(77);
    expect(existsSync(probe)).toBe(false);
    expect(r.stderr).toMatch(/bad_signature/);
    expect(s.executions.at(-1)?.status).toBe("blocked");
  }, T);

  it("token bound to a different action hash → hash_mismatch, not executed", async () => {
    const { home, work, probe } = await setup({
      onAsk: (c) => c.server.resolve(c, "approved", c.server.sign(c, { action_hash: "0".repeat(64) })),
    });
    const r = await runCli(["request", "--", "touch", probe], { home, cwd: work });
    expect(r.code).toBe(77);
    expect(existsSync(probe)).toBe(false);
    expect(r.stderr).toMatch(/hash_mismatch/);
  }, T);

  it("expired token → not executed", async () => {
    const { home, work, probe } = await setup({
      onAsk: (c) => c.server.resolve(c, "approved", c.server.sign(c, { expires_at: new Date(Date.now() - 1000).toISOString() })),
    });
    const r = await runCli(["request", "--", "touch", probe], { home, cwd: work });
    expect(r.code).toBe(77);
    expect(existsSync(probe)).toBe(false);
    expect(r.stderr).toMatch(/expired/);
  }, T);

  it("approved but no token → not executed", async () => {
    const { home, work, probe } = await setup({ onAsk: (c) => c.server.resolve(c, "approved", null) });
    const r = await runCli(["request", "--", "touch", probe], { home, cwd: work });
    expect(r.code).toBe(77);
    expect(existsSync(probe)).toBe(false);
    expect(r.stderr).toMatch(/no_token/);
  }, T);

  it("no decision → times out at TTL + grace, re-checks via GET, not executed", async () => {
    const { s, home, work, probe } = await setup({ onAsk: () => {}, approvalWindowMs: 1_000 });
    const r = await runCli(["request", "--", "touch", probe], {
      home,
      cwd: work,
      env: { AGENTGATE_DEV: "1", AGENTGATE_WAIT_GRACE_MS: "300" },
    });
    expect(r.code).toBe(77);
    expect(existsSync(probe)).toBe(false);
    expect(r.stderr).toMatch(/timed out/);
    expect(s.count("GET", "/v1/approvals/")).toBeGreaterThanOrEqual(1);
  }, T);

  it("WS drops, decision made while offline → reconnect re-fetches GET and honors it", async () => {
    const { s, home, work, probe } = await setup({
      onAsk: (c) => {
        c.server.resolve(c, "denied", null, { broadcast: false });
        c.server.dropSockets(c.sessionId);
      },
    });
    const r = await runCli(["request", "--", "touch", probe], { home, cwd: work });
    expect(r.code).toBe(77);
    expect(existsSync(probe)).toBe(false);
    expect(s.wsConnects).toBeGreaterThanOrEqual(2);
    expect(s.count("GET", "/v1/approvals/")).toBeGreaterThanOrEqual(1);
  }, T);

  it("SIGINT while waiting → exit 130, not executed, session ended (approval cancelled)", async () => {
    const { s, home, work, probe } = await setup({ onAsk: () => {} });
    const r = await runCli(["request", "--", "touch", probe], {
      home,
      cwd: work,
      onStderr: (chunk, child) => {
        if (chunk.includes("Waiting for approval")) setTimeout(() => child.kill("SIGINT"), 100);
      },
    });
    expect(r.code).toBe(130);
    expect(existsSync(probe)).toBe(false);
    expect(s.endedSessions).toHaveLength(1);
    const approval = [...s.approvals.values()][0]!.approval;
    expect(approval.status).toBe("cancelled");
  }, T);
});

describe("tamper hook (AGENTGATE_DEV=1 + AGENTGATE_TAMPER_COMMAND)", () => {
  it("modified command after approval → hash_mismatch, neither command runs", async () => {
    const { s, home, work, probe } = await setup();
    const tampered = join(work, "tampered.txt");
    const r = await runCli(["request", "--", "touch", probe], {
      home,
      cwd: work,
      env: { AGENTGATE_DEV: "1", AGENTGATE_TAMPER_COMMAND: `touch ${tampered}` },
    });
    expect(r.code).toBe(77);
    expect(existsSync(probe)).toBe(false);
    expect(existsSync(tampered)).toBe(false);
    expect(r.stderr).toMatch(/hash_mismatch/);
    expect(s.executions.at(-1)?.status).toBe("blocked");
    expect(s.executions.at(-1)?.detail).toMatch(/hash_mismatch/);
  }, T);

  it("is ignored without AGENTGATE_DEV=1", async () => {
    const { home, work, probe } = await setup();
    const tampered = join(work, "tampered.txt");
    const r = await runCli(["request", "--", "touch", probe], {
      home,
      cwd: work,
      env: { AGENTGATE_TAMPER_COMMAND: `touch ${tampered}` },
    });
    expect(r.code).toBe(0);
    expect(existsSync(probe)).toBe(true);
    expect(existsSync(tampered)).toBe(false);
  }, T);
});

describe("allow / deny", () => {
  it("policy deny → reported for audit, not executed (77)", async () => {
    const { s, home, work } = await setup();
    const victim = join(work, "victim");
    const r = await runCli(["request", "--", `rm -rf ${victim} && touch ${join(work, "x")}`], { home, cwd: work });
    expect(r.code).toBe(77);
    expect(existsSync(join(work, "x"))).toBe(false);
    const submitted = s.requests.find((q) => q.path === "/v1/actions")!.body as { policy: { decision: string } };
    expect(submitted.policy.decision).toBe("deny");
    expect(s.executions.map((e) => e.status)).toEqual(["blocked"]);
  }, T);

  it("policy allow → executes without approval and propagates the exit code", async () => {
    const { s, home, work } = await setup();
    const r = await runCli(["request", "--", "echo hello; exit 3"], { home, cwd: work });
    expect(r.stdout).toContain("hello");
    expect(r.code).toBe(3);
    expect(s.approvals.size).toBe(0);
    expect(s.executions.map((e) => [e.status, e.exit_code ?? null])).toEqual([
      ["started", null],
      ["failed", 3],
    ]);
  }, T);
});

describe("login", () => {
  it("logs in, pins the key, registers the agent, writes config 0600", async () => {
    server = await new FakeServer().start();
    const env = makeEnv({ server: "http://unused.invalid", token: "x".repeat(24), publicKeyPem: "", policy: null });
    const { rmSync, readFileSync } = await import("node:fs");
    rmSync(join(env.home, "config.json"));
    const r = await runCli(["login", "--server", server.url], { home: env.home, cwd: env.work });
    expect(r.code).toBe(0);
    const cfgPath = join(env.home, "config.json");
    expect(statSync(cfgPath).mode & 0o777).toBe(0o600);
    const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
    expect(cfg.signing_key.pem).toBe(server.keys.publicKeyPem);
    expect(cfg.agent_id).toBe("agt_test");
    expect(cfg.machine_id).toMatch(/^mch_/);
    const agentReq = server.requests.find((q) => q.path === "/v1/agents")!.body as { type: string };
    expect(agentReq.type).toBe("cli");

    const shown = await runCli(["config"], { home: env.home, cwd: env.work });
    expect(shown.stdout).not.toContain(server.token);

    const st = await runCli(["status"], { home: env.home, cwd: env.work });
    expect(st.code).toBe(0);
    expect(st.stdout).toMatch(/ping\/pong/);
  }, T);
});
