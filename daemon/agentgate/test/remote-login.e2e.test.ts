import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { checkServerUrl } from "../src/commands/login.ts";
import { FakeServer, type FakeServerOptions } from "./fake-server.ts";
import { makeEnv, runCli } from "./helpers.ts";

/** Multi-machine: remote `agentgate login` with phone approval, transport rules, public_url, installer. */

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const T = 30_000;
let server: FakeServer | null = null;
afterEach(async () => {
  await server?.stop();
  server = null;
});

async function fresh(opts: FakeServerOptions) {
  server = await new FakeServer(opts).start();
  const e = makeEnv({ server: server.url, token: server.token, publicKeyPem: server.keys.publicKeyPem, policy: null });
  rmSync(join(e.home, "config.json")); // a brand-new second computer
  return { s: server, ...e };
}

describe("remote agent login", () => {
  it("202 → waits for the phone → approved: pins key, saves refresh token, registers agent", async () => {
    const t = await fresh({ remoteAgentLogin: "approve" });
    const r = await runCli(["login", "--server", t.s.url, "--email", "dev@agentgate.local"], { home: t.home, cwd: t.work });
    expect(r.stderr).toMatch(/Approve this computer on your phone \(expires in [45]:\d\d\)/);
    expect(r.stderr).toMatch(/approved on your phone/);
    expect(r.code).toBe(0);
    expect(t.s.polls).toBeGreaterThanOrEqual(2);
    expect(t.s.loginBodies[0]).toMatchObject({ client: "agent", machine_name: expect.any(String) });
    const cfg = JSON.parse(readFileSync(join(t.home, "config.json"), "utf8"));
    expect(cfg.refresh_token).toMatch(/^agr_/);
    expect(cfg.signing_key.pem).toBe(t.s.keys.publicKeyPem);
    expect(cfg.agent_id).toBe("agt_test");
  }, T);

  it.each([
    ["deny", /denied on your phone/, 77],
    ["expire", /expired/, 77],
    ["no_phone", /Pair your phone first/, 1],
  ] as const)("%s → not logged in", async (mode, msg, code) => {
    const t = await fresh({ remoteAgentLogin: mode });
    const r = await runCli(["login", "--server", t.s.url], { home: t.home, cwd: t.work });
    expect(r.code).toBe(code);
    expect(r.stderr).toMatch(msg);
    expect(existsSync(join(t.home, "config.json"))).toBe(false);
  }, T);
});

describe("transport rules", () => {
  it.each([
    ["https://mac.tailnet-abc.ts.net", false, true, false],
    ["https://agentgate.example.com", false, true, false],
    ["http://localhost:8787", false, true, false],
    ["http://127.0.0.1:8787", false, true, false],
    ["http://100.101.102.103:8787", false, true, true],
    ["http://100.64.0.1", false, true, true],
    ["http://100.127.255.254", false, true, true],
    ["http://mac.tailnet-abc.ts.net:8787", false, true, true],
    ["http://100.128.0.1", false, false, false], // outside 100.64/10
    ["http://192.168.1.10:8787", false, false, false],
    ["http://192.168.1.10:8787", true, true, true],
    ["ftp://x", false, false, false],
  ] as const)("%s (insecure-lan=%s) → ok=%s note=%s", (url, lan, ok, note) => {
    const r = checkServerUrl(new URL(url), lan);
    expect(r.ok).toBe(ok);
    expect(Boolean(r.ok && r.note)).toBe(note);
  });
});

describe("public_url", () => {
  it("config set public_url → used by `agentgate pair`; server PUBLIC_URL is the fallback", async () => {
    server = await new FakeServer({ publicUrl: "https://server-side.example.com" }).start();
    const e = makeEnv({ server: server.url, token: server.token, publicKeyPem: server.keys.publicKeyPem });
    const fromServer = await runCli(["pair", "--no-qr"], { home: e.home, cwd: e.work });
    expect(fromServer.stdout).toMatch(/Server for the phone: https:\/\/server-side\.example\.com/);
    expect((await runCli(["config", "set", "public_url", "https://mine.example.com/"], { home: e.home, cwd: e.work })).code).toBe(0);
    const mine = await runCli(["pair", "--no-qr"], { home: e.home, cwd: e.work });
    expect(mine.stdout).toMatch(/Server for the phone: https:\/\/mine\.example\.com\b/);
    expect(mine.stdout).toContain("url=https%3A%2F%2Fmine.example.com&");
    expect((await runCli(["config", "set", "public_url", "not a url"], { home: e.home, cwd: e.work })).code).toBe(2);
    expect((await runCli(["config", "unset", "public_url"], { home: e.home, cwd: e.work })).code).toBe(0);
  }, T);
});

