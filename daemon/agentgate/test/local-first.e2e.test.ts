import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { computeActionHash } from "@agentgate/core";
import type { DecisionPayloadV2 } from "@agentgate/protocol";
import { generateDeviceKeyPair, publicKeyFingerprint, signDecision, verifyServerHello } from "@agentgate/signing";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { FakeServer, type AskContext, type FakeServerOptions } from "./fake-server.ts";
import { BIN, makeEnv, runCli, runProcess } from "./helpers.ts";

/** M7 local-first: `agentgate setup`, pairing v2, phone-signed decisions at the executor. */

const T = 90_000;
const rnd = (n: number) => new Uint8Array(randomBytes(n));
const b64 = (n: number) => Buffer.from(rnd(n)).toString("base64url");
const FAKE_LAUNCHCTL = join(dirname(fileURLToPath(import.meta.url)), "fake-launchctl.mjs");

async function freePort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const p = (s.address() as { port: number }).port;
  await new Promise<void>((r) => s.close(() => r()));
  return p;
}

// ── executor verification (fake API relays whatever token the test crafts) ──────────

let server: FakeServer | null = null;
afterEach(async () => {
  await server?.stop();
  server = null;
});

const phoneA = generateDeviceKeyPair(rnd);
const phoneB = generateDeviceKeyPair(rnd);
const keyItem = (id: string, pub: string, revoked: string | null = null) => ({ device_id: id, public_key: pub, fingerprint: publicKeyFingerprint(pub), revoked_at: revoked });

function payload(c: AskContext, over: Partial<DecisionPayloadV2> = {}): DecisionPayloadV2 {
  const now = Date.now();
  return {
    v: 2,
    approval_id: c.approval.approval_id,
    action_id: c.action.action_id,
    session_id: c.sessionId,
    action_hash: c.actionHash,
    decision: "approve",
    device_id: "dev_A",
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + 60_000).toISOString(),
    nonce: b64(18),
    ...over,
  };
}

async function setupFake(onAsk: FakeServerOptions["onAsk"], requireSig = true) {
  server = await new FakeServer({ onAsk }).start();
  server.deviceKeys = [keyItem("dev_A", phoneA.publicKey), keyItem("dev_B", phoneB.publicKey)];
  const e = makeEnv({ server: server.url, token: server.token, publicKeyPem: server.keys.publicKeyPem });
  if (requireSig) {
    const p = join(e.home, "config.json");
    writeFileSync(p, JSON.stringify({ ...JSON.parse(readFileSync(p, "utf8")), require_device_signatures: true }), { mode: 0o600 });
  }
  return { s: server, ...e, probe: join(e.work, "ran.txt") };
}

const relay = (make: (c: AskContext) => string) => (c: AskContext) => c.server.resolve(c, "approved", make(c));

describe("executor: phone-signed decisions", () => {
  it("valid decision signed by a pinned device → runs; device keys pinned 0600", async () => {
    const t = await setupFake(relay((c) => signDecision(payload(c), phoneA.privateKey)));
    const r = await runCli(["request", "--", `touch ${t.probe}`], { home: t.home, cwd: t.work });
    expect(r.stderr).not.toMatch(/BLOCKED/);
    expect(r.code).toBe(0);
    expect(existsSync(t.probe)).toBe(true);
    const pins = JSON.parse(readFileSync(join(t.home, "device-keys.json"), "utf8"));
    expect(pins.servers[t.s.url].dev_A.public_key).toBe(phoneA.publicKey);
    expect(statSync(join(t.home, "device-keys.json")).mode & 0o777).toBe(0o600);
  }, T);

  const rejects: Array<[string, (c: AskContext) => string, RegExp]> = [
    ["forged (unknown key)", (c) => signDecision(payload(c), generateDeviceKeyPair(rnd).privateKey), /\[token_bad_signature\]/],
    ["signed by device B claiming device A", (c) => signDecision(payload(c), phoneB.privateKey), /\[token_bad_signature\]/],
    ["tampered action hash", (c) => signDecision(payload(c, { action_hash: "0".repeat(64) }), phoneA.privateKey), /\[token_hash_mismatch\]/],
    ["wrong approval id", (c) => signDecision(payload(c, { approval_id: "apr_someone_else" }), phoneA.privateKey), /\[token_approval_mismatch\]/],
    [
      "expired",
      (c) => signDecision(payload(c, { issued_at: new Date(Date.now() - 120_000).toISOString(), expires_at: new Date(Date.now() - 60_000).toISOString() }), phoneA.privateKey),
      /\[token_expired\]/,
    ],
    ["a signed DENY relayed as approval", (c) => signDecision(payload(c, { decision: "deny" }), phoneA.privateKey), /\[token_not_approved\]/],
    ["unknown device id", (c) => signDecision(payload(c, { device_id: "dev_ghost" }), phoneA.privateKey), /\[token_unknown_device\].*not a known paired device/],
    ["v1 server-signed token when signatures are required", (c) => c.server.sign(c), /\[token_v1_not_accepted\]/],
  ];
  for (const [name, make, reason] of rejects) {
    it(`rejects: ${name} → 77, not executed`, async () => {
      const t = await setupFake(relay(make));
      const r = await runCli(["request", "--", `touch ${t.probe}`], { home: t.home, cwd: t.work });
      expect(r.code).toBe(77);
      expect(r.stderr).toMatch(reason);
      expect(existsSync(t.probe)).toBe(false);
    }, T);
  }

  it("legacy v1 tokens are accepted when signatures are NOT required", async () => {
    const t = await setupFake(relay((c) => c.server.sign(c)), false);
    const r = await runCli(["request", "--", `touch ${t.probe}`], { home: t.home, cwd: t.work });
    expect(r.code).toBe(0);
  }, T);

  it("replay: the same signed decision cannot run twice (nonce)", async () => {
    let saved: string | null = null;
    const t = await setupFake(relay((c) => (saved = signDecision(payload(c), phoneA.privateKey))));
    expect((await runCli(["request", "--", `touch ${t.probe}`], { home: t.home, cwd: t.work })).code).toBe(0);
    // Re-verify the consumed token through the gate with the persistent nonce store.
    const { gateExecution } = await import("../src/verify.ts");
    const { FileNonceStore } = await import("../src/nonce-store.ts");
    const body = JSON.parse(Buffer.from(saved!.split(".")[1]!, "base64url").toString());
    const draftFor = t.s.requests.find((q) => q.path === "/v1/actions")!.body as any;
    const again = gateExecution({
      token: saved,
      executable: draftFor.action,
      publicKeyPem: t.s.keys.publicKeyPem,
      approvalId: body.approval_id,
      actionId: body.action_id,
      sessionId: body.session_id,
      nonceStore: new FileNonceStore(join(t.home, "nonces")),
      deviceKeys: { publicKeyFor: (id) => (id === "dev_A" ? phoneA.publicKey : null), whyNot: () => "" },
      requireDeviceSignatures: true,
    });
    expect(computeActionHash(draftFor.action)).toBe(body.action_hash);
    expect(again).toMatchObject({ ok: false, reason: "replayed" });
  }, T);

  it("key change after pinning → refused", async () => {
    const t = await setupFake(relay((c) => signDecision(payload(c), phoneA.privateKey)));
    expect((await runCli(["request", "--", `touch ${t.probe}`], { home: t.home, cwd: t.work })).code).toBe(0); // pins A
    const evil = generateDeviceKeyPair(rnd);
    t.s.deviceKeys = [keyItem("dev_A", evil.publicKey)]; // server now claims a new key for dev_A
    t.s.opts.onAsk = relay((c) => signDecision(payload(c), evil.privateKey));
    const r = await runCli(["request", "--", `touch ${t.probe}.2`], { home: t.home, cwd: t.work });
    expect(r.code).toBe(77);
    expect(r.stderr).toMatch(/key change after pinning is refused/);
    expect(existsSync(`${t.probe}.2`)).toBe(false);
  }, T);

  it("revoked device → refused (and stays refused even if the server forgets the revocation)", async () => {
    const t = await setupFake(relay((c) => signDecision(payload(c), phoneA.privateKey)));
    t.s.deviceKeys = [keyItem("dev_A", phoneA.publicKey, new Date().toISOString())];
    const r = await runCli(["request", "--", `touch ${t.probe}`], { home: t.home, cwd: t.work });
    expect(r.code).toBe(77);
    expect(r.stderr).toMatch(/was revoked/);
    t.s.deviceKeys = [keyItem("dev_A", phoneA.publicKey)];
    expect((await runCli(["request", "--", `touch ${t.probe}`], { home: t.home, cwd: t.work })).code).toBe(77);
  }, T);

  it("hook + exec (Claude Code path) verify v2 at the real execution boundary", async () => {
    const t = await setupFake(relay((c) => signDecision(payload(c), phoneA.privateKey)));
    const hookShim = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "agentgate-hook.sh");
    const input = JSON.stringify({ session_id: "c1", cwd: t.work, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: `touch ${t.probe}` }, tool_use_id: "t1", transcript_path: "/t" });
    const h = await runProcess(hookShim, [], { home: t.home, cwd: t.work, input, env: { AGENTGATE_NODE: process.execPath } });
    expect(h.code).toBe(0);
    const wrapped = JSON.parse(h.stdout).hookSpecificOutput.updatedInput.command;
    const x = await runProcess("/bin/sh", ["-c", wrapped], { home: t.home, cwd: t.work });
    expect(x.code).toBe(0);
    expect(existsSync(t.probe)).toBe(true);
  }, T);
});

// ── `agentgate setup` against the REAL local-first API (started by a fake launchctl) ─

describe("agentgate setup (real local API, fake launchd)", () => {
  let env: ReturnType<typeof makeEnv> & { userHome: string; port: number; launchd: string };
  const run = (args: string[], extra: Record<string, string> = {}) =>
    runCli(args, {
      home: env.home,
      cwd: env.work,
      env: {
        HOME: env.userHome,
        AGENTGATE_LAUNCHCTL: FAKE_LAUNCHCTL,
        AGENTGATE_SETUP_PLATFORM: "darwin",
        FAKE_LAUNCHD_DIR: env.launchd,
        FAKE_LAUNCHD_EXTRA_ENV: JSON.stringify({ AGENTGATE_SESSION_ID: "" }),
        ...extra,
      },
    });

  beforeAll(async () => {
    const e = makeEnv({ server: "http://127.0.0.1:1", token: "x".repeat(24), publicKeyPem: "x", policy: null });
    const root = dirname(e.home);
    const userHome = join(root, "userhome");
    mkdirSync(userHome, { recursive: true });
    // setup must start from an empty AGENTGATE_HOME (no pre-baked config)
    const home = join(root, "aghome");
    env = { ...e, home, userHome, port: await freePort(), launchd: join(root, "launchd") };
    chmodSync(FAKE_LAUNCHCTL, 0o755);
  }, T);

  afterAll(async () => {
    if (env) await run(["uninstall-server"]);
  }, T);

  it("setup: server dirs 0700, launchd agent, loopback login without email, v2 QR whose fp matches the server hello", async () => {
    const r = await run(["setup", "--port", String(env.port), "--no-pair"]);
    expect([r.code, r.stderr.slice(-2000)]).toEqual([0, expect.any(String)]);
    for (const d of ["server", "server/data", "server/secrets", "server/logs"]) expect(statSync(join(env.home, d)).mode & 0o777).toBe(0o700);
    const plist = readFileSync(join(env.userHome, "Library", "LaunchAgents", "dev.agentgate.server.plist"), "utf8");
    expect(plist).toContain("<string>serve</string>");
    expect(plist).toContain(`<key>AGENTGATE_HOME</key><string>${env.home}</string>`);
    const cfg = JSON.parse(readFileSync(join(env.home, "config.json"), "utf8"));
    expect(cfg).toMatchObject({ email: "owner@agentgate.local", require_device_signatures: true });
    expect(readFileSync(join(env.launchd, "calls.log"), "utf8")).toMatch(/^bootstrap gui\/\d+ /m);

    const pair = await run(["pair", "--no-qr"]);
    expect(pair.code).toBe(0);
    const link = new URL(pair.stdout.match(/agentgate:\/\/pair\?\S+/)![0]);
    expect(link.searchParams.get("v")).toBe("2");
    expect(link.searchParams.get("email")).toBeNull(); // local-first: no email
    const fp = link.searchParams.get("fp")!;
    const challenge = b64(32);
    const hello = await (await fetch(`http://127.0.0.1:${env.port}/v1/pairing/hello`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ challenge }) })).json();
    expect(verifyServerHello(challenge, hello.signature, hello.server_public_key, fp)).toBe(true);
    expect(verifyServerHello(challenge, hello.signature, hello.server_public_key, publicKeyFingerprint(phoneA.publicKey))).toBe(false);
    expect(hello.owner.display_name.length).toBeGreaterThan(0);
  }, T);

  it("setup again is idempotent (same server config, no second bootstrap, still one owner)", async () => {
    const before = readFileSync(join(env.home, "server", "server.json"), "utf8");
    const r = await run(["setup", "--no-pair"]);
    expect(r.code).toBe(0);
    expect(r.stderr).toMatch(/already running/);
    expect(readFileSync(join(env.home, "server", "server.json"), "utf8")).toBe(before);
    expect(readFileSync(join(env.launchd, "calls.log"), "utf8").match(/^bootstrap /gm)).toHaveLength(1);
  }, T);

  it("end to end: pair a test phone (device key), request → phone-signed approve → runs; deny → blocked", async () => {
    const base = `http://127.0.0.1:${env.port}`;
    const pair = await run(["pair", "--no-qr"]);
    const code = new URL(pair.stdout.match(/agentgate:\/\/pair\?\S+/)![0]).searchParams.get("code");
    const phone = generateDeviceKeyPair(rnd);
    const login = await (
      await fetch(`${base}/v1/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client: "device", pairing_code: code, device_name: "Test iPhone", device_public_key: phone.publicKey }) })
    ).json();
    expect(login.device_id).toMatch(/^dev_/);
    const auth = { authorization: `Bearer ${login.access_token}`, "content-type": "application/json" };

    async function decideNext(decision: "approve" | "deny") {
      for (let i = 0; i < 200; i++) {
        const inbox = await (await fetch(`${base}/v1/approvals?status=pending`, { headers: auth })).json();
        const item = inbox.items?.[0];
        if (item) {
          const now = Date.now();
          const signed = signDecision(
            {
              v: 2,
              approval_id: item.approval.approval_id,
              action_id: item.action.action_id,
              session_id: item.action.session_id,
              action_hash: item.action_hash,
              decision,
              device_id: login.device_id,
              issued_at: new Date(now).toISOString(),
              expires_at: new Date(Math.min(now + 60_000, Date.parse(item.approval.expires_at))).toISOString(),
              nonce: b64(18),
            },
            phone.privateKey,
          );
          const r = await fetch(`${base}/v1/approvals/${item.approval.approval_id}/${decision}`, { method: "POST", headers: auth, body: JSON.stringify({ device_id: login.device_id, signed_decision: signed }) });
          expect(r.status).toBe(200);
          return;
        }
        await new Promise((r) => setTimeout(r, 100));
      }
      throw new Error("no pending approval appeared");
    }

    writeFileSync(join(env.home, "policy.yaml"), "version: 1\nrules:\n  - { id: ask-touch, match: { command_prefix: touch }, decision: ask }\n");
    const probe = join(env.work, "e2e.txt");
    const [r] = await Promise.all([run(["request", "--", `touch ${probe}`]), decideNext("approve")]);
    expect([r.code, r.stderr.match(/BLOCKED.*/)?.[0] ?? null]).toEqual([0, null]);
    expect(existsSync(probe)).toBe(true);

    const probe2 = join(env.work, "e2e-denied.txt");
    const [d] = await Promise.all([run(["request", "--", `touch ${probe2}`]), decideNext("deny")]);
    expect(d.code).toBe(77);
    expect(d.stderr).toMatch(/BLOCKED \[device_denied\]/);
    expect(existsSync(probe2)).toBe(false);
  }, T);

  it("server status / stop / uninstall-server keeps data unless --purge", async () => {
    const st = await run(["server", "status"]);
    expect(st.stdout).toMatch(/healthy/);
    expect((await run(["uninstall-server"])).code).toBe(0);
    expect(existsSync(join(env.home, "server", "data"))).toBe(true);
    expect(existsSync(join(env.userHome, "Library", "LaunchAgents", "dev.agentgate.server.plist"))).toBe(false);
    expect((await run(["uninstall-server", "--purge"])).code).toBe(0);
    expect(existsSync(join(env.home, "server"))).toBe(false);
  }, T);
});

void BIN;
