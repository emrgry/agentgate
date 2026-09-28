import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { SELF_MANAGEMENT_RE } from "@agentgate/adapter-claude-code";
import { base64urlEncode, generateDeviceKeyPair, publicKeyFingerprint, signRekey } from "@agentgate/signing";
import { mergeDeviceKey } from "../src/device-keys.ts";
import { FakeServer } from "./fake-server.ts";
import { makeEnv, runCli, runProcess } from "./helpers.ts";

/** Re-pairing deadlock fix, executor side: pin rotation rule, `agentgate devices` fail-closed, guard. */

const rnd = (n: number) => new Uint8Array(randomBytes(n));
const T0 = Date.parse("2026-09-28T10:00:00Z");
const iso = (ms: number) => new Date(ms).toISOString();

function rotation(o: { signer?: Uint8Array } = {}) {
  const oldKp = generateDeviceKeyPair(rnd);
  const newKp = generateDeviceKeyPair(rnd);
  const proof = signRekey({ device_id: "dev_1", new_public_key: newKp.publicKey, issued_at: iso(T0), expires_at: iso(T0 + 60_000), nonce: base64urlEncode(rnd(18)) }, o.signer ?? oldKp.privateKey);
  const pin = { public_key: oldKp.publicKey, fingerprint: publicKeyFingerprint(oldKp.publicKey), pinned_at: iso(T0 - 86_400_000), revoked_at: null, conflict: null };
  const item = { device_id: "dev_1", public_key: newKp.publicKey, fingerprint: publicKeyFingerprint(newKp.publicKey), revoked_at: null, rekeyed_at: iso(T0), rekey_proof: proof };
  return { oldKp, newKp, proof, pin, item };
}

describe("executor pin rotation (TOFU)", () => {
  it("accepts a rotation newer than the pin AND signed by the pinned key", () => {
    const { pin, item, newKp } = rotation();
    const m = mergeDeviceKey(pin, item, iso(T0 + 1000))!;
    expect(m.change).toBe("rotated");
    expect(m.pin).toMatchObject({ public_key: newKp.publicKey, conflict: null });
  });
  it.each([
    ["no proof", (r: ReturnType<typeof rotation>) => ({ ...r.item, rekey_proof: null })],
    ["no rekeyed_at", (r: ReturnType<typeof rotation>) => ({ ...r.item, rekeyed_at: null })],
    ["rekeyed_at older than the pin", (r: ReturnType<typeof rotation>) => ({ ...r.item, rekeyed_at: iso(T0 - 2 * 86_400_000) })],
    ["proof names another key", (r: ReturnType<typeof rotation>) => ({ ...r.item, public_key: generateDeviceKeyPair(rnd).publicKey })],
    ["proof for another device", (r: ReturnType<typeof rotation>) => ({ ...r.item, rekey_proof: { ...r.proof, device_id: "dev_2" } })],
  ] as const)("keeps refusing: %s", (_n, mk) => {
    const r = rotation();
    const m = mergeDeviceKey(r.pin, mk(r) as never, iso(T0 + 1000))!;
    expect(m.change).toBe("conflict");
    expect(m.pin.public_key).toBe(r.pin.public_key);
    expect(m.pin.conflict).toMatch(/server reported key/);
  });
  it("keeps refusing a proof signed by any key other than the pinned one (server can't forge)", () => {
    const r = rotation({ signer: generateDeviceKeyPair(rnd).privateKey });
    expect(mergeDeviceKey(r.pin, r.item, iso(T0 + 1000))!.change).toBe("conflict");
  });
  it("a revoked pin never rotates", () => {
    const r = rotation();
    expect(mergeDeviceKey({ ...r.pin, revoked_at: iso(T0 - 1000) }, r.item, iso(T0 + 1000))!.change).toBe("conflict");
  });
});

describe("agentgate devices", () => {
  let server: FakeServer | null = null;
  afterEach(async () => {
    await server?.stop();
    server = null;
  });
  it("revoke/reset fail closed when sudo isn't confirmed; nothing is sent", async () => {
    server = await new FakeServer().start();
    const env = makeEnv({ server: server.url, token: server.token, publicKeyPem: server.keys.publicKeyPem });
    for (const args of [["devices", "reset"], ["devices", "revoke", "dev_1"]]) {
      const r = await runCli(args, { home: env.home, cwd: env.work, env: { AGENTGATE_SUDO: "/usr/bin/false" } });
      expect(r.code).not.toBe(0);
      expect(r.stderr + r.stdout).toMatch(/sudo authentication failed/);
    }
    expect(server.requests.filter((q) => q.path.startsWith("/v1/devices")).length).toBe(0);
    expect((await runCli(["devices", "frobnicate"], { home: env.home, cwd: env.work })).code).toBe(2);
  }, 30_000);

  it("agents may not run `agentgate devices` (hook guard, Claude + Codex)", async () => {
    for (const cmd of ["agentgate devices reset", "npx agentgate devices revoke dev_1", "/x/bin/agentgate.sh devices list"]) expect(SELF_MANAGEMENT_RE.test(cmd), cmd).toBe(true);
    expect(SELF_MANAGEMENT_RE.test("echo devices")).toBe(false);
    server = await new FakeServer().start();
    const env = makeEnv({ server: server.url, token: server.token, publicKeyPem: server.keys.publicKeyPem });
    const shim = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "agentgate-hook.sh");
    const input = JSON.stringify({ session_id: "t1", cwd: env.work, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "agentgate devices reset" }, tool_use_id: "c1" });
    const r = await runProcess(shim, ["--agentgate-provider=codex"], { home: env.home, cwd: env.work, input, env: { AGENTGATE_NODE: process.execPath } });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/may not run `agentgate devices`/);
    expect(server.count("POST", "/v1/actions")).toBe(0);
  }, 30_000);
});
