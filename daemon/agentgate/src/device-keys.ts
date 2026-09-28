import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DeviceKeysResponse } from "@agentgate/protocol";
import { publicKeyFingerprint, verifyRekey } from "@agentgate/signing";
import { z } from "zod";
import type { AgentGateClient } from "./client/index.ts";
import { agentgateHome } from "./config.ts";
import { log } from "./output.ts";

/**
 * Device public keys the executors trust for phone-signed decisions (M7).
 *
 * Trust on first use, per server: a device key is pinned the first time it is seen
 * (`~/.agentgate/device-keys.json`, 0600). A DIFFERENT key later reported for a known
 * device id is refused (the server — or whoever controls it — cannot swap a phone's key);
 * revocation is sticky locally. Unknown devices are only trusted after a successful fetch
 * from the local server's loopback-only `/v1/devices/keys`.
 *
 * Key rotation (same phone, POST /v1/devices/:id/rekey): a changed key for a pinned id is
 * accepted ONLY when the server reports `rekeyed_at` newer than the pin AND a rotation proof
 * whose signature verifies against the PINNED (old) key and names exactly the new key. The
 * server alone can't forge that. Anything else (no proof, a proof by another key, a chain of
 * rotations we missed) keeps the old refusal: remove the pin to re-trust.
 */

const Pin = z.object({
  public_key: z.string(),
  fingerprint: z.string(),
  pinned_at: z.string(),
  revoked_at: z.string().nullable(),
  /** Set when the server later reported a different key for this id. */
  conflict: z.string().nullable().default(null),
});
const PinFile = z.object({ v: z.literal(1), servers: z.record(z.string(), z.record(z.string(), Pin)) });
type PinFile = z.infer<typeof PinFile>;

type Pin = z.infer<typeof Pin>;
type KeyItem = DeviceKeysResponse["items"][number];

/** Pure merge of one server-reported key into the pins (exported for tests). */
export function mergeDeviceKey(pin: Pin | undefined, k: KeyItem, now: string): { pin: Pin; change: "pinned" | "unchanged" | "rotated" | "conflict" } | null {
  let fp: string;
  try {
    fp = publicKeyFingerprint(k.public_key);
  } catch {
    return null; // malformed key from the server: never pin it
  }
  if (!pin) return { pin: { public_key: k.public_key, fingerprint: fp, pinned_at: now, revoked_at: k.revoked_at, conflict: null }, change: "pinned" };
  const next: Pin = { ...pin };
  let change: "unchanged" | "rotated" | "conflict" = "unchanged";
  if (pin.public_key !== k.public_key) {
    const proof = k.rekey_proof ?? null;
    const newer = Boolean(k.rekeyed_at) && Date.parse(k.rekeyed_at!) > Date.parse(pin.pinned_at);
    const signed =
      !!proof &&
      proof.device_id === k.device_id &&
      proof.new_public_key === k.public_key &&
      verifyRekey(proof, { publicKeyFor: (id) => (id === k.device_id ? pin.public_key : null), signatureOnly: true }).ok;
    if (newer && signed && !pin.revoked_at) {
      Object.assign(next, { public_key: k.public_key, fingerprint: fp, pinned_at: now, conflict: null });
      change = "rotated";
    } else if (!pin.conflict) {
      next.conflict = `server reported key ${fp} for ${k.device_id}, pinned ${pin.fingerprint}`;
      change = "conflict";
    }
  }
  if (k.revoked_at && !next.revoked_at) next.revoked_at = k.revoked_at; // revocation is sticky
  return { pin: next, change };
}

export const deviceKeysPath = () => join(agentgateHome(), "device-keys.json");

function load(): PinFile {
  try {
    return PinFile.parse(JSON.parse(readFileSync(deviceKeysPath(), "utf8")));
  } catch {
    return { v: 1, servers: {} };
  }
}

function save(f: PinFile) {
  mkdirSync(agentgateHome(), { recursive: true, mode: 0o700 });
  const tmp = `${deviceKeysPath()}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(f, null, 2)}\n`, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, deviceKeysPath());
}

export interface DeviceKeyLookup {
  /** Pinned, non-revoked, non-conflicting key — or null (verification then fails closed). */
  publicKeyFor(deviceId: string): string | null;
  /** Why a device has no usable key (for the block message). */
  whyNot(deviceId: string): string;
}

/** Fetch (best effort), merge into the TOFU pins, return a synchronous lookup. */
export async function resolveDeviceKeys(client: AgentGateClient, server: string): Promise<DeviceKeyLookup> {
  const file = load();
  const pins = (file.servers[server] ??= {});
  let fetched = false;
  try {
    const resp = DeviceKeysResponse.parse(await client.deviceKeys());
    fetched = true;
    const now = new Date().toISOString();
    for (const k of resp.items) {
      const m = mergeDeviceKey(pins[k.device_id], k, now);
      if (!m) continue;
      pins[k.device_id] = m.pin;
      if (m.change === "pinned") log.debug(`pinned device key ${k.device_id} ${m.pin.fingerprint}`);
      if (m.change === "rotated") log.step(`device ${k.device_id}: key rotated (signed by the pinned key) → ${m.pin.fingerprint}`);
      if (m.change === "conflict") {
        log.warn(`device ${k.device_id}: key CHANGED since it was pinned — refusing its approvals (re-pair the phone and remove it from ${deviceKeysPath()} if expected)`);
      }
    }
    save(file);
  } catch (err) {
    log.debug(`device key fetch failed (${(err as Error).message}); using pinned keys only`);
  }
  return {
    publicKeyFor(id) {
      const p = pins[id];
      return p && !p.revoked_at && !p.conflict ? p.public_key : null;
    },
    whyNot(id) {
      const p = pins[id];
      if (!p) return fetched ? `device ${id} is not a known paired device` : `device ${id} is unknown and the device key list could not be fetched`;
      if (p.revoked_at) return `device ${id} was revoked`;
      if (p.conflict) return `device ${id}: ${p.conflict} (key change after pinning is refused)`;
      return "ok";
    },
  };
}

/** New installs (agentgate setup) require phone signatures; env can force it too. */
export function requireDeviceSignatures(config: { require_device_signatures?: boolean }): boolean {
  return process.env.AGENTGATE_REQUIRE_DEVICE_SIGNATURES === "1" || config.require_device_signatures === true;
}

/** What every executor passes to gateExecution. Keys are fetched only for v2 tokens. */
export async function gateContext(
  client: AgentGateClient,
  config: { server: string; require_device_signatures?: boolean },
  token: string | null | undefined,
): Promise<{ deviceKeys?: DeviceKeyLookup; requireDeviceSignatures: boolean }> {
  const req = requireDeviceSignatures(config);
  if (!token?.startsWith("v2.")) return { requireDeviceSignatures: req };
  return { deviceKeys: await resolveDeviceKeys(client, config.server), requireDeviceSignatures: req };
}
