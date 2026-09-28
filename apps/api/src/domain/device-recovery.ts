import { lstatSync, readFileSync } from "node:fs";
import { and, eq, isNull } from "drizzle-orm";
import type { RekeyRequest } from "@agentgate/protocol";
import { verifyRekey } from "@agentgate/signing";
import { devices, pairingRequests, usedNonces, users } from "../db/schema.ts";
import type { Db } from "../db/client.ts";
import { writeAudit } from "./audit.ts";
import type { ServiceDeps } from "./context.ts";
import { DomainError } from "./errors.ts";
import { invalidateDeviceCache } from "./identity.ts";
import { revokeDeviceRefreshTokens } from "./refresh.ts";

/**
 * Device key rotation (same phone, still holding its old key) and local recovery (key lost,
 * no other device can approve). See docs/local-first.md "Re-pairing and recovery".
 */

/** Atomic single use: false if the nonce was already consumed. */
export async function consumeNonce(db: Db, nonce: string, kind: string, expiresAt: Date): Promise<boolean> {
  const r = await db.insert(usedNonces).values({ nonce: `${kind}:${nonce}`, kind, expires_at: expiresAt }).onConflictDoNothing().returning();
  return r.length === 1;
}

export async function rekeyDevice(deps: ServiceDeps, pathDeviceId: string, req: RekeyRequest): Promise<{ user: { id: string; email: string }; deviceId: string }> {
  if (req.device_id !== pathDeviceId) throw new DomainError(400, "device_mismatch", "device_id in the body must match the path");
  const [dev] = await deps.db.select().from(devices).where(eq(devices.id, pathDeviceId)).limit(1);
  // One answer for unknown / revoked / keyless: no oracle beyond "not usable".
  if (!dev || !dev.public_key) throw new DomainError(403, "rekey_rejected", "rekey rejected: unknown device");
  if (dev.revoked_at) throw new DomainError(403, "device_revoked", "this device has been revoked — pair it again");
  const now = deps.clock.now();
  const v = verifyRekey(req, { publicKeyFor: (id) => (id === dev.id ? dev.public_key : null), now });
  if (!v.ok) throw new DomainError(403, "rekey_rejected", `rekey rejected: ${v.reason}`);
  const [clash] = await deps.db.select({ id: devices.id }).from(devices).where(and(eq(devices.public_key, req.new_public_key), isNull(devices.revoked_at)));
  if (clash) throw new DomainError(409, "key_in_use", "that key already belongs to a device");
  if (!(await consumeNonce(deps.db, req.nonce, "rekey", new Date(Date.parse(req.expires_at) + 60_000)))) {
    throw new DomainError(403, "rekey_rejected", "rekey rejected: replayed");
  }
  const updated = await deps.db.transaction(async (tx) => {
    const [u] = await tx
      .update(devices)
      .set({ public_key: req.new_public_key, rekeyed_at: now, rekey_proof_json: req })
      // compare-and-swap on the old key: two concurrent rekeys can't both win
      .where(and(eq(devices.id, dev.id), eq(devices.public_key, dev.public_key!), isNull(devices.revoked_at)))
      .returning();
    if (!u) return null;
    // Sessions from before the rotation end here; the route issues a fresh refresh family.
    await revokeDeviceRefreshTokens(tx, [dev.id], now);
    await writeAudit(tx, { userId: dev.user_id, event: "device.rekeyed", payload: { device_id: dev.id, name: dev.name }, at: now });
    return u;
  });
  if (!updated) throw new DomainError(409, "rekey_conflict", "the device key changed concurrently; retry");
  invalidateDeviceCache(deps, dev.id);
  const [user] = await deps.db.select().from(users).where(eq(users.id, dev.user_id));
  return { user: { id: user!.id, email: user!.email }, deviceId: dev.id };
}

/**
 * Proof that a HUMAN ran the recovery: `agentgate devices …` runs `sudo -v` (password / Touch
 * ID) and then, via sudo, writes the one-time nonce into a root-owned file. An agent without
 * sudo can't produce a uid-0 file, so a plain curl with the agent token is refused.
 */
export type RecoveryProofCheck = (path: string, nonce: string) => boolean;

export const RECOVERY_PROOF_RE = /^\/(?:private\/)?tmp\/agentgate-recovery-[A-Za-z0-9_-]{16,64}$/;

export const rootOwnedProof: RecoveryProofCheck = (path, nonce) => {
  if (!RECOVERY_PROOF_RE.test(path)) return false;
  try {
    const st = lstatSync(path);
    if (!st.isFile() || st.uid !== 0) return false; // not a symlink, owned by root
    if (st.mode & 0o022) return false; // not group/other writable
    if (Date.now() - st.mtimeMs > 5 * 60_000) return false; // fresh
    return readFileSync(path, "utf8").trim() === nonce;
  } catch {
    return false;
  }
};

export async function recoverDevices(
  deps: ServiceDeps,
  userId: string,
  req: { action: "revoke" | "reset"; device_id?: string; nonce: string; proof_path: string },
  check: RecoveryProofCheck,
): Promise<{ revoked: string[]; expired_pairing_requests: number }> {
  if (!check(req.proof_path, req.nonce)) {
    throw new DomainError(403, "recovery_proof_required", "device recovery requires `agentgate devices` run by a human (sudo proof missing or invalid)");
  }
  if (!(await consumeNonce(deps.db, req.nonce, "recovery", new Date(deps.clock.now().getTime() + 10 * 60_000)))) {
    throw new DomainError(403, "recovery_proof_required", "recovery proof already used");
  }
  const now = deps.clock.now();
  if (req.action === "revoke") {
    if (!req.device_id) throw new DomainError(400, "device_id_required", "revoke needs a device id");
    const [row] = await deps.db.select().from(devices).where(and(eq(devices.id, req.device_id), eq(devices.user_id, userId)));
    if (!row) throw new DomainError(404, "not_found", "device not found");
    if (!row.revoked_at) {
      await deps.db.update(devices).set({ revoked_at: now, push_token: null }).where(eq(devices.id, row.id));
      await revokeDeviceRefreshTokens(deps.db, [row.id], now);
      await writeAudit(deps.db, { userId, event: "device.revoked", payload: { device_id: row.id, name: row.name, by: "local_recovery" }, at: now });
      invalidateDeviceCache(deps, row.id);
      deps.notifier.deviceRevoked(userId, row.id);
    }
    return { revoked: row.revoked_at ? [] : [row.id], expired_pairing_requests: 0 };
  }
  // reset: every device revoked, pending pairing requests expired → next pairing is a bootstrap.
  const active = await deps.db.select().from(devices).where(and(eq(devices.user_id, userId), isNull(devices.revoked_at)));
  await deps.db.update(devices).set({ revoked_at: now, push_token: null }).where(and(eq(devices.user_id, userId), isNull(devices.revoked_at)));
  await revokeDeviceRefreshTokens(deps.db, active.map((d) => d.id), now);
  const expired = await deps.db
    .update(pairingRequests)
    .set({ status: "expired", resolved_at: now })
    .where(and(eq(pairingRequests.user_id, userId), eq(pairingRequests.status, "pending")))
    .returning();
  for (const d of active) {
    invalidateDeviceCache(deps, d.id);
    deps.notifier.deviceRevoked(userId, d.id);
  }
  await writeAudit(deps.db, { userId, event: "device.recovery_reset", payload: { revoked: active.map((d) => d.id), expired_pairing_requests: expired.length }, at: now });
  return { revoked: active.map((d) => d.id), expired_pairing_requests: expired.length };
}
