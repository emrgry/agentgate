import { publicKeyFingerprint } from "@agentgate/signing";
import { and, asc, eq, isNull, ne, sql } from "drizzle-orm";
import { newId } from "@agentgate/core";
import type { Agent, Device, DeviceSummary, RekeyRequest } from "@agentgate/protocol";
import type { Db } from "../db/client.ts";
import { agents, devices, users, type DeviceRow, type UserRow } from "../db/schema.ts";
import { writeAudit } from "./audit.ts";
import type { ServiceDeps } from "./context.ts";
import { DomainError, forbidden, notFound } from "./errors.ts";
import { toAgent, toDevice } from "./mappers.ts";
import { revokeDeviceRefreshTokens } from "./refresh.ts";

/** The single owner of a local-first server (M7). */
export const OWNER_EMAIL = "owner@agentgate.local";

export async function ensureOwner(deps: ServiceDeps, displayName: string): Promise<UserRow> {
  const [row] = await deps.db
    .insert(users)
    .values({ id: newId("usr"), email: OWNER_EMAIL, display_name: displayName, created_at: deps.clock.now() })
    .onConflictDoUpdate({ target: users.email, set: { display_name: displayName } })
    .returning();
  return row!;
}

/** Dev login: upsert the user by (case-insensitive) email. */
export async function upsertUser(deps: ServiceDeps, email: string): Promise<UserRow> {
  const normalized = email.trim().toLowerCase();
  const [row] = await deps.db
    .insert(users)
    .values({ id: newId("usr"), email: normalized, created_at: deps.clock.now() })
    .onConflictDoUpdate({ target: users.email, set: { email: sql`excluded.email` } })
    .returning();
  return row!;
}

export async function userExists(deps: ServiceDeps, userId: string): Promise<boolean> {
  const rows = await deps.db.select({ id: users.id }).from(users).where(eq(users.id, userId)).limit(1);
  return rows.length > 0;
}

/**
 * Registers a device. Idempotent per (user, push_token): re-registering the same push
 * token updates name/platform instead of creating a duplicate device.
 */
export async function registerDevice(
  deps: ServiceDeps,
  userId: string,
  input: { name: string; platform: string; push_token: string | null },
): Promise<{ device: Device; created: boolean }> {
  const now = deps.clock.now();
  return deps.db.transaction(async (tx) => {
    if (input.push_token) {
      const [existing] = await tx
        .update(devices)
        .set({ name: input.name, platform: input.platform, last_seen_at: now })
        .where(and(eq(devices.user_id, userId), eq(devices.push_token, input.push_token)))
        .returning();
      if (existing) return { device: toDevice(existing), created: false };
    }
    const [row] = await tx
      .insert(devices)
      .values({
        id: newId("dev"),
        user_id: userId,
        name: input.name,
        platform: input.platform,
        push_token: input.push_token,
        created_at: now,
        last_seen_at: now,
      })
      .returning();
    await writeAudit(tx, {
      userId,
      event: "device.registered",
      payload: { device_id: row!.id, name: row!.name, platform: row!.platform },
      at: now,
    });
    return { device: toDevice(row!), created: true };
  });
}

/** Throws 403 unless the device exists and belongs to the user. */
export async function requireOwnedDevice(deps: ServiceDeps, userId: string, deviceId: string) {
  const [row] = await deps.db
    .select()
    .from(devices)
    .where(and(eq(devices.id, deviceId), eq(devices.user_id, userId)))
    .limit(1);
  if (!row) throw forbidden("device does not belong to this user");
  if (row.revoked_at) throw new DomainError(403, "device_revoked", "this device has been revoked");
  return row;
}

/** Device-status cache for token checks (per deps object; invalidated on revoke). */
const deviceCache = new WeakMap<ServiceDeps, Map<string, { userId: string; revoked: boolean; at: number }>>();
const DEVICE_CACHE_MS = 5_000;

export function invalidateDeviceCache(deps: ServiceDeps, deviceId: string) {
  deviceCache.get(deps)?.delete(deviceId);
}

/** True iff the device exists, belongs to the user and is not revoked. */
export async function deviceTokenValid(deps: ServiceDeps, userId: string, deviceId: string): Promise<boolean> {
  let cache = deviceCache.get(deps);
  if (!cache) deviceCache.set(deps, (cache = new Map()));
  const hit = cache.get(deviceId);
  const now = Date.now();
  if (hit && now - hit.at < DEVICE_CACHE_MS) return hit.userId === userId && !hit.revoked;
  const [row] = await deps.db
    .select({ user_id: devices.user_id, revoked_at: devices.revoked_at })
    .from(devices)
    .where(eq(devices.id, deviceId))
    .limit(1);
  if (!row) {
    cache.delete(deviceId);
    return false;
  }
  cache.set(deviceId, { userId: row.user_id, revoked: row.revoked_at !== null, at: now });
  return row.user_id === userId && row.revoked_at === null;
}

/** Fingerprint of a raw Ed25519 key: first 16 bytes of SHA-256(raw), base64url (22 chars). */
export function keyFingerprint(rawB64url: string): string {
  return publicKeyFingerprint(rawB64url);
}

/** Validates a device public key (raw 32-byte Ed25519, base64url). */
export function assertDeviceKey(k: string): string {
  try {
    publicKeyFingerprint(k); // strict: base64url, 32 bytes, valid curve point
  } catch {
    throw new DomainError(400, "invalid_device_key", "device_public_key must be a raw 32-byte Ed25519 public key, base64url");
  }
  return k;
}

export async function listDeviceKeys(deps: ServiceDeps, userId: string) {
  const rows = await deps.db
    .select({ id: devices.id, public_key: devices.public_key, revoked_at: devices.revoked_at, rekeyed_at: devices.rekeyed_at, rekey_proof: devices.rekey_proof_json })
    .from(devices)
    .where(and(eq(devices.user_id, userId), sql`${devices.public_key} IS NOT NULL`))
    .orderBy(asc(devices.created_at));
  return rows.map((r) => ({
    device_id: r.id,
    public_key: r.public_key!,
    fingerprint: keyFingerprint(r.public_key!),
    revoked_at: r.revoked_at ? r.revoked_at.toISOString() : null,
    rekeyed_at: r.rekeyed_at ? r.rekeyed_at.toISOString() : null,
    rekey_proof: (r.rekey_proof as RekeyRequest | null) ?? null,
  }));
}

export async function countActiveDevices(db: Db, userId: string): Promise<number> {
  const [r] = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(devices)
    .where(and(eq(devices.user_id, userId), isNull(devices.revoked_at)));
  return r?.n ?? 0;
}

export async function listDevices(deps: ServiceDeps, userId: string, currentDeviceId: string | undefined): Promise<DeviceSummary[]> {
  const rows = await deps.db.select().from(devices).where(eq(devices.user_id, userId)).orderBy(asc(devices.created_at));
  return rows.map((r) => toDeviceSummary(r, currentDeviceId));
}

export function toDeviceSummary(r: DeviceRow, currentDeviceId: string | undefined): DeviceSummary {
  return {
    id: r.id,
    name: r.name,
    platform: r.platform,
    created_at: r.created_at.toISOString(),
    last_seen_at: r.last_seen_at ? r.last_seen_at.toISOString() : null,
    revoked_at: r.revoked_at ? r.revoked_at.toISOString() : null,
    current: r.id === currentDeviceId,
    has_push: Boolean(r.push_token),
  };
}

/** Revokes a device of the user (idempotent). Returns the row and whether it changed. */
export async function revokeDevice(deps: ServiceDeps, userId: string, deviceId: string, byDeviceId: string | undefined) {
  const now = deps.clock.now();
  return deps.db.transaction(async (tx) => {
    const [row] = await tx.select().from(devices).where(and(eq(devices.id, deviceId), eq(devices.user_id, userId))).limit(1);
    if (!row) throw notFound("device");
    if (row.revoked_at) return { row, changed: false };
    const [updated] = await tx
      .update(devices)
      .set({ revoked_at: now, push_token: null })
      .where(and(eq(devices.id, deviceId), isNull(devices.revoked_at)))
      .returning();
    if (!updated) {
      const [fresh] = await tx.select().from(devices).where(eq(devices.id, deviceId));
      return { row: fresh!, changed: false };
    }
    await revokeDeviceRefreshTokens(tx, [deviceId], now);
    let byName: string | null = null;
    if (byDeviceId) {
      const [by] = await tx.select({ name: devices.name }).from(devices).where(eq(devices.id, byDeviceId));
      byName = by?.name ?? null;
    }
    await writeAudit(tx, {
      userId,
      event: "device.revoked",
      payload: { device_id: deviceId, name: row.name, by_device_id: byDeviceId ?? null, by_device_name: byName },
      at: now,
    });
    return { row: updated, changed: true };
  });
}

/** did-bound tokens: POST /v1/devices updates the caller's own device record. */
export async function updateOwnDevice(
  deps: ServiceDeps,
  userId: string,
  deviceId: string,
  input: { name: string; platform: string; push_token: string | null },
): Promise<Device> {
  await requireOwnedDevice(deps, userId, deviceId);
  return deps.db.transaction(async (tx) => {
    // A push token belongs to one device: detach it from any other record of this user.
    if (input.push_token) {
      await tx
        .update(devices)
        .set({ push_token: null })
        .where(and(eq(devices.user_id, userId), eq(devices.push_token, input.push_token), ne(devices.id, deviceId)));
    }
    const [row] = await tx
      .update(devices)
      .set({ name: input.name, platform: input.platform, push_token: input.push_token, last_seen_at: deps.clock.now() })
      .where(eq(devices.id, deviceId))
      .returning();
    return toDevice(row!);
  });
}

export async function touchDevice(deps: ServiceDeps, deviceId: string): Promise<void> {
  await deps.db.update(devices).set({ last_seen_at: deps.clock.now() }).where(eq(devices.id, deviceId));
}

export async function listPushTokens(deps: ServiceDeps, userId: string): Promise<string[]> {
  const rows = await deps.db
    .select({ push_token: devices.push_token })
    .from(devices)
    .where(and(eq(devices.user_id, userId), sql`${devices.push_token} IS NOT NULL`, isNull(devices.revoked_at)));
  return rows.map((r) => r.push_token!).filter(Boolean);
}

/** Idempotent per (user, machine_id, type); name is refreshed on re-registration. */
export async function registerAgent(
  deps: ServiceDeps,
  userId: string,
  input: { name: string; type: string; machine_id: string },
): Promise<{ agent: Agent; created: boolean }> {
  const id = newId("agt");
  const [row] = await deps.db
    .insert(agents)
    .values({ id, user_id: userId, ...input, created_at: deps.clock.now() })
    .onConflictDoUpdate({
      target: [agents.user_id, agents.machine_id, agents.type],
      set: { name: sql`excluded.name` },
    })
    .returning();
  return { agent: toAgent(row!), created: row!.id === id };
}

export async function requireOwnedAgent(deps: ServiceDeps, userId: string, agentId: string) {
  const [row] = await deps.db
    .select()
    .from(agents)
    .where(and(eq(agents.id, agentId), eq(agents.user_id, userId)))
    .limit(1);
  if (!row) throw notFound("agent");
  return row;
}
