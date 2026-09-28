import { createHash, createHmac, randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import { and, desc, eq, gt, isNull, sql } from "drizzle-orm";
import type { AuditEvent, PairingRequest, PairingRequestStatus } from "@agentgate/protocol";
import type { Db } from "../db/client.ts";
import { newId } from "@agentgate/core";
import { auditLogs, devices, pairingCodes, pairingRequests, users, type DeviceRow, type PairingRequestRow, type UserRow } from "../db/schema.ts";
import type { ServiceDeps } from "./context.ts";
import { conflict, DomainError, notFound } from "./errors.ts";
import { assertDeviceKey, countActiveDevices, requireOwnedDevice } from "./identity.ts";

/**
 * Device pairing. A device can only log in with a one-time code minted by an
 * authenticated agent of the same user (`agentgate pair` on the user's machine), so
 * knowing an email address is no longer enough to obtain a device (= approver) token.
 *
 * Codes: 8 chars Crockford base32 (40 bits), 5 min TTL, single use (compare-and-set on
 * used_at), stored as HMAC-SHA256(auth secret, code). Guessing is bounded by the route
 * rate limits; issuing is capped per user.
 */

export const PAIRING_TTL_MS = 5 * 60_000;
export const MAX_CODES_PER_HOUR = 10;
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32
/** Internal audit event (not in protocol AUDIT_EVENTS yet — older mobile builds reject unknown events). */
export const DEVICE_PAIRED_AUDIT_EVENT = "device.paired";
export const PAIRING_CREATED_AUDIT_EVENT = "pairing.created";

export function normalizePairingCode(input: string): string {
  return input
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
}

export function formatPairingCode(code: string): string {
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

const hmac = (secret: string, code: string) => createHmac("sha256", secret).update(`pairing:${code}`).digest("hex");

export async function createPairingCode(deps: ServiceDeps, secret: string, userId: string): Promise<{ code: string; expiresAt: Date }> {
  const now = deps.clock.now();
  const [recent] = await deps.db
    .select({ n: sql<number>`count(*)::int` })
    .from(pairingCodes)
    .where(and(eq(pairingCodes.user_id, userId), gt(pairingCodes.created_at, new Date(now.getTime() - 3_600_000))));
  if ((recent?.n ?? 0) >= MAX_CODES_PER_HOUR) {
    throw new DomainError(429, "too_many_pairing_codes", `at most ${MAX_CODES_PER_HOUR} pairing codes per hour`);
  }
  let code = "";
  for (let i = 0; i < 8; i++) code += ALPHABET[randomInt(ALPHABET.length)];
  const expiresAt = new Date(now.getTime() + PAIRING_TTL_MS);
  await deps.db.transaction(async (tx) => {
    await tx.insert(pairingCodes).values({ id: `pc_${randomBytes(16).toString("base64url")}`, user_id: userId, code_hash: hmac(secret, code), created_at: now, expires_at: expiresAt });
    await tx.insert(auditLogs).values({
      id: newId("aud"),
      user_id: userId,
      event: PAIRING_CREATED_AUDIT_EVENT,
      action_id: null,
      approval_id: null,
      payload_json: { expires_at: expiresAt.toISOString() },
      created_at: now,
    });
  });
  return { code, expiresAt };
}

/** Consumes a code for `email` inside `tx`. Errors never reveal whether the email exists. */
async function consumeCodeTx(tx: Db, secret: string, email: string, rawCode: string, now: Date) {
  const invalid = () => new DomainError(401, "invalid_pairing_code", "pairing code is invalid, expired or already used — run `agentgate pair` again");
  const code = normalizePairingCode(rawCode);
  if (!/^[0-9A-HJKMNP-TV-Z]{8}$/.test(code)) throw invalid();
  const [user] = await tx.select().from(users).where(eq(users.email, email.trim().toLowerCase())).limit(1);
  if (!user) throw invalid();
  const [row] = await tx
    .update(pairingCodes)
    .set({ used_at: now })
    .where(and(eq(pairingCodes.code_hash, hmac(secret, code)), eq(pairingCodes.user_id, user.id), isNull(pairingCodes.used_at), gt(pairingCodes.expires_at, now)))
    .returning({ id: pairingCodes.id });
  if (!row) throw invalid();
  return { user, pairingCodeId: row.id };
}

export const PAIRING_REQUEST_TTL_MS = 5 * 60_000;
const sha = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

export type DeviceLoginResult =
  | { kind: "bootstrap"; user: UserRow; device: DeviceRow }
  | { kind: "pending"; user: UserRow; request: PairingRequestRow; pollSecret: string };

/**
 * Device login with a valid pairing code (C2):
 *  - the user has no active device → bootstrap: the device is created now (trust on first use);
 *  - otherwise → a pairing request that an already-paired device must approve.
 */
export async function deviceLoginWithCode(
  deps: ServiceDeps,
  secret: string,
  input: { email: string; code: string; deviceName: string; platform: string; ip: string; devicePublicKey?: string },
): Promise<DeviceLoginResult> {
  const devicePublicKey = input.devicePublicKey ? assertDeviceKey(input.devicePublicKey) : null;
  const now = deps.clock.now();
  return deps.db.transaction(async (tx) => {
    const { user, pairingCodeId } = await consumeCodeTx(tx, secret, input.email, input.code, now);
    const audit = (event: AuditEvent, payload: Record<string, unknown>) =>
      tx.insert(auditLogs).values({ id: newId("aud"), user_id: user.id, event, action_id: null, approval_id: null, payload_json: payload, created_at: now });
    // Serialize concurrent bootstrap attempts for the same user.
    await tx.execute(sql`SELECT id FROM users WHERE id = ${user.id} FOR UPDATE`);
    if ((await countActiveDevices(tx, user.id)) === 0) {
      const [device] = await tx
        .insert(devices)
        .values({ id: newId("dev"), user_id: user.id, name: input.deviceName, platform: input.platform, push_token: null, created_at: now, last_seen_at: now, public_key: devicePublicKey })
        .returning();
      await audit("device.paired", { bootstrap: true, device_id: device!.id, name: device!.name, platform: device!.platform, ip: input.ip, pairing_id: pairingCodeId });
      return { kind: "bootstrap", user, device: device! };
    }
    const pollSecret = randomBytes(32).toString("base64url");
    const [request] = await tx
      .insert(pairingRequests)
      .values({
        id: `prq_${randomBytes(16).toString("base64url")}`,
        user_id: user.id,
        status: "pending",
        device_name: input.deviceName,
        platform: input.platform,
        ip: input.ip,
        poll_secret_hash: sha(pollSecret),
        requested_at: now,
        expires_at: new Date(now.getTime() + PAIRING_REQUEST_TTL_MS),
        device_public_key: devicePublicKey,
      })
      .returning();
    await audit("device.pairing_requested", {
      pairing_request_id: request!.id,
      device_name: request!.device_name,
      platform: request!.platform,
      ip: input.ip,
      pairing_id: pairingCodeId,
    });
    return { kind: "pending", user, request: request!, pollSecret };
  });
}

/**
 * Remote agent login (another computer): never granted directly — an already-paired device
 * must approve it. No active device → 403 pair_phone_first (no remote bootstrap).
 */
export async function createAgentLoginRequest(
  deps: ServiceDeps,
  input: { email: string; machineName: string; platform: string; ip: string },
): Promise<{ user: UserRow; request: PairingRequestRow; pollSecret: string }> {
  const now = deps.clock.now();
  const refuse = () =>
    new DomainError(403, "pair_phone_first", "remote agent login needs a paired phone to approve it — pair your phone on the server machine first (`agentgate pair`)");
  return deps.db.transaction(async (tx) => {
    const [user] = await tx.select().from(users).where(eq(users.email, input.email.trim().toLowerCase())).limit(1);
    if (!user) throw refuse();
    if ((await countActiveDevices(tx, user.id)) === 0) throw refuse();
    const pollSecret = randomBytes(32).toString("base64url");
    const [request] = await tx
      .insert(pairingRequests)
      .values({
        id: `prq_${randomBytes(16).toString("base64url")}`,
        user_id: user.id,
        status: "pending",
        kind: "agent",
        device_name: input.machineName,
        platform: input.platform,
        ip: input.ip,
        poll_secret_hash: sha(pollSecret),
        requested_at: now,
        expires_at: new Date(now.getTime() + PAIRING_REQUEST_TTL_MS),
      })
      .returning();
    await tx.insert(auditLogs).values({
      id: newId("aud"),
      user_id: user.id,
      event: "agent.login_requested",
      action_id: null,
      approval_id: null,
      payload_json: { pairing_request_id: request!.id, machine_name: input.machineName, platform: input.platform, ip: input.ip },
      created_at: now,
    });
    return { user, request: request!, pollSecret };
  });
}

export function toPairingRequest(r: PairingRequestRow, now: Date): PairingRequest {
  const status = r.status === "pending" && now.getTime() >= r.expires_at.getTime() ? "expired" : r.status;
  return {
    id: r.id,
    status,
    kind: r.kind,
    machine_name: r.kind === "agent" ? r.device_name : null,
    device_name: r.device_name,
    platform: r.platform,
    ip: r.ip,
    requested_at: r.requested_at.toISOString(),
    expires_at: r.expires_at.toISOString(),
    resolved_at: r.resolved_at ? r.resolved_at.toISOString() : null,
  };
}

// ── long-poll wakeups (single process; same caveat as the WS hub) ────────────
const waiters = new Map<string, Set<() => void>>();
export function wakePairingWaiters(id: string) {
  const set = waiters.get(id);
  waiters.delete(id);
  set?.forEach((w) => w());
}
function waitForChange(id: string, ms: number): Promise<void> {
  return new Promise((resolveP) => {
    const set = waiters.get(id) ?? new Set();
    waiters.set(id, set);
    const done = () => {
      clearTimeout(t);
      set.delete(done);
      if (set.size === 0 && waiters.get(id) === set) waiters.delete(id);
      resolveP();
    };
    const t = setTimeout(done, ms);
    set.add(done);
  });
}

/** Loads a request by id + poll secret (constant-time). Wrong id or secret → 404. */
async function loadForPoller(deps: ServiceDeps, id: string, secret: string): Promise<PairingRequestRow> {
  const [row] = await deps.db.select().from(pairingRequests).where(eq(pairingRequests.id, id)).limit(1);
  const given = Buffer.from(sha(secret), "hex");
  const expected = Buffer.from(row?.poll_secret_hash ?? "0".repeat(64), "hex");
  const ok = timingSafeEqual(given, expected);
  if (!row || !ok) throw notFound("pairing request");
  return row;
}

async function expireIfDue(deps: ServiceDeps, row: PairingRequestRow): Promise<PairingRequestRow> {
  const now = deps.clock.now();
  if (row.status !== "pending" || now.getTime() < row.expires_at.getTime()) return row;
  const [u] = await deps.db
    .update(pairingRequests)
    .set({ status: "expired", resolved_at: now })
    .where(and(eq(pairingRequests.id, row.id), eq(pairingRequests.status, "pending")))
    .returning();
  if (u) return u;
  const [fresh] = await deps.db.select().from(pairingRequests).where(eq(pairingRequests.id, row.id));
  return fresh!;
}

export type PollResult = { request: PairingRequestRow; delivered: { user: UserRow; device: DeviceRow | null } | null };

/**
 * GET /v1/pairing/requests/:id. Long-polls while pending (≤ waitMs). On the first poll after
 * approval the device record is created and returned exactly once (compare-and-set on
 * login_delivered_at); the caller issues the token.
 */
export async function pollPairingRequest(deps: ServiceDeps, id: string, secret: string, waitMs: number): Promise<PollResult> {
  let row = await expireIfDue(deps, await loadForPoller(deps, id, secret));
  if (row.status === "pending") {
    const remaining = row.expires_at.getTime() - deps.clock.now().getTime();
    await waitForChange(row.id, Math.max(0, Math.min(waitMs, remaining)));
    row = await expireIfDue(deps, await loadForPoller(deps, id, secret));
  }
  if (row.status !== "approved" || row.login_delivered_at) return { request: row, delivered: null };

  const now = deps.clock.now();
  return deps.db.transaction(async (tx) => {
    const [claimed] = await tx
      .update(pairingRequests)
      .set({ login_delivered_at: now })
      .where(and(eq(pairingRequests.id, row.id), eq(pairingRequests.status, "approved"), isNull(pairingRequests.login_delivered_at)))
      .returning();
    if (!claimed) {
      const [fresh] = await tx.select().from(pairingRequests).where(eq(pairingRequests.id, row.id));
      return { request: fresh!, delivered: null };
    }
    const [user] = await tx.select().from(users).where(eq(users.id, claimed.user_id));
    // Agent logins: no device record; the route issues an agent token + refresh token.
    if (claimed.kind === "agent") return { request: claimed, delivered: { user: user!, device: null } };
    const [device] = await tx
      .insert(devices)
      .values({
        id: newId("dev"),
        user_id: claimed.user_id,
        name: claimed.device_name,
        platform: claimed.platform,
        push_token: null,
        created_at: now,
        last_seen_at: now,
        public_key: claimed.device_public_key,
      })
      .returning();
    const [final] = await tx.update(pairingRequests).set({ device_id: device!.id }).where(eq(pairingRequests.id, claimed.id)).returning();
    await tx.insert(auditLogs).values({
      id: newId("aud"),
      user_id: claimed.user_id,
      event: "device.paired",
      action_id: null,
      approval_id: null,
      payload_json: { bootstrap: false, device_id: device!.id, name: device!.name, platform: device!.platform, pairing_request_id: claimed.id, ip: claimed.ip },
      created_at: now,
    });
    return { request: final!, delivered: { user: user!, device: device! } };
  });
}

export async function listPairingRequests(deps: ServiceDeps, userId: string, status: PairingRequestStatus | undefined): Promise<PairingRequest[]> {
  const now = deps.clock.now();
  const rows = await deps.db.select().from(pairingRequests).where(eq(pairingRequests.user_id, userId)).orderBy(desc(pairingRequests.requested_at)).limit(50);
  return rows.map((r) => toPairingRequest(r, now)).filter((r) => !status || r.status === status);
}

/** Approve/deny by an already-paired, non-revoked device of the same user. */
export async function resolvePairingRequest(
  deps: ServiceDeps,
  userId: string,
  id: string,
  deviceId: string,
  decision: "approve" | "deny",
): Promise<PairingRequest> {
  const approver = await requireOwnedDevice(deps, userId, deviceId);
  const now = deps.clock.now();
  const [row] = await deps.db.select().from(pairingRequests).where(and(eq(pairingRequests.id, id), eq(pairingRequests.user_id, userId))).limit(1);
  if (!row) throw notFound("pairing request");
  const current = await expireIfDue(deps, row);
  if (current.status !== "pending") {
    throw conflict(current.status === "expired" ? "pairing_request_expired" : "pairing_request_already_resolved", `pairing request is ${current.status}`, {
      request: toPairingRequest(current, now),
    });
  }
  const status = decision === "approve" ? "approved" : "denied";
  const updated = await deps.db.transaction(async (tx) => {
    const [u] = await tx
      .update(pairingRequests)
      .set({ status, resolved_at: now, resolved_by_device_id: approver.id })
      .where(and(eq(pairingRequests.id, id), eq(pairingRequests.status, "pending"), gt(pairingRequests.expires_at, now)))
      .returning();
    if (!u) return null;
    await tx.insert(auditLogs).values({
      id: newId("aud"),
      user_id: userId,
      event:
        u.kind === "agent"
          ? decision === "approve"
            ? "agent.login_approved"
            : "agent.login_denied"
          : decision === "approve"
            ? "device.pairing_approved"
            : "device.pairing_denied",
      action_id: null,
      approval_id: null,
      payload_json: {
        pairing_request_id: id,
        device_name: u.device_name,
        ...(u.kind === "agent" ? { machine_name: u.device_name } : {}),
        ip: u.ip,
        by_device_id: approver.id,
        by_device_name: approver.name,
      },
      created_at: now,
    });
    return u;
  });
  if (!updated) {
    const [fresh] = await deps.db.select().from(pairingRequests).where(eq(pairingRequests.id, id));
    throw conflict("pairing_request_already_resolved", `pairing request is ${fresh!.status}`, { request: toPairingRequest(fresh!, now) });
  }
  wakePairingWaiters(id);
  return toPairingRequest(updated, now);
}
