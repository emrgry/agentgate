import { createHash, randomBytes } from "node:crypto";
import { and, eq, inArray, isNull } from "drizzle-orm";
import { newId } from "@agentgate/core";
import type { Db } from "../db/client.ts";
import { auditLogs, devices, refreshTokens, users } from "../db/schema.ts";
import type { ServiceDeps } from "./context.ts";
import { DomainError } from "./errors.ts";

/**
 * Rotating refresh tokens for agent clients (the daemon / installed Claude Code hooks
 * live for days; access tokens live 1 h) and for paired devices (phones; access tokens
 * live 12 h, the pairing must survive for months).
 *
 * - Opaque random token; only its SHA-256 is stored.
 * - Single use: a successful refresh consumes the presented token (compare-and-set on
 *   used_at IS NULL) and issues a new one in the same family.
 * - Reuse detection: presenting an already-consumed token (or losing a concurrent
 *   rotation race) revokes the entire family and is audited. Legit holders then must
 *   log in again — the standard trade-off for stolen-token containment.
 * - Each token expires 30 days (agents) / 90 days (devices) after issue (sliding with rotation).
 * - Device families are bound to one device id. Revoking the device revokes its families
 *   (revokeDeviceRefreshTokens) and a refresh for a revoked device fails with 401 device_revoked.
 */

export type RefreshAudience = "agent" | "device";
export const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const DEVICE_REFRESH_TTL_MS = 90 * 24 * 60 * 60 * 1000;
export const refreshTtlMs = (audience: RefreshAudience) => (audience === "device" ? DEVICE_REFRESH_TTL_MS : REFRESH_TTL_MS);
/** Internal audit event — deliberately not in protocol AUDIT_EVENTS (see listActivity). */
export const REFRESH_REUSE_AUDIT_EVENT = "auth.refresh_reuse_detected";

export const hashRefreshToken = (token: string) => createHash("sha256").update(token, "utf8").digest("hex");

const rid = () => `rtk_${randomBytes(16).toString("base64url")}`;
const newOpaqueToken = () => `agr_${randomBytes(32).toString("base64url")}`;

const unauthorized = (code: string, message: string) => new DomainError(401, code, message);

/**
 * Issues a refresh token. Starts a new family unless `familyId` is given.
 * Default audience "agent"; audience "device" requires `deviceId` (the family is bound to it).
 */
export async function issueRefreshToken(
  db: Db,
  input: { userId: string; now: Date; familyId?: string } & ({ audience?: "agent"; deviceId?: undefined } | { audience: "device"; deviceId: string }),
): Promise<{ token: string; id: string; familyId: string }> {
  const audience: RefreshAudience = input.audience ?? "agent";
  const token = newOpaqueToken();
  const id = rid();
  const familyId = input.familyId ?? `rtf_${randomBytes(16).toString("base64url")}`;
  await db.insert(refreshTokens).values({
    id,
    user_id: input.userId,
    family_id: familyId,
    token_hash: hashRefreshToken(token),
    audience,
    device_id: audience === "device" ? input.deviceId! : null,
    created_at: input.now,
    expires_at: new Date(input.now.getTime() + refreshTtlMs(audience)),
  });
  return { token, id, familyId };
}

/** Revokes every live refresh token bound to the given devices (device revoke / recovery / rekey). */
export async function revokeDeviceRefreshTokens(db: Db, deviceIds: string[], now: Date): Promise<number> {
  if (deviceIds.length === 0) return 0;
  const r = await db
    .update(refreshTokens)
    .set({ revoked_at: now })
    .where(and(inArray(refreshTokens.device_id, deviceIds), isNull(refreshTokens.revoked_at)))
    .returning({ id: refreshTokens.id });
  return r.length;
}

type RotateResult =
  | { kind: "ok"; userId: string; email: string; token: string; audience: RefreshAudience; deviceId: string | null }
  | { kind: "reuse"; userId: string; familyId: string; tokenId: string }
  | { kind: "error"; error: DomainError };

export async function rotateRefreshToken(
  deps: ServiceDeps,
  presented: string,
): Promise<{ userId: string; email: string; refreshToken: string; audience: RefreshAudience; deviceId: string | null }> {
  const now = deps.clock.now();
  const hash = hashRefreshToken(presented);

  const result: RotateResult = await deps.db.transaction(async (tx) => {
    const [row] = await tx.select().from(refreshTokens).where(eq(refreshTokens.token_hash, hash)).limit(1);
    if (!row) return { kind: "error", error: unauthorized("invalid_refresh_token", "unknown refresh token") };
    if (row.audience === "device") {
      // Checked first so a phone learns it was unpaired (not just "log in again").
      const [dev] = row.device_id
        ? await tx.select({ user_id: devices.user_id, revoked_at: devices.revoked_at }).from(devices).where(eq(devices.id, row.device_id)).limit(1)
        : [];
      if (!dev || dev.revoked_at || dev.user_id !== row.user_id) {
        // Defense in depth: every revoke path already revokes the families; make sure.
        await tx
          .update(refreshTokens)
          .set({ revoked_at: now })
          .where(and(eq(refreshTokens.family_id, row.family_id), isNull(refreshTokens.revoked_at)));
        return { kind: "error", error: unauthorized("device_revoked", "this device has been revoked — pair it again") };
      }
    }
    if (row.revoked_at) return { kind: "error", error: unauthorized("refresh_token_revoked", "refresh token revoked — log in again") };
    if (row.used_at) return { kind: "reuse", userId: row.user_id, familyId: row.family_id, tokenId: row.id };
    if (row.expires_at.getTime() <= now.getTime()) {
      return { kind: "error", error: unauthorized("refresh_token_expired", "refresh token expired — log in again") };
    }
    const [user] = await tx.select().from(users).where(eq(users.id, row.user_id)).limit(1);
    if (!user) return { kind: "error", error: unauthorized("invalid_refresh_token", "unknown user") };

    const next = newOpaqueToken();
    const nextId = rid();
    // Compare-and-set: exactly one concurrent refresh can consume a token.
    const [consumed] = await tx
      .update(refreshTokens)
      .set({ used_at: now, replaced_by: nextId })
      .where(and(eq(refreshTokens.id, row.id), isNull(refreshTokens.used_at), isNull(refreshTokens.revoked_at)))
      .returning({ id: refreshTokens.id });
    if (!consumed) return { kind: "reuse", userId: row.user_id, familyId: row.family_id, tokenId: row.id };

    await tx.insert(refreshTokens).values({
      id: nextId,
      user_id: row.user_id,
      family_id: row.family_id,
      token_hash: hashRefreshToken(next),
      audience: row.audience,
      device_id: row.device_id,
      created_at: now,
      // Sliding: each rotation restarts the lifetime.
      expires_at: new Date(now.getTime() + refreshTtlMs(row.audience)),
    });
    return { kind: "ok", userId: user.id, email: user.email, token: next, audience: row.audience, deviceId: row.device_id };
  });

  if (result.kind === "ok") {
    return { userId: result.userId, email: result.email, refreshToken: result.token, audience: result.audience, deviceId: result.deviceId };
  }
  if (result.kind === "error") throw result.error;

  // Reuse: revoke the whole family in its own transaction (must survive the 401).
  await deps.db.transaction(async (tx) => {
    const revoked = await tx
      .update(refreshTokens)
      .set({ revoked_at: now })
      .where(and(eq(refreshTokens.family_id, result.familyId), isNull(refreshTokens.revoked_at)))
      .returning({ id: refreshTokens.id });
    await tx.insert(auditLogs).values({
      id: newId("aud"),
      user_id: result.userId,
      event: REFRESH_REUSE_AUDIT_EVENT,
      action_id: null,
      approval_id: null,
      payload_json: { family_id: result.familyId, reused_token_id: result.tokenId, revoked_count: revoked.length },
      created_at: now,
    });
  });
  deps.logger.warn({ family_id: result.familyId, user_id: result.userId }, "refresh token reuse detected; family revoked");
  throw unauthorized("refresh_token_reused", "refresh token already used — all sessions from this login were revoked; log in again");
}
