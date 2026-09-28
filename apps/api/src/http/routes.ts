import type { FastifyInstance, FastifyReply } from "fastify";
import { z, type ZodTypeAny } from "zod";
import { rekeyDevice, recoverDevices, rootOwnedProof, type RecoveryProofCheck } from "../domain/device-recovery.ts";
import {
  ActionRecord,
  ActivityResponse,
  Agent,
  ApprovalDetail,
  ApprovalToken,
  CancelApprovalRequest,
  CancelApprovalResponse,
  CreateSessionRequest,
  Device,
  KeysResponse,
  ListApprovalsQuery,
  ListApprovalsResponse,
  LoginRequest,
  LoginResponse,
  RekeyRequest,
  PairingResponse,
  DeviceKeyRegistration,
  SignedDecision,
  DeviceKeysResponse,
  PairingHelloRequest,
  PairingHelloResponse,
  PairingPendingResponse,
  PairingPollResponse,
  PairingRequestStatus,
  ListPairingRequestsResponse,
  ResolvePairingRequest,
  ResolvePairingResponse,
  ListDevicesResponse,
  RevokeDeviceResponse,
  RefreshRequest,
  RefreshResponse,
  RegisterAgentRequest,
  RegisterDeviceRequest,
  ReportExecutionRequest,
  ResolveApprovalRequest,
  ResolveApprovalResponse,
  Session,
  SubmitActionRequest,
  SubmitActionResponse,
} from "@agentgate/protocol";
import { signAccessToken } from "../auth/tokens.ts";
import { eq } from "drizzle-orm";
import { devices } from "../db/schema.ts";
import type { ServiceDeps } from "../domain/context.ts";
import {
  listDeviceKeys,
  invalidateDeviceCache,
  listDevices,
  registerAgent,
  registerDevice,
  revokeDevice,
  toDeviceSummary,
  updateOwnDevice,
  upsertUser,
} from "../domain/identity.ts";
import { endSession, listSessionActions, startSession } from "../domain/sessions.ts";
import { reportExecution, submitAction } from "../domain/actions.ts";
import { cancelApproval, getApproval, listApprovals, requestApprovalForAction, resolveApproval } from "../domain/approvals.ts";
import { listActivity } from "../domain/activity.ts";
import { issueRefreshToken, rotateRefreshToken } from "../domain/refresh.ts";
import {
  createAgentLoginRequest,
  createPairingCode,
  deviceLoginWithCode,
  listPairingRequests,
  pollPairingRequest,
  resolvePairingRequest,
  toPairingRequest,
} from "../domain/pairing.ts";
import { DomainError, notFound as notFoundError } from "../domain/errors.ts";
import { ProxyPolicy } from "./client-ip.ts";
import type { ApprovalSigner } from "../keys.ts";
import { claims, requireAuth } from "./auth.ts";

// ── API-local schemas (not in @agentgate/protocol yet) ──────────────────────
const IdParams = z.object({ id: z.string().min(1).max(64) });
/** POST /v1/approvals — explicit approval request for an existing action. */
export const CreateApprovalRequest = z.object({
  action_id: z.string().min(1).max(64),
  ttl_seconds: z.number().int().positive().optional(),
});
export const ListActionsResponse = z.object({ items: z.array(ActionRecord) });
export const ActivityQuery = z.object({ limit: z.coerce.number().int().min(1).max(200).default(50) });
/** Agent-token GET /v1/approvals/:id additionally carries the token once approved. */
export const ApprovalDetailForAgent = ApprovalDetail.extend({ approval_token: ApprovalToken.nullable() });
const GetApprovalQuery = z.object({ device_id: z.string().min(1).max(64).optional() });

/** Validates the outgoing body against the contract, then sends it. */
function send<S extends ZodTypeAny>(reply: FastifyReply, schema: S, body: z.input<S>, status = 200) {
  return reply.status(status).send(schema.parse(body));
}

export function registerRoutes(
  app: FastifyInstance,
  deps: ServiceDeps,
  opts: {
    authSecret: string;
    signer: ApprovalSigner;
    auth?: { allowRemoteAgentLogin?: boolean; openDeviceLogin?: boolean };
    rateLimit?: { authPerMinute?: number; pollPerMinute?: number };
    pairingLongPollMs?: number;
    publicUrl?: string;
    proxies?: ProxyPolicy;
    mode?: "dev" | "local";
    requireDeviceSignatures?: boolean;
    /** Local mode: the single owner every login maps to. */
    owner?: { id: string; email: string; display_name: string | null };
    machineName?: string;
    /** Device recovery proof (default: root-owned nonce file written via sudo). Tests inject one. */
    recoveryProof?: RecoveryProofCheck;
  },
): void {
  const local = opts.mode === "local";
  const proxies = opts.proxies ?? new ProxyPolicy([]);
  const clientIp = (req: Parameters<ProxyPolicy["clientIp"]>[0]) => proxies.clientIp(req);
  const isLocalRequest = (req: Parameters<ProxyPolicy["clientIp"]>[0]) => proxies.isLocalRequest(req);
  const authPerMinute = opts.rateLimit?.authPerMinute ?? 20;
  /** Strict per-IP limit for credential endpoints (brute force of pairing codes / logins). */
  const strict = { config: { rateLimit: { max: authPerMinute, timeWindow: "1 minute" } } };
  const anyClient = { preHandler: requireAuth(deps, opts.authSecret) };
  const deviceOnly = { preHandler: requireAuth(deps, opts.authSecret, { audience: "device" }) };
  const agentOnly = { preHandler: requireAuth(deps, opts.authSecret, { audience: "agent" }) };

  app.get("/healthz", async () => ({ ok: true }));

  // ── Public ──────────────────────────────────────────────────────────────
  app.post("/v1/auth/login", strict, async (req, reply) => {
    const body = LoginRequest.parse(req.body);
    const keyReg = DeviceKeyRegistration.partial().parse(req.body ?? {});
    if (local) {
      // M7 local-first: one owner; no email. Agents only from this machine.
      const owner = opts.owner!;
      if (body.client === "agent") {
        if (!isLocalRequest(req)) {
          throw new DomainError(403, "agent_login_loopback_only", "local-first server: agents log in from this machine only (other computers run their own server)");
        }
        return send(reply, LoginResponse, await agentLogin(owner));
      }
      if (!body.pairing_code) throw new DomainError(401, "pairing_required", "device login requires a pairing code — scan the QR from `agentgate pair`");
      if (opts.requireDeviceSignatures && !keyReg.device_public_key) {
        throw new DomainError(400, "device_key_required", "this server requires a device key (device_public_key) at pairing");
      }
      return deviceCodeLogin(reply, owner.email, body, keyReg.device_public_key, clientIp(req));
    }
    if (!body.email) throw new DomainError(400, "email_required", "email is required on this server");
    const email = body.email;
    let user;
    if (body.client === "agent") {
      // Agents run on the user's machine; a remote agent login would let anyone who can
      // reach the API act as the user's agent (and mint pairing codes).
      // Genuinely local (not merely proxied from 127.0.0.1 by tailscale serve) → direct login.
      if (!isLocalRequest(req) && !opts.auth?.allowRemoteAgentLogin) {
        // Another computer: an already-paired phone must approve it (never bootstrapped remotely).
        const r = await createAgentLoginRequest(deps, {
          email,
          machineName: body.machine_name ?? "Unnamed computer",
          platform: body.platform ?? "unknown",
          ip: clientIp(req),
        });
        deps.notifier.pairingRequested(r.user.id, toPairingRequest(r.request, deps.clock.now()));
        return send(
          reply,
          PairingPendingResponse,
          { status: "pending_approval", pairing_request_id: r.request.id, poll_secret: r.pollSecret, expires_at: r.request.expires_at.toISOString() },
          202,
        );
      }
      user = await upsertUser(deps, email);
    } else if (opts.auth?.openDeviceLogin) {
      user = await upsertUser(deps, email);
    } else {
      if (!body.pairing_code) {
        throw new DomainError(401, "pairing_required", "device login requires a pairing code — run `agentgate pair` on your computer");
      }
      return deviceCodeLogin(reply, email, body, keyReg.device_public_key, clientIp(req));
    }
    const { token, expiresAt } = signAccessToken(
      opts.authSecret,
      { sub: user.id, email: user.email, aud: body.client },
      deps.clock.now(),
    );
    // Agents (daemon, installed hooks) are long-lived: give them a rotating refresh token.
    const refresh =
      body.client === "agent" ? await issueRefreshToken(deps.db, { userId: user.id, now: deps.clock.now() }) : null;
    return send(reply, LoginResponse, {
      access_token: token,
      expires_at: expiresAt.toISOString(),
      user: { id: user.id, email: user.email },
      ...(refresh ? { refresh_token: refresh.token } : {}),
    });
  });

  /** Device login with a pairing code: bootstrap (200) or pending approval by a paired device (202). */
  async function deviceCodeLogin(
    reply: FastifyReply,
    email: string,
    body: { pairing_code?: string; device_name?: string; platform?: string },
    devicePublicKey: string | undefined,
    ip: string,
  ) {
    const r = await deviceLoginWithCode(deps, opts.authSecret, {
      email,
      code: body.pairing_code!,
      deviceName: body.device_name ?? "Unnamed device",
      platform: body.platform ?? "ios",
      ip,
      ...(devicePublicKey ? { devicePublicKey } : {}),
    });
    if (r.kind === "pending") {
      // An already-paired device must approve this one (C2).
      deps.notifier.pairingRequested(r.user.id, toPairingRequest(r.request, deps.clock.now()));
      return send(
        reply,
        PairingPendingResponse,
        { status: "pending_approval", pairing_request_id: r.request.id, poll_secret: r.pollSecret, expires_at: r.request.expires_at.toISOString() },
        202,
      );
    }
    return send(reply, LoginResponse, await deviceLogin(r.user, r.device.id));
  }

  // ── M7: server identity proof for QR pairing ─────────────────────────────
  app.post("/v1/pairing/hello", strict, async (req, reply) => {
    if (!local || !opts.owner) throw notFoundError("route");
    const { challenge, device_id } = PairingHelloRequest.parse(req.body);
    const signature = opts.signer.signBytes(new TextEncoder().encode(`agentgate-pairing-hello:v1:${challenge}`));
    // A re-pairing phone sends its device id: if still active here, it should rekey instead
    // of creating a second device record (which would need its own old record to approve).
    let alreadyPaired: boolean | undefined;
    if (device_id) {
      const [d] = await deps.db.select({ revoked_at: devices.revoked_at, user_id: devices.user_id }).from(devices).where(eq(devices.id, device_id)).limit(1);
      alreadyPaired = Boolean(d && !d.revoked_at && d.user_id === opts.owner.id);
    }
    req.log.info({ has_device_id: Boolean(device_id), already_paired: alreadyPaired }, "pairing hello");
    return send(reply, PairingHelloResponse, {
      server_public_key: opts.signer.publicKeyRaw,
      signature,
      machine_name: opts.machineName ?? "AgentGate",
      owner: { id: opts.owner.id, display_name: opts.owner.display_name ?? "Owner" },
      ...(alreadyPaired !== undefined ? { already_paired: alreadyPaired } : {}),
    });
  });

  /** Same phone, new key: signed by the OLD key (public route — the signature is the proof). */
  app.post("/v1/devices/:id/rekey", strict, async (req, reply) => {
    const { id } = IdParams.parse(req.params);
    const body = RekeyRequest.parse(req.body);
    const r = await rekeyDevice(deps, id, body);
    // Rekey revoked the device's previous refresh families; this starts a fresh one.
    return send(reply, LoginResponse, await deviceLogin(r.user, r.deviceId));
  });

  /**
   * Local recovery (key lost, nobody can approve): loopback agent token AND a proof that a human
   * ran `agentgate devices` with sudo (root-owned one-time nonce file).
   */
  app.post("/v1/devices/recovery", { ...strict, ...agentOnly }, async (req, reply) => {
    if (!isLocalRequest(req)) throw new DomainError(403, "loopback_only", "device recovery is only possible on this computer");
    const body = z
      .object({
        action: z.enum(["revoke", "reset"]),
        device_id: z.string().min(1).max(64).optional(),
        nonce: z.string().regex(/^[A-Za-z0-9_-]{32,128}$/),
        proof_path: z.string().max(256),
      })
      .parse(req.body);
    const r = await recoverDevices(deps, claims(req).sub, body, opts.recoveryProof ?? rootOwnedProof);
    return reply.status(200).send(r);
  });

  /** Executors fetch + pin device keys to verify phone-signed decisions (loopback agents only). */
  app.get("/v1/devices/keys", agentOnly, async (req, reply) => {
    if (!isLocalRequest(req)) throw new DomainError(403, "loopback_only", "device keys are only served to local agents");
    return send(reply, DeviceKeysResponse, { items: await listDeviceKeys(deps, claims(req).sub) });
  });

  /** Agent token + fresh refresh-token family (remote agent login approved by a device). */
  async function agentLogin(user: { id: string; email: string }) {
    const { token, expiresAt } = signAccessToken(opts.authSecret, { sub: user.id, email: user.email, aud: "agent" }, deps.clock.now());
    const refresh = await issueRefreshToken(deps.db, { userId: user.id, now: deps.clock.now() });
    return { access_token: token, expires_at: expiresAt.toISOString(), user: { id: user.id, email: user.email }, refresh_token: refresh.token };
  }

  /** Signs a device token bound to `deviceId` + a fresh device-bound refresh-token family. */
  async function deviceLogin(user: { id: string; email: string }, deviceId: string) {
    const now = deps.clock.now();
    const { token, expiresAt } = signAccessToken(opts.authSecret, { sub: user.id, email: user.email, aud: "device", did: deviceId }, now);
    const refresh = await issueRefreshToken(deps.db, { userId: user.id, now, audience: "device", deviceId });
    return {
      access_token: token,
      expires_at: expiresAt.toISOString(),
      user: { id: user.id, email: user.email },
      device_id: deviceId,
      refresh_token: refresh.token,
    };
  }

  // ── Pairing requests (new device waits for an already-paired device) ─────
  app.get(
    "/v1/pairing/requests/:id",
    { config: { rateLimit: { max: opts.rateLimit?.pollPerMinute ?? 60, timeWindow: "1 minute" } } },
    async (req, reply) => {
      const { id } = IdParams.parse(req.params);
      const secret = req.headers["x-pairing-secret"];
      if (typeof secret !== "string" || secret.length < 16 || secret.length > 256) throw notFoundError("pairing request");
      const r = await pollPairingRequest(deps, id, secret, opts.pairingLongPollMs ?? 25_000);
      const now = deps.clock.now();
      const status = toPairingRequest(r.request, now).status;
      let login = null;
      if (r.delivered?.device) login = await deviceLogin(r.delivered.user, r.delivered.device.id);
      else if (r.delivered) login = await agentLogin(r.delivered.user);
      return send(reply, PairingPollResponse, { status, login });
    },
  );

  app.get("/v1/pairing/requests", deviceOnly, async (req, reply) => {
    const { status } = z.object({ status: PairingRequestStatus.optional() }).parse(req.query);
    return send(reply, ListPairingRequestsResponse, { items: await listPairingRequests(deps, claims(req).sub, status) });
  });

  for (const decision of ["approve", "deny"] as const) {
    app.post(`/v1/pairing/requests/:id/${decision}`, deviceOnly, async (req, reply) => {
      const { id } = IdParams.parse(req.params);
      const body = ResolvePairingRequest.parse(req.body);
      const c = claims(req);
      if (c.did && body.device_id !== c.did) throw new DomainError(403, "forbidden", "device_id must be the calling device");
      const request = await resolvePairingRequest(deps, c.sub, id, body.device_id, decision);
      deps.notifier.pairingResolved(c.sub, request);
      return send(reply, ResolvePairingResponse, { request });
    });
  }

  app.post("/v1/pairing", { ...strict, preHandler: requireAuth(deps, opts.authSecret, { audience: "agent" }) }, async (req, reply) => {
    const { code, expiresAt } = await createPairingCode(deps, opts.authSecret, claims(req).sub);
    return send(reply, PairingResponse, { code, expires_at: expiresAt.toISOString(), ...(opts.publicUrl ? { public_url: opts.publicUrl } : {}) }, 201);
  });

  app.post("/v1/auth/refresh", strict, async (req, reply) => {
    const body = RefreshRequest.parse(req.body);
    const rotated = await rotateRefreshToken(deps, body.refresh_token);
    // Device families: same binding as the pairing login (aud device, did = device id).
    const device = rotated.audience === "device" && rotated.deviceId ? rotated.deviceId : null;
    const { token, expiresAt } = signAccessToken(
      opts.authSecret,
      device
        ? { sub: rotated.userId, email: rotated.email, aud: "device", did: device }
        : { sub: rotated.userId, email: rotated.email, aud: "agent" },
      deps.clock.now(),
    );
    return send(reply, RefreshResponse, {
      access_token: token,
      expires_at: expiresAt.toISOString(),
      refresh_token: rotated.refreshToken,
      ...(device ? { device_id: device } : {}),
    });
  });

  app.get("/v1/keys", async (_req, reply) =>
    send(reply, KeysResponse, {
      approval_signing_key: { kid: opts.signer.kid, alg: "Ed25519", pem: opts.signer.publicKeyPem },
    }),
  );

  // ── Devices / agents / sessions ─────────────────────────────────────────
  app.post("/v1/devices", deviceOnly, async (req, reply) => {
    const body = RegisterDeviceRequest.parse(req.body);
    const c = claims(req);
    // Paired (did-bound) tokens: this updates the caller's own device (push token, name).
    if (c.did) return send(reply, Device, await updateOwnDevice(deps, c.sub, c.did, body), 200);
    const { device, created } = await registerDevice(deps, c.sub, body);
    return send(reply, Device, device, created ? 201 : 200);
  });

  app.get("/v1/devices", anyClient, async (req, reply) => {
    const c = claims(req);
    // Agents: only on this computer (`agentgate devices list`).
    if (c.aud === "agent" && !isLocalRequest(req)) throw new DomainError(403, "loopback_only", "devices are only listed to local agents");
    return send(reply, ListDevicesResponse, { items: await listDevices(deps, c.sub, c.did) });
  });

  app.post("/v1/devices/:id/revoke", deviceOnly, async (req, reply) => {
    const { id } = IdParams.parse(req.params);
    const c = claims(req);
    const { row } = await revokeDevice(deps, c.sub, id, c.did);
    invalidateDeviceCache(deps, id);
    deps.notifier.deviceRevoked(c.sub, id);
    return send(reply, RevokeDeviceResponse, { device: toDeviceSummary(row, c.did) });
  });

  app.post("/v1/agents", agentOnly, async (req, reply) => {
    const body = RegisterAgentRequest.parse(req.body);
    const { agent, created } = await registerAgent(deps, claims(req).sub, body);
    return send(reply, Agent, agent, created ? 201 : 200);
  });

  app.post("/v1/sessions", agentOnly, async (req, reply) => {
    const body = CreateSessionRequest.parse(req.body);
    return send(reply, Session, await startSession(deps, claims(req).sub, body.agent_id), 201);
  });

  app.post("/v1/sessions/:id/end", agentOnly, async (req, reply) => {
    const { id } = IdParams.parse(req.params);
    return send(reply, Session, await endSession(deps, claims(req).sub, id));
  });

  app.get("/v1/sessions/:id/actions", anyClient, async (req, reply) => {
    const { id } = IdParams.parse(req.params);
    return send(reply, ListActionsResponse, { items: await listSessionActions(deps, claims(req).sub, id) });
  });

  // ── Actions ─────────────────────────────────────────────────────────────
  app.post("/v1/actions", agentOnly, async (req, reply) => {
    const body = SubmitActionRequest.parse(req.body);
    return send(reply, SubmitActionResponse, await submitAction(deps, claims(req).sub, body), 201);
  });

  app.post("/v1/actions/:id/execution", agentOnly, async (req, reply) => {
    const { id } = IdParams.parse(req.params);
    const body = ReportExecutionRequest.parse(req.body);
    return send(reply, ActionRecord, await reportExecution(deps, claims(req).sub, id, body));
  });

  // ── Approvals ───────────────────────────────────────────────────────────
  app.post("/v1/approvals", agentOnly, async (req, reply) => {
    const body = CreateApprovalRequest.parse(req.body);
    return send(reply, ApprovalDetail, await requestApprovalForAction(deps, claims(req).sub, body), 201);
  });

  app.get("/v1/approvals", anyClient, async (req, reply) => {
    const q = ListApprovalsQuery.parse(req.query);
    return send(reply, ListApprovalsResponse, { items: await listApprovals(deps, claims(req).sub, q) });
  });

  app.get("/v1/approvals/:id", anyClient, async (req, reply) => {
    const { id } = IdParams.parse(req.params);
    const c = claims(req);
    if (c.aud === "agent") {
      const detail = await getApproval(deps, c.sub, id, { kind: "agent" });
      return send(reply, ApprovalDetailForAgent, { ...detail, approval_token: detail.approval_token ?? null });
    }
    const header = req.headers["x-agentgate-device-id"];
    const deviceId = (typeof header === "string" ? header : undefined) ?? GetApprovalQuery.parse(req.query).device_id;
    return send(reply, ApprovalDetail, await getApproval(deps, c.sub, id, { kind: "device", deviceId: deviceId ?? null }));
  });

  app.post("/v1/approvals/:id/cancel", agentOnly, async (req, reply) => {
    const { id } = IdParams.parse(req.params);
    const body = CancelApprovalRequest.parse(req.body ?? {});
    return send(reply, CancelApprovalResponse, { approval: await cancelApproval(deps, claims(req).sub, id, body) });
  });

  for (const decision of ["approve", "deny"] as const) {
    app.post(`/v1/approvals/:id/${decision}`, deviceOnly, async (req, reply) => {
      const { id } = IdParams.parse(req.params);
      const body = ResolveApprovalRequest.extend({ signed_decision: SignedDecision.optional() }).parse(req.body);
      const did = claims(req).did;
      if (did && body.device_id !== did) throw new DomainError(403, "forbidden", "device_id must be the calling device");
      return send(reply, ResolveApprovalResponse, await resolveApproval(deps, claims(req).sub, id, body.device_id, decision, { ...(body.signed_decision ? { signedDecision: body.signed_decision } : {}), requireDeviceSignatures: opts.requireDeviceSignatures ?? false }));
    });
  }

  // ── Activity ────────────────────────────────────────────────────────────
  app.get("/v1/activity", anyClient, async (req, reply) => {
    const { limit } = ActivityQuery.parse(req.query);
    return send(reply, ActivityResponse, { items: await listActivity(deps, claims(req).sub, limit) });
  });
}
