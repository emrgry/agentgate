import Fastify, { type FastifyInstance, type FastifyServerOptions } from "fastify";
import websocket from "@fastify/websocket";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import type { Db } from "./db/client.ts";
import type { ApprovalSigner } from "./keys.ts";
import { nullNotifier, systemClock, type Clock, type Logger, type ServiceDeps } from "./domain/context.ts";
import { expireDueApprovals } from "./domain/approvals.ts";
import { listPushTokens } from "./domain/identity.ts";
import { registerErrorHandling } from "./http/errors.ts";
import { redactUrl } from "./http/auth.ts";
import { ProxyPolicy } from "./http/client-ip.ts";
import { Supervisor, type SupervisorOptions } from "./control/supervisor.ts";
import { registerControlRoutes } from "./control/routes.ts";
import { hostname, userInfo } from "node:os";
import { ensureOwner } from "./domain/identity.ts";
import { publicKeyFingerprint } from "@agentgate/signing";

function defaultOwnerName(): string {
  try {
    return userInfo().username || "Owner";
  } catch {
    return "Owner";
  }
}
import { registerRoutes } from "./http/routes.ts";
import { RealtimeHub } from "./realtime/hub.ts";
import { registerRealtimeRoutes } from "./realtime/routes.ts";
import { createNotifier } from "./notifier.ts";
import type { PushSender } from "./push/expo.ts";

export interface AppOptions {
  db: Db;
  signer: ApprovalSigner;
  authSecret: string;
  /** Push sender factory; receives the app logger. */
  push: (logger: Logger) => PushSender;
  clock?: Clock;
  /** `false` disables logging (tests). */
  logLevel?: string | false;
  sweepIntervalMs?: number;
  heartbeatIntervalMs?: number;
  /** Browser origins allowed via CORS (dev web preview). Empty → CORS disabled. */
  corsOrigins?: string[];
  auth?: { allowRemoteAgentLogin?: boolean; openDeviceLogin?: boolean };
  /** Per-IP limits. Defaults: 20/min on /v1/auth/* + /v1/pairing, 600/min elsewhere. */
  rateLimit?: { authPerMinute?: number; defaultPerMinute?: number; pollPerMinute?: number } | false;
  /** Long-poll window for GET /v1/pairing/requests/:id (default 25 s). */
  pairingLongPollMs?: number;
  /** AGENTGATE_PUBLIC_URL: advertised in POST /v1/pairing so QR codes carry it. */
  publicUrl?: string | null;
  /** TRUSTED_PROXIES (CIDRs) whose forwarding headers are believed. Default: none. */
  trustedProxies?: string[];
  /** "local": M7 local-first (single owner, email-less login, pairing hello). Default "dev". */
  mode?: "dev" | "local";
  /** Approvals must carry a device-signed decision (v2); v1 server tokens are never issued. */
  requireDeviceSignatures?: boolean;
  ownerName?: string;
  machineName?: string;
  /** Control Center (docs/control-center.md): managed/observed agent sessions. */
  control?: SupervisorOptions;
  /** Session push coalescing window (ms, default 30 s). */
  sessionPushIntervalMs?: number;
  /** Device recovery proof check (default: root-owned nonce file); tests inject one. */
  recoveryProof?: import("./domain/device-recovery.ts").RecoveryProofCheck;
}

export interface App {
  app: FastifyInstance;
  supervisor: Supervisor | null;
  hub: RealtimeHub;
  deps: ServiceDeps;
  /** Starts the expiry sweeper and WS heartbeat. Stopped automatically on app.close(). */
  startBackgroundJobs(): void;
  /** One sweeper tick (exposed for tests). */
  sweep(): Promise<number>;
}

function loggerOptions(level: string | false | undefined, proxies: ProxyPolicy): FastifyServerOptions["logger"] {
  if (level === false) return false;
  return {
    level: level ?? "info",
    // Never log credentials: bearer tokens (header or WS query) and approval tokens.
    redact: { paths: ["req.headers.authorization", "req.headers.cookie"], censor: "[redacted]" },
    serializers: {
      req(req) {
        return {
          method: req.method,
          url: redactUrl(req.url),
          host: req.host,
          remoteAddress: proxies.clientIp(req as never),
        };
      },
    },
  };
}

export async function buildApp(opts: AppOptions): Promise<App> {
  const proxies = new ProxyPolicy(opts.trustedProxies ?? []);
  const app = Fastify({
    logger: loggerOptions(opts.logLevel, proxies),
    bodyLimit: 256 * 1024,
  });
  app.decorateRequest("auth", null);

  // Accept empty JSON bodies (e.g. `POST /v1/sessions/:id/end` with a JSON content-type).
  app.removeContentTypeParser("application/json");
  app.addContentTypeParser("application/json", { parseAs: "string" }, (_req, body, done) => {
    const text = typeof body === "string" ? body : body.toString("utf8");
    if (text.trim() === "") return done(null, undefined);
    try {
      done(null, JSON.parse(text));
    } catch {
      const err = Object.assign(new Error("request body is not valid JSON"), { statusCode: 400, code: "invalid_json" });
      done(err, undefined);
    }
  });

  const logger = app.log;
  const hub = new RealtimeHub(logger);
  const clock = opts.clock ?? systemClock;

  // Late-bound so the notifier can query the db through the same deps object.
  const deps: ServiceDeps = {
    db: opts.db,
    clock,
    signer: opts.signer,
    logger,
    notifier: nullNotifier,
  };
  deps.notifier = createNotifier({
    hub,
    push: opts.push(logger),
    pushTokensFor: (userId) => listPushTokens(deps, userId),
    logger,
    serverFingerprint: publicKeyFingerprint(opts.signer.publicKeyRaw),
    ...(opts.sessionPushIntervalMs !== undefined ? { sessionPushIntervalMs: opts.sessionPushIntervalMs } : {}),
  });

  // Control Center supervisor: approvals raised by a managed turn move it to awaiting_approval.
  let supervisor: Supervisor | null = null;
  if (opts.control) {
    const sup = new Supervisor(deps, { requireDeviceSignatures: opts.requireDeviceSignatures ?? false, ...opts.control });
    supervisor = sup;
    const base = deps.notifier;
    deps.notifier = {
      ...base,
      approvalCreated(userId, detail) {
        base.approvalCreated(userId, detail);
        sup.onApprovalRequested(userId, detail.action.context, detail.approval.approval_id);
      },
      approvalResolved(userId, sessionId, event) {
        base.approvalResolved(userId, sessionId, event);
        sup.onApprovalResolved(userId, event.approval_id);
      },
    };
    await sup.recoverOnBoot();
  }

  registerErrorHandling(app);
  if (opts.corsOrigins?.length) {
    await app.register(cors, { origin: opts.corsOrigins, allowedHeaders: ["authorization", "content-type", "x-agentgate-device-id"] });
  }
  if (opts.rateLimit !== false) {
    await app.register(rateLimit, {
      global: true,
      // Per real client: behind tailscale serve every request arrives from 127.0.0.1.
      keyGenerator: (req) => proxies.clientIp(req),
      max: opts.rateLimit?.defaultPerMinute ?? 600,
      timeWindow: "1 minute",
      errorResponseBuilder: (_req, ctx) =>
        Object.assign(new Error(`too many requests; retry in ${Math.ceil(ctx.ttl / 1000)}s`), { statusCode: 429, code: "rate_limited" }),
    });
  }
  await app.register(websocket, { options: { maxPayload: 64 * 1024 } });
  registerRoutes(app, deps, {
    authSecret: opts.authSecret,
    signer: opts.signer,
    ...(opts.auth ? { auth: opts.auth } : {}),
    ...(opts.rateLimit ? { rateLimit: opts.rateLimit } : {}),
    ...(opts.pairingLongPollMs !== undefined ? { pairingLongPollMs: opts.pairingLongPollMs } : {}),
    ...(opts.publicUrl ? { publicUrl: opts.publicUrl } : {}),
    proxies,
    mode: opts.mode ?? "dev",
    requireDeviceSignatures: opts.requireDeviceSignatures ?? false,
    ...(opts.mode === "local" ? { owner: await ensureOwner(deps, opts.ownerName ?? defaultOwnerName()) } : {}),
    machineName: opts.machineName ?? hostname(),
    ...(opts.recoveryProof ? { recoveryProof: opts.recoveryProof } : {}),
  });
  registerRealtimeRoutes(app, deps, hub, { authSecret: opts.authSecret });
  if (supervisor) registerControlRoutes(app, deps, supervisor, { authSecret: opts.authSecret, proxies });

  let sweeper: NodeJS.Timeout | null = null;
  let sweeping = false;
  const sweep = async () => {
    if (sweeping) return 0;
    sweeping = true;
    try {
      const n = await expireDueApprovals(deps);
      if (n > 0) logger.info({ expired: n }, "expired approvals");
      return n;
    } finally {
      sweeping = false;
    }
  };

  app.addHook("onClose", async () => {
    await supervisor?.shutdown();
    if (sweeper) clearInterval(sweeper);
    hub.closeAll();
  });

  return {
    app,
    supervisor,
    hub,
    deps,
    sweep,
    startBackgroundJobs() {
      hub.startHeartbeat(opts.heartbeatIntervalMs ?? 30_000);
      sweeper = setInterval(() => {
        sweep().catch((err: unknown) => logger.error({ err }, "expiry sweep failed"));
      }, opts.sweepIntervalMs ?? 2000);
    },
  };
}
