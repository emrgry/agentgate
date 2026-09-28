import { existsSync, realpathSync, statSync } from "node:fs";
import { basename, isAbsolute, resolve } from "node:path";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { and, eq } from "drizzle-orm";
import { z, type ZodTypeAny } from "zod";
import {
  AgentSession,
  ChangeSet,
  CommandBody,
  FileDiff,
  SessionMetrics,
  UsageReport,
  ListAgentSessionsResponse,
  ListProvidersResponse,
  ListTasksResponse,
  ListSessionEventsResponse,
  ListWorkspacesResponse,
  SubmitCommandRequest,
  SubmitCommandResponse,
  Workspace,
} from "@agentgate/protocol";
import { verifyCommand } from "@agentgate/signing";
import { newId } from "@agentgate/core";
import { auditLogs, controlCommands } from "../db/schema.ts";
import type { ServiceDeps } from "../domain/context.ts";
import { DomainError } from "../domain/errors.ts";
import { requireOwnedDevice } from "../domain/identity.ts";
import { claims, requireAuth } from "../http/auth.ts";
import type { ProxyPolicy } from "../http/client-ip.ts";
import { cid, getSession, listEvents, listSessions, listTasks, listWorkspaces, toAgentSession, toTask, workspaces } from "./store.ts";
import type { Supervisor } from "./supervisor.ts";

/**
 * Control Center REST (packages/protocol/src/sessions.ts):
 *   GET  /v1/agent-sessions?status=active|all&limit=         (device or agent)
 *   GET  /v1/agent-sessions/:id                               (device or agent)
 *   GET  /v1/agent-sessions/:id/events?after_seq=&limit=      (device or agent)
 *   POST /v1/agent-sessions                  start            (device: signed "start" | local agent: unsigned)
 *   POST /v1/agent-sessions/:id/commands     control          (device: signed | local agent: unsigned)
 *   POST /v1/agent-sessions/observe          hook events      (local agent)
 *   GET  /v1/agent-sessions/:id/changes[?task_id=]            (device or agent)  Phase 3
 *   GET  /v1/agent-sessions/:id/diff?path=&task_id=           (device or agent)  Phase 3
 *   GET  /v1/agent-sessions/:id/metrics                       (device or agent)  Phase 4
 *   GET  /v1/usage?range=today|7d|30d                         (device or agent)  Phase 4
 *   POST /v1/agent-sessions/global/commands  set_limits       (device: signed, session_id "global" | local agent)
 *   GET  /v1/workspaces                                        (device or agent)
 *   POST /v1/workspaces, DELETE /v1/workspaces/:id            (local agent only — the phone can't widen its own allowlist)
 *   POST /v1/workspaces/:id/allow-ungated {provider, allow}   (local agent only — opt-in for providers AgentGate can't gate)
 *
 * Phone commands are verified with verifyCommand against the device's registered key:
 * signature, 5-min lifetime, session binding ("new" for start), body hash; single use via
 * the UNIQUE nonce in control_commands (survives restarts). Kill must be signed ≤ 60 s ago.
 */

const IdParams = z.object({ id: z.string().min(1).max(64) });
const KILL_MAX_AGE_MS = 60_000;

function send<S extends ZodTypeAny>(reply: FastifyReply, schema: S, body: z.input<S>, status = 200) {
  return reply.status(status).send(schema.parse(body));
}

export function registerControlRoutes(app: FastifyInstance, deps: ServiceDeps, sup: Supervisor, opts: { authSecret: string; proxies: ProxyPolicy }) {
  const any = { preHandler: requireAuth(deps, opts.authSecret) };
  const localAgent = {
    preHandler: [
      requireAuth(deps, opts.authSecret, { audience: "agent" }),
      async (req: FastifyRequest) => {
        if (!opts.proxies.isLocalRequest(req)) throw new DomainError(403, "loopback_only", "only agents on this machine may do this");
      },
    ],
  };

  app.get("/v1/agent-sessions", any, async (req, reply) => {
    const q = z.object({ status: z.enum(["active", "all"]).default("all"), limit: z.coerce.number().int().min(1).max(200).default(50) }).parse(req.query);
    return send(reply, ListAgentSessionsResponse, { items: await listSessions(deps.db, claims(req).sub, q.status, q.limit) });
  });

  app.get("/v1/agent-sessions/:id", any, async (req, reply) => {
    const { id } = IdParams.parse(req.params);
    const row = await getSession(deps.db, claims(req).sub, id);
    if (!row) throw new DomainError(404, "not_found", "session not found");
    return send(reply, AgentSession, toAgentSession(row));
  });

  app.get("/v1/agent-sessions/:id/events", any, async (req, reply) => {
    const { id } = IdParams.parse(req.params);
    const q = z
      .object({
        after_seq: z.coerce.number().int().min(-1).default(-1),
        // seq is an int4 column; clients pass Number.MAX_SAFE_INTEGER to mean "latest".
        before_seq: z.coerce
          .number()
          .int()
          .min(0)
          .transform((n) => Math.min(n, 2_147_483_647))
          .optional(),
        limit: z.coerce.number().int().min(1).max(500).default(200),
      })
      .parse(req.query);
    if (!(await getSession(deps.db, claims(req).sub, id))) throw new DomainError(404, "not_found", "session not found");
    const items = await listEvents(deps.db, id, q.after_seq, q.limit, q.before_seq);
    const last = items.length ? items[items.length - 1]!.seq : null;
    // next_after_seq: cursor for NEWER events. After-paging: set when the page was full.
    // Before-paging: newer events exist by definition (≥ before_seq) → the last item's seq.
    const next = q.before_seq !== undefined ? last : items.length === q.limit ? last : null;
    return send(reply, ListSessionEventsResponse, { items, next_after_seq: next });
  });

  app.get("/v1/agent-sessions/:id/tasks", any, async (req, reply) => {
    const { id } = IdParams.parse(req.params);
    if (!(await getSession(deps.db, claims(req).sub, id))) throw new DomainError(404, "not_found", "session not found");
    return send(reply, ListTasksResponse, { items: (await listTasks(deps.db, id)).map(toTask) });
  });

  // ── Phase 3: review ─────────────────────────────────────────────────────────
  app.get("/v1/agent-sessions/:id/changes", any, async (req, reply) => {
    const { id } = IdParams.parse(req.params);
    const q = z.object({ task_id: z.string().min(1).max(64).optional() }).parse(req.query);
    return send(reply, ChangeSet, await sup.changes(claims(req).sub, id, q.task_id));
  });

  app.get("/v1/agent-sessions/:id/diff", any, async (req, reply) => {
    const { id } = IdParams.parse(req.params);
    const q = z.object({ path: z.string().min(1).max(4096), task_id: z.string().min(1).max(64).optional() }).parse(req.query);
    return send(reply, FileDiff, await sup.diff(claims(req).sub, id, q.path, q.task_id));
  });

  // ── Phase 4: metrics + usage ──────────────────────────────────────────────
  app.get("/v1/agent-sessions/:id/metrics", any, async (req, reply) => {
    const { id } = IdParams.parse(req.params);
    return send(reply, SessionMetrics, await sup.metrics(claims(req).sub, id));
  });

  app.get("/v1/usage", any, async (req, reply) => {
    const q = z.object({ range: z.enum(["today", "7d", "30d"]).default("7d") }).parse(req.query);
    return send(reply, UsageReport, await sup.usage(claims(req).sub, q.range));
  });

  app.get("/v1/providers", any, async (_req, reply) => send(reply, ListProvidersResponse, { items: sup.providers() }));

  // ── workspaces ────────────────────────────────────────────────────────────
  app.get("/v1/workspaces", any, async (req, reply) => send(reply, ListWorkspacesResponse, { items: await listWorkspaces(deps.db, claims(req).sub) }));

  app.post("/v1/workspaces", localAgent, async (req, reply) => {
    const body = z.object({ path: z.string().min(1).max(4096), label: z.string().max(100).optional() }).parse(req.body);
    const path = canonicalDir(body.path);
    const userId = claims(req).sub;
    const existing = (await listWorkspaces(deps.db, userId)).find((w) => w.path === path);
    if (existing) return send(reply, Workspace, existing);
    const [w] = await deps.db.insert(workspaces).values({ id: cid("wsp"), user_id: userId, path, label: body.label?.trim() || basename(path), created_at: deps.clock.now() }).returning();
    return send(reply, Workspace, { id: w!.id, path: w!.path, label: w!.label, ungated_providers: [] }, 201);
  });

  // Explicit, local-only opt-in to run a provider WITHOUT AgentGate gating in this workspace.
  app.post("/v1/workspaces/:id/allow-ungated", localAgent, async (req, reply) => {
    const { id } = IdParams.parse(req.params);
    const body = z.object({ provider: z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/), allow: z.boolean().default(true) }).parse(req.body);
    const userId = claims(req).sub;
    const w = (await listWorkspaces(deps.db, userId)).find((x) => x.id === id);
    if (!w) throw new DomainError(404, "not_found", "workspace not found");
    const set = new Set(w.ungated_providers ?? []);
    if (body.allow) set.add(body.provider);
    else set.delete(body.provider);
    const list = [...set].sort();
    await deps.db.update(workspaces).set({ ungated_providers: list }).where(and(eq(workspaces.id, id), eq(workspaces.user_id, userId)));
    await audit(userId, "session.command_applied", { command: body.allow ? "allow_ungated" : "disallow_ungated", workspace: w.path, provider: body.provider, by: "local_agent" });
    return send(reply, Workspace, { ...w, ungated_providers: list });
  });

  app.delete("/v1/workspaces/:id", localAgent, async (req, reply) => {
    const { id } = IdParams.parse(req.params);
    await deps.db.delete(workspaces).where(and(eq(workspaces.id, id), eq(workspaces.user_id, claims(req).sub)));
    return reply.status(204).send();
  });

  // ── start ─────────────────────────────────────────────────────────────────
  app.post("/v1/agent-sessions", any, async (req, reply) => {
    const c = claims(req);
    if (c.aud === "agent") {
      if (!opts.proxies.isLocalRequest(req)) throw new DomainError(403, "loopback_only", "agents may only start sessions on this machine");
      const b = z.object({ provider: z.string().default("claude-code"), cwd: z.string().min(1), prompt: z.string().min(1).max(16_384), title: z.string().max(200).optional() }).parse(req.body);
      const row = await sup.start(c.sub, { provider: b.provider, cwd: canonicalDir(b.cwd), prompt: b.prompt, ...(b.title ? { title: b.title } : {}), byDevice: null });
      await audit(c.sub, "session.command_applied", { command: "start", session_id: row.id, by: "local_agent" });
      return send(reply, SubmitCommandResponse, { command_id: cid("cmd"), status: "applied", session: toAgentSession(row), reason: null }, 201);
    }
    const req2 = SubmitCommandRequest.parse(req.body);
    if (req2.body.command !== "start") throw new DomainError(400, "invalid_command", "POST /v1/agent-sessions only accepts a signed 'start' command");
    const verified = await verifySigned(req, c, req2, "new");
    const wsp = (await listWorkspaces(deps.db, c.sub)).find((w) => w.id === (req2.body as { workspace_id: string }).workspace_id);
    if (!wsp) {
      await rejectRecord(c.sub, null, req2, "workspace_not_allowed", verified.nonce);
      throw new DomainError(403, "workspace_not_allowed", "sessions can only be started in an allowlisted workspace (agentgate workspace add <dir>)");
    }
    const b = req2.body as Extract<z.infer<typeof CommandBody>, { command: "start" }>;
    const cmdId = await recordCommand(c.sub, null, req2, verified.nonce, "applied");
    const row = await sup.start(c.sub, { provider: b.provider, cwd: wsp.path, prompt: b.prompt, ...(b.title ? { title: b.title } : {}), byDevice: req2.device_id });
    await deps.db.update(controlCommands).set({ session_id: row.id }).where(eq(controlCommands.id, cmdId));
    await audit(c.sub, "session.command_applied", { command: "start", session_id: row.id, device_id: req2.device_id, workspace: wsp.path });
    return send(reply, SubmitCommandResponse, { command_id: cmdId, status: "applied", session: toAgentSession(row), reason: null }, 201);
  });

  // ── control commands ──────────────────────────────────────────────────────
  app.post("/v1/agent-sessions/:id/commands", any, async (req, reply) => {
    const { id } = IdParams.parse(req.params);
    const c = claims(req);
    if (id === "global") {
      // Global default limits: only set_limits; signed for session_id "global" (or a local agent).
      let body: z.infer<typeof CommandBody>;
      let deviceId: string | null = null;
      let cmdId: string;
      if (c.aud === "agent") {
        if (!opts.proxies.isLocalRequest(req)) throw new DomainError(403, "loopback_only", "only local agents may send unsigned commands");
        body = CommandBody.parse((req.body as { body?: unknown })?.body ?? req.body);
        if (body.command !== "set_limits") throw new DomainError(400, "invalid_command", "only set_limits applies to 'global'");
        cmdId = await recordCommand(c.sub, null, { device_id: "", body, signed_command: "" }, null, "queued");
      } else {
        const r = SubmitCommandRequest.parse(req.body);
        if (r.body.command !== "set_limits") throw new DomainError(400, "invalid_command", "only set_limits applies to 'global'");
        const v = await verifySigned(req, c, r, "global");
        body = r.body;
        deviceId = r.device_id;
        cmdId = await recordCommand(c.sub, null, r, v.nonce, "queued");
      }
      const limits = await sup.setGlobalLimits(c.sub, (body as { limits: unknown }).limits);
      await deps.db.update(controlCommands).set({ status: "applied", applied_at: deps.clock.now() }).where(eq(controlCommands.id, cmdId));
      await audit(c.sub, "session.command_applied", { command: "set_limits", session_id: "global", device_id: deviceId, limits });
      // No session for "global": session is null (the phone's schema accepts null).
      return reply.status(200).send({ command_id: cmdId, status: "applied", session: null, reason: null, limits });
    }
    let body: z.infer<typeof CommandBody>;
    let deviceId: string | null = null;
    let cmdId: string;
    if (c.aud === "agent") {
      // Local convenience (`agentgate session send/stop/kill`): the owner on this machine.
      if (!opts.proxies.isLocalRequest(req)) throw new DomainError(403, "loopback_only", "only local agents may send unsigned commands");
      body = CommandBody.parse((req.body as { body?: unknown })?.body ?? req.body);
      if (body.command === "start") throw new DomainError(400, "invalid_command", "use POST /v1/agent-sessions to start");
      if (!(await getSession(deps.db, c.sub, id))) throw new DomainError(404, "not_found", "session not found");
      cmdId = await recordCommand(c.sub, id, { device_id: "", body, signed_command: "" }, null, "queued");
    } else {
      const r = SubmitCommandRequest.parse(req.body);
      if (r.body.command === "start") throw new DomainError(400, "invalid_command", "use POST /v1/agent-sessions to start");
      if (!(await getSession(deps.db, c.sub, id))) throw new DomainError(404, "not_found", "session not found");
      const v = await verifySigned(req, c, r, id);
      body = r.body;
      deviceId = r.device_id;
      cmdId = await recordCommand(c.sub, id, r, v.nonce, "queued");
    }
    try {
      const res = await sup.command(c.sub, id, body as Parameters<Supervisor["command"]>[2], deviceId);
      await deps.db.update(controlCommands).set({ status: res.status === "queued" ? "queued" : "applied", applied_at: deps.clock.now() }).where(eq(controlCommands.id, cmdId));
      await audit(c.sub, "session.command_applied", { command: body.command, session_id: id, device_id: deviceId, queued: res.status === "queued" });
      return send(reply, SubmitCommandResponse, { command_id: cmdId, status: res.status, session: res.session, reason: null, reason_code: null });
    } catch (err) {
      if (!(err instanceof DomainError) || err.status !== 409) throw err;
      await deps.db.update(controlCommands).set({ status: "rejected", reason: err.message }).where(eq(controlCommands.id, cmdId));
      await audit(c.sub, "session.command_rejected", { command: body.command, session_id: id, device_id: deviceId, reason: err.code });
      const row = (await getSession(deps.db, c.sub, id))!;
      return send(reply, SubmitCommandResponse, { command_id: cmdId, status: "rejected", session: toAgentSession(row), reason: err.message, reason_code: err.code });
    }
  });

  // ── observed sessions (installed hooks) ───────────────────────────────────
  app.post("/v1/agent-sessions/observe", localAgent, async (req, reply) => {
    const b = z.object({ provider: z.string().default("claude-code"), hook: z.record(z.string(), z.unknown()) }).parse(req.body);
    const s = await sup.observe(claims(req).sub, b.provider, b.hook);
    return reply.status(200).send({ session: s });
  });

  // ── helpers ───────────────────────────────────────────────────────────────

  async function verifySigned(req: FastifyRequest, c: { sub: string; did?: string }, r: z.infer<typeof SubmitCommandRequest>, expectedSessionId: string) {
    const fail = async (code: string, message: string) => {
      await audit(c.sub, "session.command_rejected", { command: r.body.command, session_id: expectedSessionId, device_id: r.device_id, reason: code, ip: opts.proxies.clientIp(req) });
      return new DomainError(403, code, message);
    };
    if (c.did && c.did !== r.device_id) throw await fail("forbidden", "device_id must be the calling device");
    let device;
    try {
      device = await requireOwnedDevice(deps, c.sub, r.device_id);
    } catch (err) {
      throw await fail((err as DomainError).code ?? "forbidden", (err as Error).message);
    }
    if (!device.public_key) throw await fail("device_key_required", "this device has no registered key; re-pair it to control sessions");
    const now = deps.clock.now();
    const v = verifyCommand(r.signed_command, {
      publicKeyFor: (id) => (id === device.id ? device.public_key : null),
      expectedSessionId,
      body: r.body,
      now,
    });
    if (!v.ok) throw await fail("invalid_signed_command", `signed command rejected: ${v.reason}`);
    if (v.payload.device_id !== r.device_id) throw await fail("invalid_signed_command", "signed command belongs to another device");
    if (r.body.command === "kill" && now.getTime() - Date.parse(v.payload.issued_at) > KILL_MAX_AGE_MS) {
      throw await fail("stale_command", "kill must be signed within the last 60 s");
    }
    return { nonce: v.payload.nonce };
  }

  /** Inserts the command; the UNIQUE nonce makes every signed command single-use. */
  async function recordCommand(userId: string, sessionId: string | null, r: { device_id: string; body: unknown; signed_command: string }, nonce: string | null, status: string) {
    const id = cid("cmd");
    try {
      await deps.db.insert(controlCommands).values({
        id,
        user_id: userId,
        session_id: sessionId,
        command: (r.body as { command: string }).command,
        payload_json: r.body as Record<string, unknown>,
        signed_command: r.signed_command || null,
        nonce,
        status,
        device_id: r.device_id || null,
        created_at: deps.clock.now(),
      });
    } catch (err) {
      if (nonce && /unique|duplicate/i.test(String((err as Error).message) + String((err as { cause?: unknown }).cause ?? ""))) {
        await audit(userId, "session.command_rejected", { command: (r.body as { command: string }).command, session_id: sessionId, device_id: r.device_id, reason: "replayed" });
        throw new DomainError(403, "invalid_signed_command", "signed command rejected: replayed");
      }
      throw err;
    }
    return id;
  }

  async function rejectRecord(userId: string, sessionId: string | null, r: z.infer<typeof SubmitCommandRequest>, reason: string, nonce: string) {
    await recordCommand(userId, sessionId, r, nonce, "rejected").catch(() => {});
    await audit(userId, "session.command_rejected", { command: r.body.command, session_id: sessionId, device_id: r.device_id, reason });
  }

  async function audit(userId: string, event: string, payload: Record<string, unknown>) {
    await deps.db.insert(auditLogs).values({ id: newId("aud"), user_id: userId, event, action_id: null, approval_id: null, payload_json: payload, created_at: deps.clock.now() });
  }
}

function canonicalDir(p: string): string {
  if (!isAbsolute(p)) throw new DomainError(400, "invalid_path", "path must be absolute");
  const abs = resolve(p);
  if (!existsSync(abs) || !statSync(abs).isDirectory()) throw new DomainError(400, "invalid_path", `not a directory: ${abs}`);
  return realpathSync(abs);
}
