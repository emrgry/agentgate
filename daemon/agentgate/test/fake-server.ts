import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { computeActionHash, generateSigningKeyPair, newId, newNonce, signApprovalToken } from "@agentgate/core";
import { SubmitActionRequest, type Approval, type CanonicalAction } from "@agentgate/protocol";
import { WebSocketServer, type WebSocket } from "ws";

/**
 * Minimal in-process implementation of the AgentGate v1 contract (architecture §6),
 * just enough to drive `agentgate request` end to end without the real API.
 */

export interface AskContext {
  server: FakeServer;
  approval: Approval;
  action: CanonicalAction;
  actionHash: string;
  sessionId: string;
}

export interface FakeServerOptions {
  /** What to do when an `ask` action is submitted. Default: approve with a valid token. */
  onAsk?: (ctx: AskContext) => void;
  /** Reject WS upgrades with this HTTP status. */
  wsRejectStatus?: number;
  /** Override approval window length (ms). */
  approvalWindowMs?: number;
  /** Never answer POST /v1/actions (to exercise client-side deadlines). */
  hangActions?: boolean;
  /** Delay POST /v1/auth/refresh responses (widens race windows in tests). */
  refreshDelayMs?: number;
  /** Delay POST /v1/sessions responses (widens race windows in tests). */
  sessionDelayMs?: number;
  /** Simulate a REMOTE agent login: 202 + phone decision on poll, or 403 pair_phone_first. */
  remoteAgentLogin?: "approve" | "deny" | "expire" | "no_phone";
  /** Returned as public_url by POST /v1/pairing. */
  publicUrl?: string;
}

export interface Recorded {
  method: string;
  path: string;
  body: unknown;
}

export class FakeServer {
  readonly keys = generateSigningKeyPair();
  readonly token = "test-access-token-0123456789";
  /** Access tokens accepted (login token + every refreshed one). */
  readonly validTokens = new Set<string>([this.token]);
  /** Refresh tokens: token → state. Rotation + reuse detection like the real API. */
  readonly refreshTokens = new Map<string, { family: string; used: boolean; revoked: boolean; expired?: boolean }>();
  refreshCalls = 0;
  readonly cancels: Array<{ approval_id: string; reason?: string }> = [];
  readonly loginBodies: any[] = [];
  /** GET /v1/devices/keys response items (mutable by tests). */
  deviceKeys: Array<{ device_id: string; public_key: string; fingerprint: string; revoked_at: string | null }> = [];
  polls = 0;
  readonly createdSessions: string[] = [];
  readonly requests: Recorded[] = [];
  readonly executions: Array<{ action_id: string; status: string; exit_code?: number | null; detail?: string }> = [];
  readonly endedSessions: string[] = [];
  readonly approvals = new Map<string, { approval: Approval; action: CanonicalAction; actionHash: string; token: string | null }>();
  readonly sockets = new Map<string, Set<WebSocket>>();
  wsConnects = 0;
  private http!: Server;
  private wss!: WebSocketServer;
  url = "";

  constructor(readonly opts: FakeServerOptions = {}) {}

  async start(): Promise<this> {
    this.wss = new WebSocketServer({ noServer: true });
    this.http = createServer((req, res) => void this.handle(req, res));
    this.http.on("upgrade", (req, socket, head) => {
      const u = new URL(req.url ?? "/", "http://x");
      if (u.pathname !== "/v1/agent/connect") return socket.destroy();
      if (this.opts.wsRejectStatus) {
        socket.end(`HTTP/1.1 ${this.opts.wsRejectStatus} Rejected\r\nConnection: close\r\n\r\n`);
        return;
      }
      if (!this.validTokens.has((req.headers.authorization ?? "").replace(/^Bearer /, ""))) {
        socket.end("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
        return;
      }
      const sessionId = u.searchParams.get("session_id") ?? "";
      this.wss.handleUpgrade(req, socket, head, (ws) => {
        this.wsConnects++;
        const set = this.sockets.get(sessionId) ?? new Set();
        set.add(ws);
        this.sockets.set(sessionId, set);
        ws.on("close", () => set.delete(ws));
        ws.on("message", (d) => {
          try {
            if (JSON.parse(d.toString()).type === "ping") ws.send(JSON.stringify({ type: "pong" }));
          } catch {
            /* ignore */
          }
        });
        ws.send(JSON.stringify({ type: "hello", server_time: new Date().toISOString() }));
      });
    });
    await new Promise<void>((r) => this.http.listen(0, "127.0.0.1", r));
    this.url = `http://127.0.0.1:${(this.http.address() as AddressInfo).port}`;
    return this;
  }

  async stop() {
    for (const set of this.sockets.values()) for (const ws of set) ws.terminate();
    this.wss.close();
    this.http.closeAllConnections();
    await new Promise<void>((r) => this.http.close(() => r()));
  }

  // ── helpers for scenarios ────────────────────────────────────────────────
  sign(ctx: AskContext, overrides: Partial<Parameters<typeof signApprovalToken>[0]> = {}, privateKeyPem = this.keys.privateKeyPem) {
    return signApprovalToken(
      {
        v: 1,
        approval_id: ctx.approval.approval_id,
        action_id: ctx.action.action_id,
        session_id: ctx.sessionId,
        action_hash: ctx.actionHash,
        decision: "approved",
        expires_at: new Date(Date.now() + 60_000).toISOString(),
        nonce: newNonce(),
        issued_at: new Date().toISOString(),
        ...overrides,
      },
      privateKeyPem,
    );
  }

  resolve(ctx: AskContext, status: Approval["status"], token: string | null, opts: { broadcast?: boolean } = {}) {
    const rec = this.approvals.get(ctx.approval.approval_id)!;
    rec.approval = {
      ...rec.approval,
      status,
      decision: status === "approved" ? "approve" : status === "denied" ? "deny" : null,
      resolved_at: new Date().toISOString(),
      resolved_by_device_id: status === "approved" || status === "denied" ? "dev_test_phone" : null,
    };
    rec.token = token;
    if (opts.broadcast === false) return;
    const msg = JSON.stringify({
      type: "approval.resolved",
      approval_id: ctx.approval.approval_id,
      action_id: ctx.action.action_id,
      status,
      approval_token: token,
    });
    for (const ws of this.sockets.get(ctx.sessionId) ?? []) ws.send(msg);
  }

  dropSockets(sessionId: string) {
    for (const ws of this.sockets.get(sessionId) ?? []) ws.terminate();
  }

  count(method: string, pathPrefix: string) {
    return this.requests.filter((r) => r.method === method && r.path.startsWith(pathPrefix)).length;
  }

  /** Issue a refresh token in a new family (what login does). */
  issueRefreshToken(opts: { expired?: boolean } = {}): string {
    const t = `agr_${newNonce()}${newNonce()}`;
    this.refreshTokens.set(t, { family: newNonce(), used: false, revoked: false, ...(opts.expired ? { expired: true } : {}) });
    return t;
  }

  // ── HTTP ─────────────────────────────────────────────────────────────────
  private async handle(req: IncomingMessage, res: ServerResponse) {
    const chunks: Buffer[] = [];
    for await (const ch of req) chunks.push(ch as Buffer);
    const raw = Buffer.concat(chunks).toString("utf8");
    const body = raw ? JSON.parse(raw) : undefined;
    const path = new URL(req.url ?? "/", "http://x").pathname;
    const method = req.method ?? "GET";
    this.requests.push({ method, path, body });

    const send = (status: number, json: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(json));
    };
    const now = () => new Date().toISOString();

    if (method === "POST" && path === "/v1/auth/login" && body.client === "agent" && this.opts.remoteAgentLogin) {
      this.loginBodies.push(body);
      if (this.opts.remoteAgentLogin === "no_phone") return send(403, { error: { code: "pair_phone_first", message: "pair a phone first" } });
      return send(202, { status: "pending_approval", pairing_request_id: "prq_remote1", poll_secret: "s".repeat(43), expires_at: new Date(Date.now() + 300_000).toISOString() });
    }
    const pm = path.match(/^\/v1\/pairing\/requests\/([^/]+)$/);
    if (method === "GET" && pm) {
      if (req.headers["x-pairing-secret"] !== "s".repeat(43) || pm[1] !== "prq_remote1") return send(404, { error: { code: "not_found", message: "nope" } });
      this.polls++;
      if (this.polls === 1) {
        await new Promise((r) => setTimeout(r, 200));
        return send(200, { status: "pending", login: null });
      }
      const mode = this.opts.remoteAgentLogin;
      if (mode === "deny") return send(200, { status: "denied", login: null });
      if (mode === "expire") return send(200, { status: "expired", login: null });
      return send(200, {
        status: "approved",
        login: { access_token: this.token, expires_at: new Date(Date.now() + 3_600_000).toISOString(), user: { id: "usr_test", email: "dev@agentgate.local" }, refresh_token: this.issueRefreshToken() },
      });
    }
    if (method === "POST" && path === "/v1/auth/login") {
      return send(200, {
        access_token: this.token,
        expires_at: new Date(Date.now() + 3_600_000).toISOString(),
        user: { id: "usr_test", email: body.email },
        ...(body.client === "agent" ? { refresh_token: this.issueRefreshToken() } : {}),
      });
    }
    if (method === "POST" && path === "/v1/auth/refresh") {
      this.refreshCalls++;
      if (this.opts.refreshDelayMs) await new Promise((r) => setTimeout(r, this.opts.refreshDelayMs));
      const rec = this.refreshTokens.get(body?.refresh_token);
      const fail = (code: string) => send(401, { error: { code, message: code } });
      if (!rec) return fail("invalid_refresh_token");
      if (rec.revoked) return fail("refresh_token_revoked");
      if (rec.used) {
        for (const r of this.refreshTokens.values()) if (r.family === rec.family) r.revoked = true;
        return fail("refresh_token_reused");
      }
      if (rec.expired) return fail("refresh_token_expired");
      rec.used = true;
      const next = `agr_${newNonce()}${newNonce()}`;
      this.refreshTokens.set(next, { family: rec.family, used: false, revoked: false });
      const access = `refreshed-access-${newNonce()}`;
      this.validTokens.add(access);
      return send(200, { access_token: access, expires_at: new Date(Date.now() + 3_600_000).toISOString(), refresh_token: next });
    }
    if (method === "GET" && path === "/v1/keys") {
      return send(200, { approval_signing_key: { kid: "test-key-1", alg: "Ed25519", pem: this.keys.publicKeyPem } });
    }
    if (!this.validTokens.has((req.headers.authorization ?? "").replace(/^Bearer /, ""))) {
      return send(401, { error: { code: "unauthorized", message: "invalid or expired token" } });
    }
    if (method === "GET" && path === "/v1/devices/keys") {
      return send(200, { items: this.deviceKeys });
    }
    if (method === "POST" && path === "/v1/pairing") {
      return send(201, { code: "7KQ2MZ9D", expires_at: new Date(Date.now() + 300_000).toISOString(), ...(this.opts.publicUrl ? { public_url: this.opts.publicUrl } : {}) });
    }
    if (method === "POST" && path === "/v1/agents") {
      return send(200, { id: "agt_test", name: body.name, type: body.type, machine_id: body.machine_id, created_at: now() });
    }
    if (method === "POST" && path === "/v1/sessions") {
      if (this.opts.sessionDelayMs) await new Promise((r) => setTimeout(r, this.opts.sessionDelayMs));
      const id = newId("ses");
      this.createdSessions.push(id);
      return send(200, { id, agent_id: body.agent_id, status: "active", started_at: now(), ended_at: null });
    }
    let m = path.match(/^\/v1\/sessions\/([^/]+)\/end$/);
    if (method === "POST" && m) {
      this.endedSessions.push(m[1]!);
      for (const rec of this.approvals.values()) {
        if (rec.action.session_id === m[1] && rec.approval.status === "pending") rec.approval = { ...rec.approval, status: "cancelled", resolved_at: now() };
      }
      return send(200, { id: m[1], agent_id: "agt_test", status: "ended", started_at: now(), ended_at: now() });
    }
    if (method === "POST" && path === "/v1/actions") {
      if (this.opts.hangActions) return;
      const parsed = SubmitActionRequest.safeParse(body);
      if (!parsed.success) return send(400, { error: { code: "invalid_request", message: parsed.error.message } });
      const { action: draft, policy, action_hash } = parsed.data;
      if (this.endedSessions.includes(draft.session_id)) return send(409, { error: { code: "session_ended", message: "session has ended" } });
      const serverHash = computeActionHash(draft);
      if (serverHash !== action_hash) return send(422, { error: { code: "hash_mismatch", message: "hash mismatch" } });
      const action: CanonicalAction = {
        ...draft,
        action_id: newId("act"),
        created_at: now(),
        risk: { level: policy.risk, reason: policy.reason },
        resource: draft.resource ?? {},
        context: draft.context ?? {},
      };
      let approval: Approval | null = null;
      if (policy.decision === "ask") {
        const ttl = Math.min(900, Math.max(30, parsed.data.approval_ttl_seconds ?? 120));
        const requested = new Date();
        approval = {
          approval_id: newId("apr"),
          action_id: action.action_id,
          status: "pending",
          decision: null,
          requested_at: requested.toISOString(),
          expires_at: new Date(requested.getTime() + (this.opts.approvalWindowMs ?? ttl * 1000)).toISOString(),
          resolved_at: null,
          resolved_by_device_id: null,
        };
        this.approvals.set(approval.approval_id, { approval, action, actionHash: serverHash, token: null });
        const ctx: AskContext = { server: this, approval, action, actionHash: serverHash, sessionId: draft.session_id };
        const onAsk = this.opts.onAsk ?? ((c: AskContext) => c.server.resolve(c, "approved", c.server.sign(c)));
        setTimeout(() => onAsk(ctx), 50);
      }
      return send(200, { action, action_hash: serverHash, policy_decision: policy.decision, approval, execution: "not_started" });
    }
    m = path.match(/^\/v1\/actions\/([^/]+)\/execution$/);
    if (method === "POST" && m) {
      this.executions.push({ action_id: m[1]!, ...body });
      return send(200, { ok: true });
    }
    m = path.match(/^\/v1\/approvals\/([^/]+)\/cancel$/);
    if (method === "POST" && m) {
      const rec = this.approvals.get(m[1]!);
      if (!rec) return send(404, { error: { code: "not_found", message: "approval not found" } });
      if (body?.session_id && body.session_id !== rec.action.session_id) return send(403, { error: { code: "forbidden", message: "session" } });
      this.cancels.push({ approval_id: m[1]!, reason: body?.reason });
      if (rec.approval.status === "pending") {
        const ctx = { server: this, approval: rec.approval, action: rec.action, actionHash: rec.actionHash, sessionId: rec.action.session_id };
        this.resolve(ctx, "cancelled", null);
      } else if (rec.approval.status !== "cancelled") {
        return send(409, { error: { code: "approval_already_resolved", message: rec.approval.status }, approval: rec.approval });
      }
      return send(200, { approval: this.approvals.get(m[1]!)!.approval });
    }
    m = path.match(/^\/v1\/approvals\/([^/]+)$/);
    if (method === "GET" && m) {
      const rec = this.approvals.get(m[1]!);
      if (!rec) return send(404, { error: { code: "not_found", message: "no such approval" } });
      return send(200, { approval: rec.approval, action: rec.action, action_hash: rec.actionHash, agent_name: "test-host" });
    }
    return send(404, { error: { code: "not_found", message: `${method} ${path}` } });
  }
}
