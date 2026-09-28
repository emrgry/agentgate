import {
  ActionRecord,
  Agent,
  ApiError,
  ApprovalDetail,
  ApprovalToken,
  CancelApprovalResponse,
  KeysResponse,
  LoginResponse,
  PairingPendingResponse,
  PairingPollResponse,
  RefreshResponse,
  PairingResponse,
  Session,
  type SubmitActionRequest,
} from "@agentgate/protocol";
import { z } from "zod";

/**
 * Typed HTTP client for the AgentGate v1 API (docs/architecture.md §6).
 * Deliberately free of CLI concerns so it can move to `packages/sdk` unchanged.
 * Every response is validated with the protocol schema; anything unexpected throws
 * (callers on the approval path treat every throw as "block").
 */

export type ApiErrorKind = "network" | "timeout" | "http" | "invalid_response";

export class ApiRequestError extends Error {
  constructor(
    readonly kind: ApiErrorKind,
    message: string,
    readonly status?: number,
    readonly code?: string,
  ) {
    super(message);
    this.name = "ApiRequestError";
  }
}

export interface ClientOptions {
  server: string;
  accessToken?: string;
  /** Per-request timeout. Default 10 s. */
  timeoutMs?: number;
  fetch?: typeof fetch;
  /** Debug hook; receives already-redacted data (no Authorization header). */
  debug?: (msg: string, data?: unknown) => void;
}

export type ExecutionStatus = "started" | "completed" | "failed" | "blocked";

export interface ApprovalLookup {
  detail: ApprovalDetail;
  /**
   * Signed token if the server chose to include one in the detail response
   * (not part of the v1 contract; tolerated and still fully verified).
   */
  approval_token: string | null;
}

export class AgentGateClient {
  readonly server: string;
  private accessToken: string | undefined;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly debug: (msg: string, data?: unknown) => void;

  constructor(opts: ClientOptions) {
    this.server = opts.server.replace(/\/+$/, "");
    this.accessToken = opts.accessToken;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.fetchImpl = opts.fetch ?? fetch;
    this.debug = opts.debug ?? (() => {});
  }

  setAccessToken(token: string | undefined) {
    this.accessToken = token;
  }

  // ── Auth / keys ───────────────────────────────────────────────────────────
  login(email: string, client: "agent" | "device" = "agent") {
    return this.request("POST", "/v1/auth/login", LoginResponse, { email, client }, { auth: false });
  }

  /**
   * Agent login that may need phone approval: from another computer the server answers
   * 202 PairingPendingResponse; locally 200 LoginResponse.
   */
  loginAgent(email: string | undefined, extra: { machine_name?: string; platform?: "macos" | "linux" | "windows" }) {
    return this.request("POST", "/v1/auth/login", z.union([PairingPendingResponse, LoginResponse]), { ...(email ? { email } : {}), client: "agent", ...extra }, { auth: false });
  }

  /** Long-poll a pairing/login request (no bearer; the poll secret proves ownership). */
  pollPairing(id: string, secret: string, timeoutMs = 40_000) {
    return this.request("GET", `/v1/pairing/requests/${enc(id)}`, PairingPollResponse, undefined, {
      auth: false,
      timeoutMs,
      headers: { "x-pairing-secret": secret },
    });
  }

  /** Rotates the refresh token. Unauthenticated; the refresh token is the credential. */
  refresh(refreshToken: string) {
    return this.request("POST", "/v1/auth/refresh", RefreshResponse, { refresh_token: refreshToken }, { auth: false });
  }

  // ── Control Center (local agent) ──────────────────────────────────────────
  observe(provider: string, hook: Record<string, unknown>, timeoutMs = 3_000) {
    return this.request("POST", "/v1/agent-sessions/observe", null, { provider, hook }, { timeoutMs });
  }
  agentSessions(status: "active" | "all" = "all") {
    return this.request("GET", `/v1/agent-sessions?status=${status}&limit=100`, null) as Promise<{ items: any[] }>;
  }
  agentSession(id: string) {
    return this.request("GET", `/v1/agent-sessions/${enc(id)}`, null) as Promise<any>;
  }
  sessionEvents(id: string, afterSeq: number) {
    return this.request("GET", `/v1/agent-sessions/${enc(id)}/events?after_seq=${afterSeq}&limit=200`, null) as Promise<{ items: any[]; next_after_seq: number | null }>;
  }
  startAgentSession(body: { provider: string; cwd: string; prompt: string; title?: string }) {
    return this.request("POST", "/v1/agent-sessions", null, body, { timeoutMs: 30_000 }) as Promise<any>;
  }
  sessionCommand(id: string, body: Record<string, unknown>) {
    return this.request("POST", `/v1/agent-sessions/${enc(id)}/commands`, null, { body }) as Promise<any>;
  }
  sessionTasks(id: string) {
    return this.request("GET", `/v1/agent-sessions/${enc(id)}/tasks`, null) as Promise<{ items: any[] }>;
  }
  devicesList() {
    return this.request("GET", "/v1/devices", null) as Promise<{ items: any[] }>;
  }
  deviceRecovery(body: { action: "revoke" | "reset"; device_id?: string; nonce: string; proof_path: string }) {
    return this.request("POST", "/v1/devices/recovery", null, body) as Promise<{ revoked: string[]; expired_pairing_requests: number }>;
  }
  sessionMetrics(id: string) {
    return this.request("GET", `/v1/agent-sessions/${enc(id)}/metrics`, null) as Promise<any>;
  }
  usage(range: string) {
    return this.request("GET", `/v1/usage?range=${enc(range)}`, null) as Promise<any>;
  }
  providersList() {
    return this.request("GET", "/v1/providers", null) as Promise<{ items: any[] }>;
  }
  workspaces() {
    return this.request("GET", "/v1/workspaces", null) as Promise<{ items: any[] }>;
  }
  addWorkspace(path: string, label?: string) {
    return this.request("POST", "/v1/workspaces", null, { path, ...(label ? { label } : {}) }) as Promise<any>;
  }
  allowUngated(id: string, provider: string, allow: boolean) {
    return this.request("POST", `/v1/workspaces/${enc(id)}/allow-ungated`, null, { provider, allow }) as Promise<any>;
  }
  removeWorkspace(id: string) {
    return this.request("DELETE", `/v1/workspaces/${enc(id)}`, null) as Promise<unknown>;
  }

  /** GET /v1/devices/keys — device public keys (agent token, loopback only). */
  deviceKeys() {
    return this.request("GET", "/v1/devices/keys", null);
  }

  /** POST /v1/pairing — one-time device pairing code (agent token). */
  pair() {
    return this.request("POST", "/v1/pairing", PairingResponse, {});
  }

  keys() {
    return this.request("GET", "/v1/keys", KeysResponse, undefined, { auth: false });
  }

  // ── Agents & sessions ─────────────────────────────────────────────────────
  registerAgent(body: { name: string; type: string; machine_id: string }) {
    return this.request("POST", "/v1/agents", Agent, body);
  }

  createSession(agentId: string) {
    return this.request("POST", "/v1/sessions", Session, { agent_id: agentId });
  }

  endSession(sessionId: string, timeoutMs?: number) {
    return this.request("POST", `/v1/sessions/${enc(sessionId)}/end`, null, {}, { timeoutMs });
  }

  // ── Actions ───────────────────────────────────────────────────────────────
  submitAction(body: SubmitActionRequest) {
    return this.request("POST", "/v1/actions", ActionRecord, body);
  }

  reportExecution(
    actionId: string,
    body: { status: ExecutionStatus; exit_code?: number | null; detail?: string },
    timeoutMs?: number,
  ) {
    const detail = body.detail && body.detail.length > 2048 ? `${body.detail.slice(0, 2045)}...` : body.detail;
    return this.request("POST", `/v1/actions/${enc(actionId)}/execution`, null, { ...body, detail }, { timeoutMs });
  }

  // ── Approvals ─────────────────────────────────────────────────────────────
  async getApproval(approvalId: string): Promise<ApprovalLookup> {
    const raw = await this.request("GET", `/v1/approvals/${enc(approvalId)}`, null);
    const parsed = ApprovalDetail.safeParse(raw);
    if (!parsed.success) {
      throw new ApiRequestError("invalid_response", `GET /v1/approvals/:id: ${parsed.error.issues[0]?.message ?? "invalid"}`);
    }
    return { detail: parsed.data, approval_token: extractToken(raw) };
  }

  /** POST /v1/approvals/:id/cancel — agent gave up waiting. Idempotent server-side. */
  cancelApproval(approvalId: string, body: { session_id?: string; reason?: string } = {}, timeoutMs?: number) {
    return this.request("POST", `/v1/approvals/${enc(approvalId)}/cancel`, CancelApprovalResponse, body, { timeoutMs });
  }

  // ── Transport ─────────────────────────────────────────────────────────────
  private async request<S extends z.ZodTypeAny>(
    method: "GET" | "POST" | "DELETE",
    path: string,
    schema: S | null,
    body?: unknown,
    opts: { auth?: boolean; timeoutMs?: number; headers?: Record<string, string> } = {},
  ): Promise<S extends z.ZodTypeAny ? z.infer<S> : unknown> {
    const url = `${this.server}${path}`;
    const headers: Record<string, string> = { accept: "application/json", ...opts.headers };
    if (body !== undefined) headers["content-type"] = "application/json";
    if (opts.auth !== false) {
      if (!this.accessToken) throw new ApiRequestError("http", "not logged in (no access token)", 401, "unauthenticated");
      headers.authorization = `Bearer ${this.accessToken}`;
    }
    this.debug(`→ ${method} ${path}`, body);

    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(opts.timeoutMs ?? this.timeoutMs),
      });
    } catch (err) {
      const e = err as Error;
      if (e.name === "TimeoutError" || e.name === "AbortError") {
        throw new ApiRequestError("timeout", `${method} ${path}: timed out`);
      }
      const cause = (e as { cause?: { code?: string; message?: string } }).cause;
      throw new ApiRequestError("network", `${method} ${path}: ${cause?.code ?? cause?.message ?? e.message}`);
    }

    const text = await res.text().catch(() => "");
    let json: unknown = undefined;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        if (res.ok) throw new ApiRequestError("invalid_response", `${method} ${path}: response is not JSON`, res.status);
      }
    }
    this.debug(`← ${res.status} ${method} ${path}`, json);

    if (!res.ok) {
      const err = ApiError.safeParse(json);
      const code = err.success ? err.data.error.code : `http_${res.status}`;
      const msg = err.success ? err.data.error.message : res.statusText || "request failed";
      throw new ApiRequestError("http", `${method} ${path}: ${res.status} ${code}: ${msg}`, res.status, code);
    }
    if (!schema) return json as never;
    const parsed = schema.safeParse(json);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      throw new ApiRequestError(
        "invalid_response",
        `${method} ${path}: unexpected response shape (${issue?.path.join(".") ?? ""}: ${issue?.message ?? "invalid"})`,
        res.status,
      );
    }
    return parsed.data;
  }
}

function enc(s: string) {
  return encodeURIComponent(s);
}

function extractToken(raw: unknown): string | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const approval = r.approval as Record<string, unknown> | undefined;
  for (const candidate of [r.approval_token, approval?.approval_token]) {
    const ok = ApprovalToken.safeParse(candidate);
    if (ok.success) return ok.data;
  }
  return null;
}
