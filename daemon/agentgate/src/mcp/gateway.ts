import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { hostname } from "node:os";
import { ActionDraft } from "@agentgate/protocol";
import { authorizeAction, describeError } from "../authorize.ts";
import { AgentGateClient } from "../client/index.ts";
import { paths, type LoggedInConfig } from "../config.ts";
import { EXIT } from "../exit-codes.ts";
import { detectGit } from "../git.ts";
import { FileNonceStore } from "../nonce-store.ts";
import { log } from "../output.ts";
import { loadEffectivePolicy } from "../policy.ts";
import { blockInfo, reportBlocked, requireLogin } from "../runtime.ts";
import { gateExecution } from "../verify.ts";
import { gateContext } from "../device-keys.ts";

/**
 * `agentgate mcp wrap --name <server> -- <upstream command…>` — stdio MCP gateway.
 *
 * A raw, newline-delimited JSON-RPC relay between an MCP client (our stdin/stdout) and the
 * upstream MCP server (child process). Every message passes through byte-for-byte EXCEPT
 * client→server `tools/call` requests, which are authorized first:
 *   policy → report → (ask) phone approval → verify signed token (pinned key, nonce) →
 *   forward the exact request → report completed/failed from the response.
 * Anything else — deny, denied, expired, cancelled, API down, gateway error — is answered
 * by the gateway itself with a CallToolResult {isError:true} and NEVER forwarded.
 * The gateway is the executor, so there is no gap between what was approved and what runs.
 *
 * stdout is the protocol channel: all logging goes to stderr.
 */

export interface GatewayOptions {
  name: string;
  command: string;
  args: string[];
  env?: string;
  ttl: number;
  /** Progress heartbeat while waiting (ms). */
  progressMs?: number;
}

type Json = Record<string, unknown>;
type Id = string | number;

interface ToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

interface GatedCall {
  id: Id;
  tool: string;
  abort: AbortController;
  state: "authorizing" | "forwarded" | "done";
  actionId: string | null;
  progress: NodeJS.Timeout | null;
}

const idKey = (id: Id) => `${typeof id}:${id}`;

/** MCP clientInfo.name → AgentGate agent.type. */
export function normalizeClient(name: string | undefined): string {
  const n = (name ?? "").toLowerCase();
  if (!n) return "mcp-client";
  if (n === "claude-ai" || n.includes("claude desktop") || n.includes("claude-desktop")) return "claude-desktop";
  if (n.includes("claude-code") || n.includes("claude code")) return "claude-code";
  if (n.includes("cursor")) return "cursor";
  if (n.includes("codex")) return "codex";
  if (n.includes("windsurf")) return "windsurf";
  if (n.includes("vscode") || n.includes("visual studio code")) return "vscode";
  return "mcp-client";
}

/**
 * Risk the gateway asserts from tool annotations. Per the MCP spec the defaults are
 * readOnlyHint=false, destructiveHint=true, openWorldHint=true — so an unannotated tool is
 * presumed destructive. Annotations come from the (untrusted) server: they can only raise
 * risk here, never lower it below what the policy engine infers.
 */
export function annotationRisk(a: ToolAnnotations | null): { level: "high"; reason: string } | undefined {
  if (!a) return { level: "high", reason: "MCP tool without known annotations (presumed destructive)" };
  if (a.readOnlyHint === true) return undefined;
  if (a.destructiveHint !== false) return { level: "high", reason: "MCP tool may perform destructive updates" };
  if (a.openWorldHint !== false) return { level: "high", reason: "MCP tool interacts with external systems" };
  return undefined;
}

export class McpGateway {
  private upstream!: ChildProcessByStdio<Writable, Readable, null>;
  private clientName: string | undefined;
  private clientVersion: string | undefined;
  private initialized = false;
  private readonly tools = new Map<string, ToolAnnotations | null>();
  private toolsFresh = false;
  private readonly clientToolsListIds = new Set<string>();
  private readonly internal = new Map<string, (msg: Json) => void>();
  private internalSeq = 0;
  private readonly internalPrefix = `agentgate-${Math.random().toString(36).slice(2, 8)}-`;
  private readonly calls = new Map<string, GatedCall>();
  /** Non-gated client requests forwarded upstream and not yet answered (for crash errors). */
  private readonly pendingClient = new Map<string, Id>();
  private session: Promise<{ client: AgentGateClient; config: LoggedInConfig; sessionId: string }> | null = null;
  private sessionId: string | null = null;
  private sessionClient: AgentGateClient | null = null;
  private closing = false;
  private readonly git = detectGit(process.cwd());

  constructor(private readonly o: GatewayOptions) {}

  run(): Promise<number> {
    return new Promise((resolveRun) => {
      try {
        this.upstream = spawn(this.o.command, this.o.args, { stdio: ["pipe", "pipe", "inherit"], env: process.env });
      } catch (err) {
        log.fail(`cannot start upstream MCP server: ${(err as Error).message}`);
        return resolveRun(EXIT.ERROR);
      }
      this.upstream.on("error", (err) => log.fail(`upstream MCP server error: ${err.message}`));
      lines(process.stdin, (l) => this.fromClient(l), () => void this.shutdown("client closed stdin", 0).then(resolveRun));
      lines(this.upstream.stdout, (l) => this.fromUpstream(l), () => {});
      this.upstream.on("exit", (code, signal) => {
        if (this.closing) return;
        log.warn(`upstream MCP server exited (${signal ?? code})`);
        void this.shutdown("upstream exited", code ?? 1).then(resolveRun);
      });
      for (const s of ["SIGINT", "SIGTERM", "SIGHUP"] as const) process.on(s, () => void this.shutdown(`signal ${s}`, 0).then(resolveRun));
    });
  }

  // ── plumbing ──────────────────────────────────────────────────────────────

  private toClient(msg: Json | string) {
    process.stdout.write(`${typeof msg === "string" ? msg : JSON.stringify(msg)}\n`);
  }

  private toUpstream(raw: string) {
    if (this.upstream.stdin.writable) this.upstream.stdin.write(`${raw}\n`);
  }

  private fromClient(line: string) {
    if (!line.trim()) return;
    let msg: unknown;
    try {
      msg = JSON.parse(line);
    } catch {
      // Fail closed: never forward bytes we could not inspect.
      return this.toClient({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error (AgentGate gateway)" } });
    }
    if (Array.isArray(msg)) {
      // JSON-RPC batch (older MCP revisions): inspect every element individually.
      if (msg.some((m) => isToolsCall(m))) {
        for (const m of msg) this.fromClientMessage(m as Json, JSON.stringify(m));
        return;
      }
      if (/"method"\s*:\s*"tools\/call"/.test(line)) {
        return this.toClient({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Ambiguous batch refused by AgentGate" } });
      }
      return this.toUpstream(line);
    }
    this.fromClientMessage(msg as Json, line);
  }

  private fromClientMessage(msg: Json, raw: string) {
    if (!msg || typeof msg !== "object") return this.toUpstream(raw);
    const method = msg.method;
    // Parser-differential guard: a line that mentions tools/call but does not parse as one
    // (e.g. duplicate "method" keys) is refused rather than forwarded.
    if (method !== "tools/call" && /"method"\s*:\s*"tools\/call"/.test(raw)) {
      if ("id" in msg) return this.toClient({ jsonrpc: "2.0", id: msg.id as Id, error: { code: -32600, message: "Ambiguous request refused by AgentGate" } });
      return;
    }
    if (method === "initialize" && isObj(msg.params)) {
      const ci = (msg.params as Json).clientInfo as Json | undefined;
      this.clientName = typeof ci?.name === "string" ? ci.name : undefined;
      this.clientVersion = typeof ci?.version === "string" ? ci.version : undefined;
    }
    if (method === "notifications/initialized") this.initialized = true;
    if (method === "tools/list" && "id" in msg) this.clientToolsListIds.add(idKey(msg.id as Id));
    if (method === "notifications/cancelled" && isObj(msg.params)) {
      const rid = (msg.params as Json).requestId as Id | undefined;
      const call = rid !== undefined ? this.calls.get(idKey(rid)) : undefined;
      if (call && call.state === "authorizing") {
        // Not forwarded yet: stop here. Cancels the pending approval; no response is sent.
        call.abort.abort();
        return;
      }
    }
    if (method === "tools/call" && "id" in msg) return void this.gate(msg);
    if (typeof method === "string" && "id" in msg && (typeof msg.id === "string" || typeof msg.id === "number")) {
      this.pendingClient.set(idKey(msg.id), msg.id);
    }
    this.toUpstream(raw);
  }

  private fromUpstream(line: string) {
    if (!line.trim()) return;
    let msg: Json | null = null;
    try {
      const m = JSON.parse(line);
      msg = isObj(m) ? (m as Json) : null;
    } catch {
      /* pass through untouched */
    }
    if (msg && msg.method === undefined && "id" in msg) {
      const k = idKey(msg.id as Id);
      const internal = typeof msg.id === "string" ? this.internal.get(msg.id) : undefined;
      if (internal) {
        this.internal.delete(msg.id as string);
        return internal(msg);
      }
      this.pendingClient.delete(k);
      if (this.clientToolsListIds.delete(k)) this.cacheTools(msg);
      const call = this.calls.get(k);
      if (call && call.state === "forwarded") this.completed(call, msg);
    }
    if (msg && msg.method === "notifications/tools/list_changed") {
      this.toolsFresh = false;
      this.tools.clear();
    }
    this.toClient(line);
  }

  private cacheTools(resp: Json) {
    const tools = (resp.result as Json | undefined)?.tools;
    if (!Array.isArray(tools)) return;
    for (const t of tools) {
      if (isObj(t) && typeof (t as Json).name === "string") {
        const a = (t as Json).annotations;
        this.tools.set((t as Json).name as string, isObj(a) ? (a as ToolAnnotations) : null);
      }
    }
  }

  /** Our own tools/list (all pages) to learn annotations; never visible to the client. */
  private async refreshTools(): Promise<void> {
    if (!this.initialized) return;
    let cursor: string | undefined;
    for (let page = 0; page < 20; page++) {
      const resp = await this.internalRequest("tools/list", cursor ? { cursor } : {});
      this.cacheTools(resp);
      const next = (resp.result as Json | undefined)?.nextCursor;
      if (typeof next !== "string" || !next) break;
      cursor = next;
    }
    this.toolsFresh = true;
  }

  private internalRequest(method: string, params: Json): Promise<Json> {
    const id = `${this.internalPrefix}${++this.internalSeq}`;
    return new Promise((resolveP, reject) => {
      const t = setTimeout(() => {
        this.internal.delete(id);
        reject(new Error(`${method} timed out`));
      }, 5_000);
      this.internal.set(id, (m) => {
        clearTimeout(t);
        resolveP(m);
      });
      this.toUpstream(JSON.stringify({ jsonrpc: "2.0", id, method, params }));
    });
  }

  // ── gating ────────────────────────────────────────────────────────────────

  private async ensureSession() {
    this.session ??= (async () => {
      const config = await requireLogin();
      const client = new AgentGateClient({ server: config.server, accessToken: config.access_token, debug: (m) => log.debug(m) });
      const agentType = normalizeClient(this.clientName);
      const agent = await client.registerAgent({ name: `${hostname()} · ${this.o.name}`.slice(0, 128), type: `mcp-${agentType}`.slice(0, 64), machine_id: config.machine_id });
      const s = await client.createSession(agent.id);
      this.sessionId = s.id;
      this.sessionClient = client;
      log.step(`MCP gateway session ${s.id} (${this.o.name}, client ${this.clientName ?? "unknown"})`);
      return { client, config, sessionId: s.id };
    })();
    try {
      const s = await this.session;
      // Access tokens rotate: use a fresh client for each call.
      const config = await requireLogin();
      return { ...s, config, client: new AgentGateClient({ server: config.server, accessToken: config.access_token, debug: (m) => log.debug(m) }) };
    } catch (err) {
      this.session = null; // retry next time; this call is blocked
      throw err;
    }
  }

  buildDraft(sessionId: string, tool: string, args: unknown, annotations: ToolAnnotations | null): ActionDraft {
    const risk = annotationRisk(annotations);
    const context: Record<string, string> = { hostname: hostname(), mcp_server: this.o.name };
    if (this.clientName) context.mcp_client = this.clientName.slice(0, 256);
    if (this.git.repo) context.repo = this.git.repo;
    if (this.git.branch) context.branch = this.git.branch;
    const agentType = normalizeClient(this.clientName);
    return ActionDraft.parse({
      session_id: sessionId,
      agent: this.clientVersion ? { type: agentType, version: this.clientVersion.slice(0, 64) } : { type: agentType },
      action: {
        category: "mcp",
        operation: "invoke",
        tool: `${this.o.name}/${tool}`.slice(0, 128),
        arguments: { server: this.o.name, tool, arguments: isObj(args) ? args : {}, annotations: annotations ?? {} },
        cwd: process.cwd(),
      },
      resource: { type: "mcp_server", name: this.o.name, ...(this.o.env ? { environment: this.o.env } : {}) },
      context,
      ...(risk ? { risk } : {}),
    });
  }

  private async gate(msg: Json) {
    const id = msg.id as Id;
    const params = isObj(msg.params) ? (msg.params as Json) : {};
    const tool = typeof params.name === "string" ? params.name : "";
    const call: GatedCall = { id, tool, abort: new AbortController(), state: "authorizing", actionId: null, progress: null };
    this.calls.set(idKey(id), call);
    const progressToken = isObj(params._meta) ? ((params._meta as Json).progressToken as string | number | undefined) : undefined;
    let approvalId: string | null = null;
    if (progressToken !== undefined) {
      const started = Date.now();
      call.progress = setInterval(() => {
        if (call.state !== "authorizing") return;
        this.toClient({
          jsonrpc: "2.0",
          method: "notifications/progress",
          params: {
            progressToken,
            progress: Math.round((Date.now() - started) / 1000),
            message: `Waiting for approval on your phone… (AgentGate${approvalId ? ` ${approvalId}` : ""})`,
          },
        });
      }, this.o.progressMs ?? 5_000);
    }

    let client: AgentGateClient | null = null;
    try {
      if (!tool) throw Object.assign(new Error("tools/call without a tool name"), { reason: "invalid_request" });
      if (!this.toolsFresh || !this.tools.has(tool)) await this.refreshTools().catch((e) => log.debug(`tools/list refresh failed: ${(e as Error).message}`));
      const annotations = this.tools.get(tool) ?? null;
      const s = await this.ensureSession();
      client = s.client;
      const draft = this.buildDraft(s.sessionId, tool, params.arguments, annotations);
      const auth = await authorizeAction(
        {
          client: s.client,
          config: s.config,
          policy: loadEffectivePolicy(),
          signal: call.abort.signal,
          ttl: this.o.ttl,
          onActionId: (aid) => (call.actionId = aid),
          onApproval: (aid) => (approvalId = aid),
        },
        draft,
      );
      if (call.abort.signal.aborted) throw new Error("cancelled by the client");
      if (auth.kind === "approved") {
        const gctx = await gateContext(s.client, s.config, auth.token);
        const gate = gateExecution({
          ...gctx,
          token: auth.token,
          executable: draft,
          publicKeyPem: s.config.signing_key.pem,
          approvalId: auth.approvalId,
          actionId: auth.actionId,
          sessionId: s.sessionId,
          nonceStore: new FileNonceStore(paths.nonces()),
          requireCommand: false,
        });
        if (!gate.ok) throw Object.assign(new Error(`approval token rejected (${gate.reason}): ${gate.detail}`), { reason: `token_${gate.reason}` });
      }
      if (this.closing) throw new Error("gateway is shutting down");
      await s.client.reportExecution(auth.actionId, { status: "started" }, 3_000).catch((e) => log.warn(`could not report start: ${describeError(e)}`));
      call.state = "forwarded";
      this.stopProgress(call);
      // Forward exactly what was hashed: same id, name and arguments (re-serialized from the
      // parsed message, so the upstream sees precisely the arguments we inspected).
      this.toUpstream(JSON.stringify(msg));
      log.step(`→ forwarded ${this.o.name}/${tool} (${auth.kind === "approved" ? "approved" : "allowed by policy"})`);
    } catch (err) {
      this.stopProgress(call);
      call.state = "done";
      this.calls.delete(idKey(id));
      const b = blockInfo(err);
      const reason = (err as { reason?: string }).reason ?? b.reason;
      if (client) await reportBlocked(client, call.actionId, `${reason}: ${b.message}`);
      if (call.abort.signal.aborted) {
        log.step(`✖ ${this.o.name}/${tool} cancelled by the client (not forwarded)`);
        return; // cancelled requests get no response (MCP cancellation semantics)
      }
      log.fail(`✖ blocked ${this.o.name}/${tool} [${reason}]: ${b.message}`);
      this.toClient({
        jsonrpc: "2.0",
        id,
        result: { isError: true, content: [{ type: "text", text: `Blocked by AgentGate: ${b.message}` }] },
      });
    }
  }

  private stopProgress(call: GatedCall) {
    if (call.progress) clearInterval(call.progress);
    call.progress = null;
  }

  private completed(call: GatedCall, resp: Json) {
    call.state = "done";
    this.calls.delete(idKey(call.id));
    const isError = "error" in resp || (isObj(resp.result) && (resp.result as Json).isError === true);
    const client = this.sessionClient;
    if (!client || !call.actionId) return;
    const detail = "error" in resp ? `JSON-RPC error: ${String((resp.error as Json)?.message ?? "")}`.slice(0, 500) : isError ? "tool returned isError" : undefined;
    void requireLogin()
      .then((cfg) => new AgentGateClient({ server: cfg.server, accessToken: cfg.access_token }))
      .catch(() => client)
      .then((c) => c.reportExecution(call.actionId!, { status: isError ? "failed" : "completed", exit_code: null, ...(detail ? { detail } : {}) }, 3_000))
      .catch((e) => log.warn(`could not report result: ${describeError(e)}`));
  }

  // ── shutdown ──────────────────────────────────────────────────────────────

  private shutdownPromise: Promise<number> | null = null;
  private shutdown(why: string, code: number): Promise<number> {
    this.shutdownPromise ??= (async () => {
      this.closing = true;
      log.debug(`gateway shutting down: ${why}`);
      const upstreamGone = why === "upstream exited";
      for (const call of [...this.calls.values()]) {
        if (call.state === "authorizing") call.abort.abort();
        if (call.state === "forwarded" || upstreamGone) {
          this.toClient({ jsonrpc: "2.0", id: call.id, error: { code: -32000, message: `AgentGate gateway: upstream MCP server ${upstreamGone ? "exited" : "closed"} before responding` } });
          if (this.sessionClient && call.actionId) {
            await this.sessionClient
              .reportExecution(call.actionId, { status: "failed", exit_code: null, detail: `upstream ${upstreamGone ? "exited" : "closed"}` }, 2_000)
              .catch(() => {});
          }
        }
        this.stopProgress(call);
      }
      this.calls.clear();
      if (upstreamGone) {
        for (const id of this.pendingClient.values()) {
          this.toClient({ jsonrpc: "2.0", id, error: { code: -32000, message: "AgentGate gateway: upstream MCP server exited before responding" } });
        }
      }
      this.pendingClient.clear();
      if (this.sessionId && this.sessionClient) {
        await this.sessionClient.endSession(this.sessionId, 3_000).catch((e) => log.debug(`end session failed: ${describeError(e)}`));
      }
      if (!upstreamGone) {
        this.upstream.stdin.end();
        const exited = new Promise<void>((r) => this.upstream.once("exit", () => r()));
        const t = setTimeout(() => this.upstream.kill("SIGTERM"), 2_000);
        await Promise.race([exited, new Promise((r) => setTimeout(r, 4_000))]);
        clearTimeout(t);
      }
      return upstreamGone ? (code === 0 ? 0 : 1) : code;
    })();
    return this.shutdownPromise;
  }
}

function isObj(v: unknown): v is Json {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function isToolsCall(m: unknown): boolean {
  return isObj(m) && m.method === "tools/call";
}

/** Newline-delimited reader (MCP stdio framing). Keeps \r if present (raw pass-through). */
function lines(stream: NodeJS.ReadableStream, onLine: (l: string) => void, onEnd: () => void) {
  let buf = "";
  stream.setEncoding("utf8");
  stream.on("data", (chunk: string) => {
    buf += chunk;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const l = buf.slice(0, i);
      buf = buf.slice(i + 1);
      onLine(l);
    }
  });
  stream.on("end", () => {
    if (buf) onLine(buf);
    onEnd();
  });
}
