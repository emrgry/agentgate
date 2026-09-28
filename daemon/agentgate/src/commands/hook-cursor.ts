import { appendFileSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { ActionDraft } from "@agentgate/protocol";
import {
  canonicalEvent,
  conversationKey,
  CursorAdapter,
  cwdOf,
  INSTALL_MARKER,
  isGateEvent,
  parseGateInput,
  PROVIDER_ARG,
  renderAllow,
  renderDeny,
  type CursorGateInput,
  type CursorPermissionOutput,
  type NormalizeOptions,
} from "@agentgate/adapter-cursor";
import { authorizeAction, cancelApprovalQuietly, describeError, SessionGoneError, type Authorized } from "../authorize.ts";
import { forgetHookSession, replaceHookSession, resolveHookSession } from "../claude-sessions.ts";
import { AgentGateClient } from "../client/index.ts";
import { agentgateHome, paths } from "../config.ts";
import { gateContext } from "../device-keys.ts";
import { bindExecContext, computeExecContext, diffExecContext, type ExecContext } from "../exec-context.ts";
import { EXIT, ExitError } from "../exit-codes.ts";
import { detectGit } from "../git.ts";
import { clearPending, listPending, markPending } from "../hook-state.ts";
import { layout } from "../install-layout.ts";
import { isWrapped, shimPath } from "../mcp/install.ts";
import { FileNonceStore } from "../nonce-store.ts";
import { log, setSink } from "../output.ts";
import { loadEffectivePolicy } from "../policy.ts";
import { blockInfo, reportBlocked, requireLogin, SignalScope } from "../runtime.ts";
import { gateExecution } from "../verify.ts";
import { hookTimeoutSeconds, protectedDirs } from "./hook.ts";
import { CURSOR_OUR_EVENTS, projectCursorHooksPath, userCursorHooksPath } from "./install-cursor.ts";

/**
 * `agentgate hook cursor` — Cursor agent-hook entry (via bin/agentgate-hook.sh
 * --agentgate-provider=cursor). docs/cursor.md has the verified contract.
 *
 * Gating events (beforeShellExecution, beforeMCPExecution, beforeReadFile, preToolUse):
 *   stdout is ALWAYS exactly one permission JSON: {"permission":"allow"} or
 *   {"permission":"deny","user_message":…,"agent_message":…}; exit 0.
 *   Never Cursor's own "ask": an `ask` policy decision creates an AgentGate approval, pushes
 *   it to the phone and BLOCKS until the phone's signed decision arrives; the decision is
 *   verified against the pinned device key and its one-time nonce is consumed HERE (Cursor
 *   cannot run a rewritten command, so there is no `agentgate exec` step).
 * Fail-closed, three layers: every handled error → deny JSON; an internal deadline
 * (hook timeout − 15 s) → deny JSON; a crash / anything but exit 0|2 → the shim exits 2
 * (Cursor: deny), and the hooks.json entries carry `failClosed: true` (crash/timeout/no
 * output → block).
 *
 * sessionEnd: fire-and-forget cleanup (cancel pending approvals, end the mapped session).
 */

const DEADLINE_MARGIN_S = 15;
const SESSION_END_BUDGET_MS = 5_000;
/** beforeReadFile carries the whole file content. */
const MAX_STDIN_BYTES = 64 * 1024 * 1024;

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

export interface CursorHookOptions {
  /** Already-parsed stdin (when invoked through the Claude Code hook). */
  preparsed?: unknown;
  mode?: NormalizeOptions["mode"];
}

export async function cursorHookCommand(o: CursorHookOptions = {}): Promise<number> {
  setSink((line) => {
    try {
      appendFileSync(paths.hookLog(), `${new Date().toISOString()} [cursor] ${line}\n`, { mode: 0o600 });
    } catch {
      /* logging never changes the decision */
    }
  });
  const mode = o.mode ?? "native";
  let event = "";
  let answered = false;
  const respond = (v: CursorPermissionOutput | Json) => {
    if (answered) return;
    answered = true;
    process.stdout.write(`${JSON.stringify(v)}\n`);
  };
  const deny = (message: string, reason: string) => {
    log.fail(`hook denied [${reason}]: ${message}`);
    const m = denyMessages(message, reason);
    respond(renderDeny(event, m.user, m.agent));
    return EXIT.OK;
  };

  const budgetMs = (hookTimeoutSeconds() - DEADLINE_MARGIN_S) * 1000;
  const started = Date.now();
  let waitingOn: { approvalId: string; sessionId: string; client: AgentGateClient } | null = null;
  const deadline = setTimeout(() => {
    // Answer before Cursor's own timeout; take the request off the phone (≤ 3 s).
    const exit = () => {
      if (answered) return process.exit(EXIT.OK);
      const m = denyMessages(`no decision within the hook deadline (${Math.round(budgetMs / 1000)}s)`, "hook_deadline");
      log.fail("hook denied [hook_deadline]");
      answered = true;
      process.stdout.write(`${JSON.stringify(renderDeny(event, m.user, m.agent))}\n`, () => process.exit(EXIT.OK));
    };
    const hard = setTimeout(() => process.exit(2), 4_500);
    hard.unref();
    const w = waitingOn;
    if (!w) exit();
    else
      void cancelApprovalQuietly(w.client, w.approvalId, w.sessionId, "hook_deadline").finally(() => {
        clearPending(w.approvalId);
        exit();
      });
  }, Math.max(0, budgetMs));

  try {
    if (budgetMs <= 0) return deny(`hook timeout too short (${hookTimeoutSeconds()}s ≤ ${DEADLINE_MARGIN_S}s margin)`, "config");
    let json: unknown = o.preparsed;
    if (json === undefined) {
      const raw = await readStdin(MAX_STDIN_BYTES);
      try {
        json = JSON.parse(raw);
      } catch (err) {
        throw new Error(`invalid hook input (${(err as Error).message.split("\n")[0]})`);
      }
    }
    event = canonicalEvent(isObj(json) ? json.hook_event_name : undefined);

    if (event === "sessionEnd") {
      await sessionEnd(conversationKey(json));
      respond({});
      return EXIT.OK;
    }
    if (!isGateEvent(event)) {
      // Not registered by us (or a Claude-import observe event): no opinion, never blocks.
      log.debug(`ignoring event '${event}'`);
      if (mode === "native") respond({});
      return EXIT.OK;
    }

    const g = parseGateInput(json);
    const roots = workspaceRoots(json);
    if (mode === "claude-import" && g.event === "preToolUse" && nativeCursorHookFor(roots)) {
      // Cursor also runs the native AgentGate hook for this call; answering allow here
      // cannot loosen it (Cursor merges: deny > ask > allow).
      log.debug("Cursor-imported Claude hook: native Cursor hook installed — deferring");
      respond(renderAllow());
      return EXIT.OK;
    }
    const out = await gate(g, json, roots, mode, {
      remainingMs: () => budgetMs - (Date.now() - started),
      onApproval: (w) => (waitingOn = w),
    });
    respond(out);
    return EXIT.OK;
  } catch (err) {
    const b = blockInfo(err);
    return deny(b.message, b.reason);
  } finally {
    clearTimeout(deadline);
  }
}

// ── gating ──────────────────────────────────────────────────────────────────

interface GateDeps {
  remainingMs: () => number;
  onApproval: (w: { approvalId: string; sessionId: string; client: AgentGateClient } | null) => void;
}

async function gate(g: CursorGateInput, json: unknown, roots: string[], mode: NormalizeOptions["mode"], deps: GateDeps): Promise<CursorPermissionOutput> {
  const rawCwd = cwdOf(g) ?? process.env.CURSOR_PROJECT_DIR;
  if (!rawCwd) throw new Error("no working directory in the hook input (cwd / workspace_roots)");
  const cwd = realpathSync(rawCwd);
  const git = detectGit(cwd);
  const home = homedir();
  const adapter = new CursorAdapter({
    homeDir: home,
    projectRoot: git.root ? realpathSync(git.root) : cwd,
    agentgateHome: agentgateHome(),
    protectedDirs: protectedDirs(),
  });
  const ctx = {
    cwd,
    ...(git.repo ? { repo: git.repo } : {}),
    ...(git.branch ? { branch: git.branch } : {}),
    ...(process.env.AGENTGATE_ENV ? { environment: process.env.AGENTGATE_ENV } : {}),
  };
  const nopts: NormalizeOptions = { mode };
  // Ungoverned calls must not create sessions or touch the network.
  const probe = adapter.normalize(g, { ...ctx, session_id: "ses_pending" }, nopts);
  if (!probe) return renderAllow();
  if (g.event === "beforeMCPExecution" && mode === "native" && gatewayHandles(g, roots)) {
    // Already behind `agentgate mcp wrap`: the gateway asks/verifies for this exact call.
    log.step(`MCP ${g.input.mcp_server_name}/${g.input.tool_name}: wrapped by the AgentGate gateway — deciding there`);
    return renderAllow();
  }
  const guard = adapter.guard(g, cwd, nopts);

  const key = conversationKey(json);
  const envSession = process.env.AGENTGATE_SESSION_ID;
  if (!envSession && !key) throw new Error("no AgentGate session: the hook input has no conversation_id");

  const policy = loadEffectivePolicy();
  const config = await requireLogin();
  const client = new AgentGateClient({ server: config.server, accessToken: config.access_token, debug: log.debug });

  // Shell: bind the approval to what the command resolves to now (binaries, scripts, push
  // targets) and re-check it right before answering (shrinks the TOCTOU window to ms).
  const command = probe.action.category === "shell" ? (probe.action.command ?? "") : null;
  const execCtx = (): ExecContext | null =>
    command !== null ? computeExecContext(command, cwd, { path: process.env.PATH ?? "/usr/bin:/bin", gitHooks: "allowed" }) : null;
  const approvedCtx = execCtx();
  const draftFor = (sid: string): ActionDraft => {
    const d = adapter.normalize(g, { ...ctx, session_id: sid }, nopts)!;
    return approvedCtx ? bindExecContext(d, approvedCtx) : d;
  };

  let sessionId = envSession ?? (await resolveHookSession(client, config, key!));
  const scope = new SignalScope().install();
  let actionId: string | null = null;
  let pendingId: string | null = null;
  try {
    const ttl = Number(process.env.AGENTGATE_TTL) > 0 ? Math.floor(Number(process.env.AGENTGATE_TTL)) : 120;
    const authorize = (sid: string) =>
      authorizeAction(
        {
          client,
          config,
          policy,
          signal: scope.abort.signal,
          ttl,
          maxWaitMs: Math.max(0, deps.remainingMs() - 2_000),
          ...(guard ? { floor: guard } : {}),
          onActionId: (id) => (actionId = id),
          onApproval: (approvalId) => {
            pendingId = approvalId;
            deps.onApproval({ approvalId, sessionId: sid, client });
            markPending({ approval_id: approvalId, session_id: sid, ...(key ? { claude_session_id: key } : {}), pid: process.pid });
          },
        },
        draftFor(sid),
      );
    let draft = draftFor(sessionId);
    let auth: Authorized;
    try {
      auth = await authorize(sessionId);
    } catch (err) {
      if (envSession || !(err instanceof SessionGoneError)) throw err;
      log.warn(`${err.message}; starting a new AgentGate session`);
      sessionId = await replaceHookSession(client, config, key!, sessionId);
      draft = draftFor(sessionId);
      auth = await authorize(sessionId);
    }

    const why = `${auth.evaluation.rule_id ? `rule ${auth.evaluation.rule_id}` : "default"}, risk ${auth.evaluation.risk.level}`;
    if (auth.kind === "approved") {
      // Verify the phone's signed decision against the pinned device key and consume its
      // one-time nonce: an approval is good for exactly this one call.
      const gctx = await gateContext(client, config, auth.token);
      const v = gateExecution({
        ...gctx,
        token: auth.token,
        executable: draft,
        publicKeyPem: config.signing_key.pem,
        approvalId: auth.approvalId,
        actionId: auth.actionId,
        sessionId,
        nonceStore: new FileNonceStore(paths.nonces()),
        requireCommand: false,
      });
      if (!v.ok) throw new ExitError(EXIT.BLOCKED, `approval token rejected (${v.reason}): ${v.detail}`, `token_${v.reason}`);
      if (approvedCtx) {
        const now = execCtx()!;
        const diff = diffExecContext(approvedCtx, now);
        if (diff) throw new ExitError(EXIT.BLOCKED, `what the command would run changed while waiting for approval (${diff.detail})`, `exec_context_${diff.reason}`);
      }
      log.ok(`approved${auth.approvedBy ? ` by device ${auth.approvedBy}` : ""} (${why}); decision verified and consumed`);
    } else {
      log.ok(`allowed by policy (${why})`);
    }
    return renderAllow();
  } catch (err) {
    const b = blockInfo(err);
    await reportBlocked(client, actionId, `${b.reason}: ${b.message}`);
    throw err;
  } finally {
    if (pendingId) clearPending(pendingId);
    deps.onApproval(null);
    scope.uninstall();
  }
}

/** User-facing / agent-facing texts for a denial (the agent must not route around the gate). */
export function denyMessages(message: string, reason: string): { user: string; agent: string } {
  const noRetry = "Do not retry it or work around it; ask the user how to proceed.";
  if (reason === "device_denied") {
    return { user: "AgentGate: denied on your phone.", agent: `The user denied this action on their phone (AgentGate). ${noRetry}` };
  }
  if (reason === "policy_denied" || reason === "server_policy_denied") {
    return { user: `AgentGate blocked this: ${message}`, agent: `AgentGate policy blocked this action: ${message}. ${noRetry}` };
  }
  if (["approval_timeout", "hook_deadline", "approval_expired", "approval_cancelled", "interrupted"].includes(reason)) {
    return {
      user: `AgentGate: no approval from your phone in time (${message}). Approve on your phone, then retry.`,
      agent:
        "This action needs the user's approval on their phone (AgentGate) and no decision arrived in time, so it was blocked. " +
        "Tell the user to keep their phone at hand and approve the request, then retry the exact same action once.",
    };
  }
  if (["server_unreachable", "login_required", "unauthorized", "realtime_unavailable", "server_error"].includes(reason)) {
    return {
      user: `AgentGate is unavailable (${message}) — blocked (fail-closed). Check \`agentgate status\`.`,
      agent: `The user's approval gate (AgentGate) is unavailable, so this action was blocked (fail-closed). ${noRetry}`,
    };
  }
  if (reason.startsWith("token_") || reason.startsWith("exec_context_")) {
    return { user: `AgentGate: the approval could not be verified (${message}) — blocked.`, agent: `AgentGate could not verify the approval for this action, so it was blocked. ${noRetry}` };
  }
  return { user: `AgentGate blocked this action: ${message} [${reason}]`, agent: `AgentGate blocked this action (${message}). ${noRetry}` };
}

// ── MCP gateway coexistence ─────────────────────────────────────────────────

/**
 * True only if this stdio MCP server is launched through `agentgate mcp wrap` in EVERY
 * Cursor mcp.json that defines it (user + workspace roots) and Cursor's reported launch
 * command is our shim: then the gateway gates the call and the hook stays out of the way.
 * Anything else (HTTP/SSE, plugin servers, unknown names, partial wrapping) → the hook gates.
 */
export function gatewayHandles(g: CursorGateInput, roots: string[], home = homedir()): boolean {
  if (g.event !== "beforeMCPExecution") return false;
  const name = g.input.mcp_server_name;
  if (!name || g.input.url || g.input.mcp_server_url) return false;
  const shim = shimPath();
  const launched = g.input.command;
  if (typeof launched !== "string" || !launched.startsWith(shim) || !launched.includes(` mcp wrap --name ${name} `)) return false;
  const defs: unknown[] = [];
  for (const f of [join(home, ".cursor", "mcp.json"), ...roots.map((r) => join(r, ".cursor", "mcp.json"))]) {
    try {
      const d = JSON.parse(readFileSync(f, "utf8")) as Json;
      if (isObj(d.mcpServers) && name in d.mcpServers) defs.push(d.mcpServers[name]);
    } catch {
      /* no such config */
    }
  }
  return defs.length > 0 && defs.every((e) => isWrapped(e) && isObj(e) && e.command === shim);
}

// ── Claude Code hook import coexistence ─────────────────────────────────────

const shQuoted = (p: string) => `'${p.replace(/'/g, `'\\''`)}'`;

/**
 * A genuine native AgentGate Cursor hook (not just the marker string) covers these roots:
 * every gating event has our exact command shape, pointing at this installation's shim,
 * with failClosed. Used to decide whether the Cursor-imported Claude hook may defer.
 */
export function nativeCursorHookFor(roots: string[]): boolean {
  const files = [userCursorHooksPath(), ...roots.filter((r) => typeof r === "string" && r).map(projectCursorHooksPath)];
  const shim = layout().hookShim;
  const tail = `(?:${escapeRe(shQuoted(shim))}|${escapeRe(shim)}) ${escapeRe(PROVIDER_ARG)} ${escapeRe(INSTALL_MARKER)}$`;
  const cmdRe = new RegExp(`^(?:AGENTGATE_[A-Z_]+=(?:'[^']*'|[^\\s';&|$\`]+) )+${tail}`);
  const gateEvents = CURSOR_OUR_EVENTS.filter((e) => e !== "sessionEnd");
  return files.some((f) => {
    try {
      const d = JSON.parse(readFileSync(f, "utf8")) as Json;
      if (!isObj(d.hooks)) return false;
      const hooks = d.hooks;
      return gateEvents.every(
        (ev) => Array.isArray(hooks[ev]) && (hooks[ev] as unknown[]).some((h) => isObj(h) && typeof h.command === "string" && cmdRe.test(h.command) && h.failClosed === true && (h.type === undefined || h.type === "command")),
      );
    } catch {
      return false;
    }
  });
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function workspaceRoots(json: unknown): string[] {
  const r = isObj(json) && Array.isArray(json.workspace_roots) ? json.workspace_roots : [];
  return r.filter((x): x is string => typeof x === "string" && x.length > 0);
}

// ── sessionEnd ──────────────────────────────────────────────────────────────

async function sessionEnd(key: string | null): Promise<void> {
  if (!key || process.env.AGENTGATE_SESSION_ID) return;
  const hard = setTimeout(() => process.exit(EXIT.OK), SESSION_END_BUDGET_MS + 1_000);
  try {
    const pending = listPending({ claude_session_id: key });
    const m = forgetHookSession(key);
    if (!pending.length && !m) return;
    const config = await requireLogin();
    const client = new AgentGateClient({ server: config.server, accessToken: config.access_token, timeoutMs: 2_000 });
    await Promise.all(pending.map((p) => cancelApprovalQuietly(client, p.approval_id, p.session_id, "cursor_session_ended").then(() => clearPending(p.approval_id))));
    if (m) {
      await client.endSession(m.session_id, 3_000);
      log.step(`hook session ${m.session_id} ended (Cursor conversation closed)`);
    }
  } catch (err) {
    log.warn(`sessionEnd: could not end session (${describeError(err)}); pending approvals will expire`);
  } finally {
    clearTimeout(hard);
  }
}

function readStdin(limit: number): Promise<string> {
  return new Promise((resolveP, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    process.stdin.on("data", (d: Buffer) => {
      size += d.length;
      if (size > limit) {
        reject(new Error("hook input too large"));
        process.stdin.destroy();
        return;
      }
      chunks.push(d);
    });
    process.stdin.once("end", () => resolveP(Buffer.concat(chunks).toString("utf8")));
    process.stdin.once("error", reject);
  });
}
