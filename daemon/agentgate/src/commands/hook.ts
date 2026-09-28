import { appendFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { ActionDraft } from "@agentgate/protocol";
import { ClaudeCodeAdapter, PreToolUseInput, type PreToolUseOutput } from "@agentgate/adapter-claude-code";
import { z } from "zod";
import { shellQuote } from "../action.ts";
import { pruneApprovals, saveApproval } from "../approval-store.ts";
import { authorizeAction, cancelApprovalQuietly, describeError, SessionGoneError, type Authorized } from "../authorize.ts";
import { clearPending, listPending, markPending, pruneToolUse, rememberToolUse, takeToolUse } from "../hook-state.ts";
import { forgetHookSession, replaceHookSession, resolveHookSession } from "../claude-sessions.ts";
import { AgentGateClient } from "../client/index.ts";
import { agentgateHome, paths, type LoggedInConfig } from "../config.ts";
import { EXIT, ExitError } from "../exit-codes.ts";
import { detectGit } from "../git.ts";
import { FileNonceStore } from "../nonce-store.ts";
import { log, setSink } from "../output.ts";
import { loadEffectivePolicy } from "../policy.ts";
import { blockInfo, reportBlocked, requireLogin, SignalScope } from "../runtime.ts";
import { gateExecution } from "../verify.ts";
import { gateContext } from "../device-keys.ts";
import { bindExecContext, computeExecContext, gitHooksSetting } from "../exec-context.ts";
import { layout } from "../install-layout.ts";

/**
 * `agentgate hook claude-code` — Claude Code hook entry (PreToolUse + SessionEnd,
 * dispatched on stdin `hook_event_name`).
 *
 * PreToolUse: Claude Code treats exit 2 as "block" (stderr = reason) and EVERY other
 * failure (other non-zero exit, crash, hook timeout) as fail-OPEN. Therefore:
 *   - this command returns only 0 (decision JSON on stdout) or 2;
 *   - every exception → 2;
 *   - an internal deadline (hook timeout − 30 s) fires process.exit(2) before Claude's
 *     own timeout can;
 *   - bin/agentgate-hook.sh maps any other exit (node missing, crash, signal) to 2.
 *
 * SessionEnd: cannot block anything; best effort (≤ 5 s) end of the hook-managed
 * AgentGate session, always exit 0.
 *
 * Session: AGENTGATE_SESSION_ID (set by `agentgate run`) wins; otherwise the Claude
 * `session_id` is mapped to a hook-managed AgentGate session (see claude-sessions.ts).
 * Status lines go to $AGENTGATE_HOME/hook.log; stderr carries only the block reason.
 */

export const HOOK_EXIT_BLOCK = 2;
const DEFAULT_HOOK_TIMEOUT_S = 600;
const DEADLINE_MARGIN_S = 30;
const SESSION_END_BUDGET_MS = 5_000;
const POST_TOOL_USE_BUDGET_MS = 5_000;

/** Approval this process is waiting on (cancelled best-effort on a hard deadline). */
let waitingOn: { approvalId: string; sessionId: string; client: AgentGateClient } | null = null;
const MAX_STDIN_BYTES = 8 * 1024 * 1024;

/** Absolute path of the POSIX runner used in rewritten Bash commands. */
export function execShimPath(): string {
  return layout().cli;
}

/** AgentGate's own code + data the agent must not touch (see adapter guard). */
export function protectedDirs(): string[] {
  const secrets =
    process.platform === "darwin"
      ? join(homedir(), "Library", "Application Support", "agentgate-api")
      : join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "agentgate-api");
  // Dev checkout: the repo's AgentGate code; installed release: versions/, current, the
  // running version and the PATH shim (see install-layout.ts).
  return [...layout().protectedDirs, process.env.AGENTGATE_API_SECRETS_DIR || secrets];
}

export function hookTimeoutSeconds(): number {
  const v = Number(process.env.AGENTGATE_HOOK_TIMEOUT_S);
  return Number.isFinite(v) && v > 0 ? v : DEFAULT_HOOK_TIMEOUT_S;
}

const HookEnvelope = z.object({ hook_event_name: z.string(), session_id: z.string().optional() }).passthrough();

export async function hookCommand(agent: string | undefined): Promise<number> {
  if (agent !== "claude-code") {
    process.stderr.write(`AgentGate: unsupported hook '${agent ?? ""}' (expected claude-code) — blocking\n`);
    return HOOK_EXIT_BLOCK;
  }
  setSink((line) => {
    try {
      appendFileSync(paths.hookLog(), `${new Date().toISOString()} ${line}\n`, { mode: 0o600 });
    } catch {
      /* logging must never change the decision */
    }
  });

  const started = Date.now();
  const budgetMs = (hookTimeoutSeconds() - DEADLINE_MARGIN_S) * 1000;
  const block = (message: string, reason = "blocked") => {
    log.fail(`hook blocked [${reason}]: ${message}`);
    process.stderr.write(`AgentGate blocked this action: ${message} [${reason}]\n`);
    return HOOK_EXIT_BLOCK;
  };
  if (budgetMs <= 0) return block(`hook timeout too short (${hookTimeoutSeconds()}s ≤ ${DEADLINE_MARGIN_S}s margin)`);

  // Hard stop well before Claude's hook timeout (which would fail open).
  const deadline = setTimeout(() => {
    block(`no decision within the hook deadline (${Math.round(budgetMs / 1000)}s)`, "hook_deadline");
    // Take the request off the phone (≤ 3 s, well inside the 30 s margin), then exit 2.
    const w = waitingOn;
    const hardExit = setTimeout(() => process.exit(HOOK_EXIT_BLOCK), 3_500);
    if (!w) process.exit(HOOK_EXIT_BLOCK);
    else
      void cancelApprovalQuietly(w.client, w.approvalId, w.sessionId, "hook_deadline").finally(() => {
        clearPending(w.approvalId);
        clearTimeout(hardExit);
        process.exit(HOOK_EXIT_BLOCK);
      });
  }, budgetMs);

  try {
    const raw = await readStdin(MAX_STDIN_BYTES);
    let json: unknown;
    try {
      json = JSON.parse(raw);
    } catch (err) {
      throw new Error(`invalid hook input (${(err as Error).message.split("\n")[0]})`);
    }
    const env = HookEnvelope.safeParse(json);
    const evName = env.success ? env.data.hook_event_name : "";
    if (evName === "SessionEnd") {
      clearTimeout(deadline);
      await Promise.all([sessionEnd(env.success ? env.data.session_id : undefined), observe(json)]);
      return EXIT.OK;
    }
    if (evName === "PostToolUse") {
      clearTimeout(deadline);
      await Promise.all([postToolUse(json), observe(json)]);
      return EXIT.OK; // never blocks, never prints a decision
    }
    if (["SessionStart", "UserPromptSubmit", "Notification", "Stop"].includes(evName)) {
      clearTimeout(deadline);
      await observe(json);
      return EXIT.OK; // observe-only: no stdout (UserPromptSubmit stdout would become context)
    }
    const out = await preToolUse(json, () => budgetMs - (Date.now() - started));
    if (out) process.stdout.write(`${JSON.stringify(out)}\n`);
    return EXIT.OK;
  } catch (err) {
    const b = blockInfo(err);
    return block(b.message, b.reason);
  } finally {
    clearTimeout(deadline);
  }
}

// ── Observed sessions (Control Center) ───────────────────────────────────────

const pickStr = (v: unknown, max: number) => (typeof v === "string" ? v.slice(0, max) : undefined);

/** Minimal, trimmed hook facts for the local server — never file contents or tool output. */
export function observePayload(hook: Record<string, unknown>): Record<string, unknown> {
  const ti = (hook.tool_input ?? {}) as Record<string, unknown>;
  const tr = (hook.tool_response ?? {}) as Record<string, unknown>;
  const out: Record<string, unknown> = {
    session_id: pickStr(hook.session_id, 256),
    cwd: pickStr(hook.cwd, 4096),
    hook_event_name: pickStr(hook.hook_event_name, 64),
    source: pickStr(hook.source, 64),
    prompt: pickStr(hook.prompt, 4096),
    tool_name: pickStr(hook.tool_name, 128),
    notification_type: pickStr(hook.notification_type, 64),
    message: pickStr(hook.message, 1024),
    reason: pickStr(hook.reason, 128),
  };
  if (hook.tool_input && typeof hook.tool_input === "object") {
    out.tool_input = Object.fromEntries(
      ["command", "file_path", "path", "notebook_path", "pattern", "url", "description"].filter((k) => typeof ti[k] === "string").map((k) => [k, (ti[k] as string).slice(0, 500)]),
    );
  }
  if (hook.tool_response && typeof hook.tool_response === "object") {
    out.tool_response = { success: tr.success === false ? false : undefined, is_error: tr.is_error === true ? true : undefined, error: typeof tr.error === "string" ? tr.error.slice(0, 300) : undefined };
  }
  return Object.fromEntries(Object.entries(out).filter(([, v]) => v !== undefined));
}

/** Best effort (≤ 3 s): report to the local server; failures are only logged. */
async function observe(json: unknown): Promise<void> {
  if (!json || typeof json !== "object") return;
  try {
    const config = await requireLogin();
    const client = new AgentGateClient({ server: config.server, accessToken: config.access_token, timeoutMs: 3_000 });
    // A Control Center turn marks its own hook processes (env inherited from the turn): the
    // server then attributes these events to the managed session instead of creating an
    // observed duplicate.
    const managed = process.env.AGENTGATE_MANAGED_SESSION;
    await client.observe("claude-code", {
      ...observePayload(json as Record<string, unknown>),
      ...(managed && /^[A-Za-z0-9_-]{1,64}$/.test(managed) ? { agentgate_managed_session: managed } : {}),
    });
  } catch (err) {
    log.debug(`observe failed: ${describeError(err)}`);
  }
}

// ── PostToolUse (reporting only) ─────────────────────────────────────────────

/**
 * Reports execution of an allowed/approved non-Bash tool call, correlated by Claude's
 * tool_use_id (stored at PreToolUse). Best effort, ≤ 5 s, always exit 0 with no stdout:
 * it cannot influence any decision. Claude only fires PostToolUse after the tool ran;
 * an explicit error marker in tool_response is reported as `failed`.
 */
async function postToolUse(json: unknown): Promise<void> {
  const hard = setTimeout(() => process.exit(EXIT.OK), POST_TOOL_USE_BUDGET_MS + 1_000);
  try {
    const input = z.object({ tool_use_id: z.string().optional(), tool_name: z.string().optional(), tool_response: z.unknown().optional() }).passthrough().parse(json);
    pruneToolUse();
    if (!input.tool_use_id) return;
    const rec = takeToolUse(input.tool_use_id);
    if (!rec) return; // not ours (ungoverned, Bash reported by exec, or already reported)
    const config = await requireLogin();
    const client = new AgentGateClient({ server: config.server, accessToken: config.access_token, timeoutMs: 2_000 });
    const failure = toolFailure(input.tool_response);
    await client.reportExecution(rec.action_id, { status: "started" }, 2_000).catch(() => {});
    await client.reportExecution(
      rec.action_id,
      failure ? { status: "failed", exit_code: null, detail: `${rec.tool_name}: ${failure}` } : { status: "completed", exit_code: null, detail: `${rec.tool_name} completed` },
      2_000,
    );
    log.step(`reported ${rec.tool_name} ${failure ? "failed" : "completed"} for ${rec.action_id}`);
  } catch (err) {
    log.warn(`PostToolUse: could not report (${describeError(err)})`);
  } finally {
    clearTimeout(hard);
  }
}

function toolFailure(resp: unknown): string | null {
  if (!resp || typeof resp !== "object") return null;
  const r = resp as Record<string, unknown>;
  if (r.success === false) return typeof r.error === "string" ? r.error.slice(0, 500) : "tool reported success=false";
  if (r.is_error === true || r.isError === true) return "tool reported an error";
  if (typeof r.error === "string" && r.error) return r.error.slice(0, 500);
  return null;
}

// ── SessionEnd ──────────────────────────────────────────────────────────────

async function sessionEnd(claudeSessionId: string | undefined): Promise<void> {
  const hard = setTimeout(() => process.exit(EXIT.OK), SESSION_END_BUDGET_MS + 1_000);
  try {
    const runSession = process.env.AGENTGATE_SESSION_ID;
    const pending = listPending({
      ...(runSession ? { session_id: runSession } : {}),
      ...(claudeSessionId ? { claude_session_id: claudeSessionId } : {}),
    });
    const m = !runSession && claudeSessionId ? forgetHookSession(claudeSessionId) : null;
    if (!pending.length && !m) return;
    const config = await requireLogin();
    const client = new AgentGateClient({ server: config.server, accessToken: config.access_token, timeoutMs: 2_000 });
    // Approvals still on the phone for a session that no longer exists: cancel them.
    await Promise.all(
      pending.map((p) => cancelApprovalQuietly(client, p.approval_id, p.session_id, "claude_session_ended").then(() => clearPending(p.approval_id))),
    );
    if (!m) return; // `agentgate run` owns and ends its session
    pruneApprovals(m.session_id);
    await client.endSession(m.session_id, 3_000);
    log.step(`hook session ${m.session_id} ended (Claude session ${claudeSessionId} closed)`);
  } catch (err) {
    log.warn(`SessionEnd: could not end session (${describeError(err)}); pending approvals will expire`);
  } finally {
    clearTimeout(hard);
  }
}

// ── PreToolUse ──────────────────────────────────────────────────────────────

async function preToolUse(json: unknown, remainingMs: () => number): Promise<PreToolUseOutput | null> {
  let input: PreToolUseInput;
  try {
    input = PreToolUseInput.parse(json);
  } catch (err) {
    throw new Error(`invalid PreToolUse input (${(err as Error).message.split("\n")[0]})`);
  }
  log.debug(`hook ${input.tool_name}`);

  const envSession = process.env.AGENTGATE_SESSION_ID;
  if (!envSession && !input.session_id) {
    throw new Error("no AgentGate session: AGENTGATE_SESSION_ID unset and the hook input has no session_id");
  }

  const cwd = realpathSync(input.cwd);
  const git = detectGit(cwd);
  const adapter = new ClaudeCodeAdapter({
    homeDir: homedir(),
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
  // Normalize first: ungoverned tools must not create sessions or touch the network.
  const probe = adapter.normalize(input, { ...ctx, session_id: "ses_pending" });
  if (!probe) return null;
  // Self-protection / sensitive-read floor (can only make the decision stricter).
  const guard = adapter.guard(input, cwd);

  const policy = loadEffectivePolicy();
  const config = await requireLogin();
  const client = new AgentGateClient({ server: config.server, accessToken: config.access_token, debug: log.debug });
  const managed = !envSession;
  // H2: bind Bash approvals to what executes (PATH, binaries, scripts, push target).
  const execCtx =
    input.tool_name === "Bash" && typeof input.tool_input.command === "string"
      ? computeExecContext(input.tool_input.command, cwd, { path: process.env.PATH ?? "/usr/bin:/bin", gitHooks: gitHooksSetting() })
      : null;
  const draftFor = (sid: string) => {
    const d = adapter.normalize(input, { ...ctx, session_id: sid })!;
    return execCtx ? bindExecContext(d, execCtx) : d;
  };
  let sessionId = envSession ?? (await resolveHookSession(client, config, input.session_id!));

  const scope = new SignalScope().install();
  let actionId: string | null = null;
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
          maxWaitMs: Math.max(0, remainingMs() - 2_000),
          ...(guard ? { floor: guard } : {}),
          onActionId: (id) => (actionId = id),
          onApproval: (approvalId) => {
            waitingOn = { approvalId, sessionId: sid, client };
            markPending({ approval_id: approvalId, session_id: sid, ...(input.session_id ? { claude_session_id: input.session_id } : {}), pid: process.pid });
          },
        },
        draftFor(sid),
      );

    let draft: ActionDraft = draftFor(sessionId);
    let auth: Authorized;
    try {
      auth = await authorize(sessionId);
    } catch (err) {
      // A hook-managed session ended server-side (or the server forgot it): re-map once.
      if (!(managed && err instanceof SessionGoneError)) throw err;
      log.warn(`${err.message}; starting a new AgentGate session`);
      sessionId = await replaceHookSession(client, config, input.session_id!, sessionId);
      draft = draftFor(sessionId);
      auth = await authorize(sessionId);
    }
    const gctx = auth.kind === "approved" ? await gateContext(client, config, auth.token) : { requireDeviceSignatures: false };
    const out = finish(adapter, input, draft, auth, config, sessionId, gctx);
    if (input.tool_name !== "Bash" && input.tool_use_id) {
      rememberToolUse({ tool_use_id: input.tool_use_id, action_id: auth.actionId, session_id: sessionId, tool_name: input.tool_name, created_at: new Date().toISOString() });
    }
    return out;
  } catch (err) {
    const b = blockInfo(err);
    await reportBlocked(client, actionId, `${b.reason}: ${b.message}`);
    throw err;
  } finally {
    if (waitingOn) clearPending(waitingOn.approvalId);
    waitingOn = null;
    scope.uninstall();
  }
}

function finish(
  adapter: ClaudeCodeAdapter,
  input: PreToolUseInput,
  draft: ActionDraft,
  auth: Authorized,
  config: LoggedInConfig,
  sessionId: string,
  gctx: Awaited<ReturnType<typeof gateContext>>,
): PreToolUseOutput {
  const why = `${auth.evaluation.rule_id ? `rule ${auth.evaluation.rule_id}` : "default"}, risk ${auth.evaluation.risk.level}`;
  if (auth.kind === "allow") {
    return adapter.render({ kind: "allow", reason: `AgentGate: allowed by policy (${why})` });
  }

  const byWho = auth.approvedBy ? ` by device ${auth.approvedBy}` : "";
  if (input.tool_name === "Bash") {
    // Verify now (fail early on a bad token) but leave the nonce for `agentgate exec`.
    const pre = gateExecution({
      ...gctx,
      token: auth.token,
      executable: draft,
      publicKeyPem: config.signing_key.pem,
      approvalId: auth.approvalId,
      actionId: auth.actionId,
      sessionId,
    });
    if (!pre.ok) throw new ExitError(EXIT.BLOCKED, `approval token rejected (${pre.reason}): ${pre.detail}`, `token_${pre.reason}`);
    // The record carries the session binding, so exec needs no AGENTGATE_SESSION_ID.
    saveApproval({
      v: 1,
      approval_id: auth.approvalId,
      action_id: auth.actionId,
      session_id: sessionId,
      token: auth.token!,
      draft,
      stored_at: new Date().toISOString(),
    });
    const wrapped = wrapCommand(auth.approvalId, pre.command);
    log.ok(`approved${byWho}; rewritten to ${wrapped}`);
    return adapter.render({ kind: "allow", reason: `AgentGate: approved${byWho} (${auth.approvalId})`, rewrittenCommand: wrapped }, input);
  }

  // Non-Bash: Claude executes exactly the tool_input we normalized; consume the token here.
  const gate = gateExecution({
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
  if (!gate.ok) throw new ExitError(EXIT.BLOCKED, `approval token rejected (${gate.reason}): ${gate.detail}`, `token_${gate.reason}`);
  log.ok(`approved${byWho}; token verified and consumed`);
  return adapter.render({ kind: "allow", reason: `AgentGate: approved${byWho} (${auth.approvalId})` });
}

/**
 * `[AGENTGATE_HOME=… AGENTGATE_NODE=… ]'/abs/bin/agentgate.sh' exec --approval apr_… -- '<original>'`.
 * Home and node are pinned when known, so exec works even where Claude's Bash tool has
 * a different environment/PATH (desktop app). Paths only — no secrets.
 */
export function wrapCommand(approvalId: string, original: string): string {
  const pins = (["AGENTGATE_HOME", "AGENTGATE_NODE"] as const)
    .filter((k) => process.env[k])
    .map((k) => `${k}=${shellQuote(process.env[k]!)} `)
    .join("");
  return `${pins}${shellQuote(execShimPath())} exec --approval ${approvalId} -- ${shellQuote(original)}`;
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
