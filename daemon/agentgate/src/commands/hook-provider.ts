import { appendFileSync, existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, relative, isAbsolute } from "node:path";
import type { ActionDraft } from "@agentgate/protocol";
import { codexGuard, codexReceiptFacts, codexToolClass, normalizeCodexHook, parseCodexHookInput, type CodexGuardVerdict } from "@agentgate/adapter-codex";
import { normalizeGenericHook } from "@agentgate/adapter-generic";
import { API_ABUSE_RE, SELF_MANAGEMENT_RE } from "@agentgate/adapter-claude-code";
import { authorizeAction, cancelApprovalQuietly, SessionGoneError, type Authorized } from "../authorize.ts";
import { forgetHookSession, replaceHookSession, resolveHookSession } from "../claude-sessions.ts";
import { pruneApprovals } from "../approval-store.ts";
import { AgentGateClient } from "../client/index.ts";
import { agentgateHome, paths } from "../config.ts";
import { gateContext } from "../device-keys.ts";
import { EXIT, ExitError } from "../exit-codes.ts";
import { detectGit } from "../git.ts";
import { clearPending, listPending, markPending } from "../hook-state.ts";
import { bindExecContext, computeExecContext, diffExecContext, type ExecContext } from "../exec-context.ts";
import { FileNonceStore } from "../nonce-store.ts";
import { log, setSink } from "../output.ts";
import { loadEffectivePolicy } from "../policy.ts";
import { blockInfo, reportBlocked, requireLogin, SignalScope } from "../runtime.ts";
import { gateExecution } from "../verify.ts";
import { HOOK_EXIT_BLOCK, hookTimeoutSeconds, protectedDirs } from "./hook.ts";
import { codexHeartbeatPath } from "./install-codex.ts";

/**
 * `agentgate hook codex|<generic id>` — PreToolUse gate for supervisor-run Codex / generic
 * (e.g. Hermes) turns. Same fail-closed contract as the Claude hook: 0 = allow (silent),
 * 2 = block (reason on stderr), every exception → 2, hard deadline → 2.
 *
 * Differences from Claude Code:
 *   - no command rewriting: an approved action's token is verified AND its nonce consumed
 *     here, for every tool (Bash included). Codex ≥ 0.131 could take an `updatedInput`
 *     rewrite, but the rewritten `agentgate exec …` would run inside Codex's sandbox, which
 *     can't write ~/.agentgate (nonces) or reach the local server — so it would always fail;
 *   - gating receipts: when AGENTGATE_GATE_RECEIPTS is set (supervisor-run turns), an
 *     `invoked` record is appended BEFORE authorization and a `decision` record after, so the
 *     supervisor's tripwire can prove the hook actually ran for every tool it sees. A receipt
 *     that cannot be written blocks the call.
 *   - session: the provider's session id maps to a hook-managed AgentGate session
 *     (key "<provider>:<id>"); AGENTGATE_CONTROL_SESSION (set by the supervisor) is attached to
 *     the action context so approvals surface on the right Control Center session.
 *
 * Codex specifics (both modes): the self-protection guard (codexGuard) is a floor on policy;
 * Bash approvals are bound to the exec context (binaries, scripts, push target) and that
 * binding is re-checked right before the hook allows — the command then runs inside Codex
 * without an `agentgate exec` wrapper (Codex's sandbox can't reach ~/.agentgate or the
 * server), so this re-check is the last point where a changed script/binary is caught.
 *
 * Interactive Codex (`agentgate install codex`, AGENTGATE_CODEX_INSTALL=user|project):
 *   - tools that run and write nothing (update_plan, goals, subagent control, non-sensitive
 *     view_image) pass without a round trip;
 *   - SessionEnd: cancel still-pending approvals and end the mapped session (≤ 2.5 s);
 *   - a project-scoped install defers to the managed hook inside a Control Center turn
 *     (the per-session CODEX_HOME under $AGENTGATE_HOME), so approvals aren't asked twice.
 */

const DEADLINE_MARGIN_S = 30;
const MAX_STDIN_BYTES = 8 * 1024 * 1024;
const CODEX_SESSION_END_BUDGET_MS = 2_500;
/** Reasons after which the user can simply approve on the phone when Codex retries. */
const RETRY_HINT_REASONS = new Set(["hook_deadline", "approval_timeout", "approval_expired"]);

/** "user" | "project" when this hook gates an interactive Codex (agentgate install codex). */
export function codexInstallScope(provider: string, env: NodeJS.ProcessEnv = process.env): "user" | "project" | null {
  const v = env.AGENTGATE_CODEX_INSTALL;
  return provider === "codex" && (v === "user" || v === "project") ? v : null;
}

/** CODEX_HOME in effect for the Codex that runs this hook (canonical, like Codex). */
function effectiveCodexHome(): string {
  const env = process.env.CODEX_HOME;
  if (!env) return join(homedir(), ".codex");
  try {
    return realpathSync(env);
  } catch {
    return env;
  }
}

/**
 * Inside a Control Center Codex turn: CODEX_HOME is a supervisor-prepared home under
 * $AGENTGATE_HOME (agents can't write there) whose hooks.json runs the managed provider hook,
 * and the receipts file the supervisor set belongs to it.
 */
export function inManagedCodexTurn(env: NodeJS.ProcessEnv = process.env, home = agentgateHome()): boolean {
  const ch = env.CODEX_HOME;
  const receipts = env.AGENTGATE_GATE_RECEIPTS;
  if (!ch || !receipts) return false;
  try {
    const real = realpathSync(ch);
    const rel = relative(realpathSync(home), real);
    if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) return false;
    if (receipts !== join(ch, "agentgate-receipts.jsonl") && receipts !== join(real, "agentgate-receipts.jsonl")) return false;
    const hooks = join(real, "hooks.json");
    return existsSync(hooks) && readFileSync(hooks, "utf8").includes("--agentgate-provider=codex") && !readFileSync(hooks, "utf8").includes("--agentgate-install=codex/");
  } catch {
    return false;
  }
}

export interface Receipt {
  phase: "invoked" | "decision";
  ts: string;
  provider: string;
  kind: "shell" | "file" | "mcp" | "tool" | "other";
  text: string;
  paths: string[];
  tool_use_id: string | null;
  decision?: "allow" | "deny";
}

export function writeReceipt(r: Receipt): void {
  const file = process.env.AGENTGATE_GATE_RECEIPTS;
  if (!file) return;
  // Throws on failure: no receipt → the tripwire would kill the turn anyway; block now instead.
  appendFileSync(file, `${JSON.stringify(r)}\n`, { mode: 0o600 });
}

const SHELL = /^(bash|shell|exec_command|terminal|run_command|execute_command|run_shell_command)$/i;
const WRITE = /^(write|write_file|edit|edit_file|patch|apply_patch|create_file|replace)$/i;

function genericFacts(tool: string, ti: Record<string, unknown>): Pick<Receipt, "kind" | "text" | "paths"> {
  if (SHELL.test(tool)) return { kind: "shell", text: typeof ti.command === "string" ? ti.command : Array.isArray(ti.command) ? ti.command.join(" ") : "", paths: [] };
  if (WRITE.test(tool)) {
    const p = typeof ti.path === "string" ? ti.path : typeof ti.file_path === "string" ? ti.file_path : null;
    return { kind: "file", text: "", paths: p ? [p] : [] };
  }
  return { kind: "tool", text: tool, paths: [] };
}

export async function providerHookCommand(provider: string): Promise<number> {
  setSink((line) => {
    try {
      appendFileSync(paths.hookLog(), `${new Date().toISOString()} [${provider}] ${line}\n`, { mode: 0o600 });
    } catch {
      /* logging never changes the decision */
    }
  });
  const interactive = codexInstallScope(provider);
  const block = (message: string, reason = "blocked") => {
    log.fail(`hook blocked [${reason}]: ${message}`);
    const hint = interactive && RETRY_HINT_REASONS.has(reason) ? " — nothing was run; ask Codex to retry and approve the request on your phone" : "";
    process.stderr.write(`AgentGate blocked this action: ${message}${hint} [${reason}]\n`);
    return HOOK_EXIT_BLOCK;
  };
  const budgetMs = (hookTimeoutSeconds() - DEADLINE_MARGIN_S) * 1000;
  if (budgetMs <= 0) return block("hook timeout too short");
  const started = Date.now();
  let waitingOn: { approvalId: string; sessionId: string; client: AgentGateClient } | null = null;
  const deadline = setTimeout(() => {
    block(`no decision from your phone within the hook deadline (${Math.round(budgetMs / 1000)}s); the request was withdrawn`, "hook_deadline");
    const w = waitingOn;
    const hard = setTimeout(() => process.exit(HOOK_EXIT_BLOCK), 3_500);
    if (!w) process.exit(HOOK_EXIT_BLOCK);
    else
      void cancelApprovalQuietly(w.client, w.approvalId, w.sessionId, "hook_deadline").finally(() => {
        clearPending(w.approvalId);
        clearTimeout(hard);
        process.exit(HOOK_EXIT_BLOCK);
      });
  }, budgetMs);

  let facts: Pick<Receipt, "kind" | "text" | "paths" | "tool_use_id"> = { kind: "other", text: "", paths: [], tool_use_id: null };
  const decide = (decision: "allow" | "deny") => {
    try {
      writeReceipt({ phase: "decision", ts: new Date().toISOString(), provider, ...facts, decision });
    } catch {
      /* the invoked receipt already exists; a missing decision record is treated as "deny" */
    }
  };
  try {
    const raw = await readStdin(MAX_STDIN_BYTES);
    let json: unknown;
    try {
      json = JSON.parse(raw);
    } catch (err) {
      throw new Error(`invalid hook input (${(err as Error).message.split("\n")[0]})`);
    }
    const ev = (json as { hook_event_name?: unknown })?.hook_event_name;
    if (interactive) heartbeat();
    if (interactive && ev === "SessionEnd") {
      clearTimeout(deadline);
      await codexSessionEnd(json);
      return EXIT.OK;
    }
    // Only PreToolUse gates; anything else (PostToolUse, Stop, …) is ignored, silently.
    if (ev !== undefined && ev !== "PreToolUse" && ev !== "pre_tool_use" && ev !== "pre_tool_call") return EXIT.OK;

    const envSession = process.env.AGENTGATE_SESSION_ID;
    let draftFor: (sid: string) => ActionDraft;
    let providerSession: string | undefined;
    const home = homedir();
    let guard: CodexGuardVerdict | null = null;
    let execCtx: { command: string; cwd: string; ctx: ExecContext } | null = null;
    if (provider === "codex") {
      const input = parseCodexHookInput(json);
      if (interactive === "project" && inManagedCodexTurn()) {
        log.step("Control Center turn: the managed AgentGate hook gates this call");
        return EXIT.OK;
      }
      const cwd = realpathSync(input.cwd);
      const guardOpts = { homeDir: home, agentgateHome: agentgateHome(), protectedDirs: protectedDirs(), codexHome: effectiveCodexHome() };
      if (interactive && codexToolClass({ ...input, cwd }, guardOpts) === "benign") {
        log.debug(`codex ${input.tool_name}: no side effects, not gated`);
        return EXIT.OK;
      }
      guard = codexGuard({ ...input, cwd }, guardOpts);
      const git = detectGit(cwd);
      const f = codexReceiptFacts(input);
      facts = { ...f, tool_use_id: input.tool_use_id ?? null };
      providerSession = input.session_id;
      // Bind shell approvals to what would execute (re-checked before allowing). Git hooks are
      // "allowed": without an exec wrapper nothing can disable them, so say so on the phone.
      if (f.kind === "shell" && f.text) {
        execCtx = { command: f.text, cwd, ctx: computeExecContext(f.text, cwd, { path: process.env.PATH ?? "/usr/bin:/bin", gitHooks: "allowed" }) };
      }
      const bound = execCtx;
      draftFor = (sid) => {
        const d = normalizeCodexHook(
          { ...input, cwd },
          {
            session_id: sid,
            homeDir: home,
            projectRoot: git.root ? realpathSync(git.root) : cwd,
            ...(git.repo ? { repo: git.repo } : {}),
            ...(git.branch ? { branch: git.branch } : {}),
            ...(process.env.AGENTGATE_ENV ? { environment: process.env.AGENTGATE_ENV } : {}),
          },
        );
        return bound ? bindExecContext(d, bound.ctx) : d;
      };
    } else {
      const o = (json ?? {}) as Record<string, unknown>;
      const tool = typeof o.tool_name === "string" ? o.tool_name : typeof o.name === "string" ? o.name : "";
      const ti = (o.tool_input && typeof o.tool_input === "object" ? o.tool_input : o.input && typeof o.input === "object" ? o.input : {}) as Record<string, unknown>;
      const cwd = typeof o.cwd === "string" && o.cwd ? realpathSync(o.cwd) : process.cwd();
      facts = { ...genericFacts(tool, ti), tool_use_id: typeof o.tool_use_id === "string" ? o.tool_use_id : null };
      providerSession = typeof o.session_id === "string" ? o.session_id : undefined;
      draftFor = (sid) => normalizeGenericHook(provider, json, { session_id: sid, cwd });
    }
    // Receipt BEFORE any network/policy work: proves the hook fired for this tool.
    writeReceipt({ phase: "invoked", ts: new Date().toISOString(), provider, ...facts });
    // Self-protection (same floor as the Claude adapter guard): agents may not reconfigure
    // their own gate (login/pair/devices/…) or call credential/approval endpoints directly.
    if (guard?.decision === "deny") throw new ExitError(EXIT.BLOCKED, guard.reason, "self_protection");
    if (facts.kind === "shell") {
      const m = SELF_MANAGEMENT_RE.exec(facts.text);
      if (m) throw new ExitError(EXIT.BLOCKED, `agents may not run \`agentgate ${m[1]}\` (it would reconfigure their own gate)`, "self_protection");
      const api = API_ABUSE_RE.exec(facts.text);
      if (api) throw new ExitError(EXIT.BLOCKED, `agents may not call AgentGate credential/approval endpoints directly (${api[0]})`, "self_protection");
    }

    const control = process.env.AGENTGATE_CONTROL_SESSION;
    const withControl = (d: ActionDraft): ActionDraft => (control ? { ...d, context: { ...d.context, agentgate_control_session: control.slice(0, 64) } } : d);
    const mapKey = providerSession ? `${provider}:${providerSession}` : control ? `${provider}:ctl:${control}` : null;
    if (!envSession && !mapKey) throw new Error("no AgentGate session: AGENTGATE_SESSION_ID unset and the hook input has no session id");

    const policy = loadEffectivePolicy();
    const config = await requireLogin();
    const client = new AgentGateClient({ server: config.server, accessToken: config.access_token, debug: log.debug });
    let sessionId = envSession ?? (await resolveHookSession(client, config, mapKey!));
    const scope = new SignalScope().install();
    let actionId: string | null = null;
    try {
      const authorize = (sid: string) =>
        authorizeAction(
          {
            client,
            config,
            policy,
            signal: scope.abort.signal,
            ttl: Number(process.env.AGENTGATE_TTL) > 0 ? Math.floor(Number(process.env.AGENTGATE_TTL)) : 120,
            maxWaitMs: Math.max(0, budgetMs - (Date.now() - started) - 2_000),
            ...(guard ? { floor: guard } : {}),
            onActionId: (id) => (actionId = id),
            onApproval: (approvalId) => {
              waitingOn = { approvalId, sessionId: sid, client };
              markPending({ approval_id: approvalId, session_id: sid, ...(mapKey ? { claude_session_id: mapKey } : {}), pid: process.pid });
            },
          },
          withControl(draftFor(sid)),
        );
      let draft = withControl(draftFor(sessionId));
      let auth: Authorized;
      try {
        auth = await authorize(sessionId);
      } catch (err) {
        if (envSession || !(err instanceof SessionGoneError)) throw err;
        sessionId = await replaceHookSession(client, config, mapKey!, sessionId);
        draft = withControl(draftFor(sessionId));
        auth = await authorize(sessionId);
      }
      if (auth.kind === "approved") {
        const gctx = await gateContext(client, config, auth.token);
        // No rewrite path: verify + consume the one-time token now, for every tool.
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
        // TOCTOU narrowing: what the approved command would run must not have changed while
        // the phone was deciding (a background job rewriting a script, a new binary on PATH…).
        if (execCtx) {
          const now = computeExecContext(execCtx.command, execCtx.cwd, { path: execCtx.ctx.path, gitHooks: "allowed" });
          const d = diffExecContext(execCtx.ctx, now);
          if (d) throw new ExitError(EXIT.BLOCKED, `changed while waiting for approval: ${d.detail} — ask Codex to retry`, d.reason);
        }
        log.ok(`approved${auth.approvedBy ? ` by device ${auth.approvedBy}` : ""}; token verified and consumed`);
      } else {
        log.ok(`allowed by policy (${auth.evaluation.rule_id ?? "default"})`);
      }
      decide("allow");
      return EXIT.OK;
    } catch (err) {
      const b = blockInfo(err);
      await reportBlocked(client, actionId, `${b.reason}: ${b.message}`);
      throw err;
    } finally {
      if (waitingOn) clearPending((waitingOn as { approvalId: string }).approvalId);
      waitingOn = null;
      scope.uninstall();
    }
  } catch (err) {
    decide("deny");
    const b = blockInfo(err);
    return block(b.message, b.reason);
  } finally {
    clearTimeout(deadline);
  }
}

/** Best effort: lets `agentgate status` show that the installed Codex hook actually runs. */
function heartbeat() {
  try {
    writeFileSync(codexHeartbeatPath(), `${JSON.stringify({ at: new Date().toISOString() })}\n`, { mode: 0o600 });
  } catch {
    /* never changes a decision */
  }
}

/**
 * Codex SessionEnd (interactive installs; Codex clamps it to ≤ 3 s): withdraw approvals still
 * on the phone for this Codex session and end its hook-managed AgentGate session.
 */
async function codexSessionEnd(json: unknown): Promise<void> {
  const hard = setTimeout(() => process.exit(EXIT.OK), CODEX_SESSION_END_BUDGET_MS);
  try {
    const sid = (json as { session_id?: unknown })?.session_id;
    if (typeof sid !== "string" || !sid) return;
    const key = `codex:${sid}`;
    const pending = listPending({ claude_session_id: key });
    const m = forgetHookSession(key);
    if (!pending.length && !m) return;
    const config = await requireLogin();
    const client = new AgentGateClient({ server: config.server, accessToken: config.access_token, timeoutMs: 1_500 });
    await Promise.all(pending.map((p) => cancelApprovalQuietly(client, p.approval_id, p.session_id, "codex_session_ended").then(() => clearPending(p.approval_id))));
    if (!m) return;
    pruneApprovals(m.session_id);
    await client.endSession(m.session_id, 1_500);
    log.step(`hook session ${m.session_id} ended (Codex session ${sid} closed)`);
  } catch (err) {
    log.warn(`Codex SessionEnd: could not end session (${err instanceof Error ? err.message : String(err)}); pending approvals will expire`);
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
