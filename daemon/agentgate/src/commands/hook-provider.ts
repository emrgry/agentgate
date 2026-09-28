import { appendFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import type { ActionDraft } from "@agentgate/protocol";
import { codexReceiptFacts, normalizeCodexHook, parseCodexHookInput } from "@agentgate/adapter-codex";
import { normalizeGenericHook } from "@agentgate/adapter-generic";
import { API_ABUSE_RE, SELF_MANAGEMENT_RE } from "@agentgate/adapter-claude-code";
import { authorizeAction, cancelApprovalQuietly, SessionGoneError, type Authorized } from "../authorize.ts";
import { replaceHookSession, resolveHookSession } from "../claude-sessions.ts";
import { AgentGateClient } from "../client/index.ts";
import { paths } from "../config.ts";
import { gateContext } from "../device-keys.ts";
import { EXIT, ExitError } from "../exit-codes.ts";
import { detectGit } from "../git.ts";
import { clearPending, markPending } from "../hook-state.ts";
import { FileNonceStore } from "../nonce-store.ts";
import { log, setSink } from "../output.ts";
import { loadEffectivePolicy } from "../policy.ts";
import { blockInfo, reportBlocked, requireLogin, SignalScope } from "../runtime.ts";
import { gateExecution } from "../verify.ts";
import { HOOK_EXIT_BLOCK, hookTimeoutSeconds } from "./hook.ts";

/**
 * `agentgate hook codex|<generic id>` — PreToolUse gate for supervisor-run Codex / generic
 * (e.g. Hermes) turns. Same fail-closed contract as the Claude hook: 0 = allow (silent),
 * 2 = block (reason on stderr), every exception → 2, hard deadline → 2.
 *
 * Differences from Claude Code:
 *   - no command rewriting (these CLIs can't take an updated tool input): an approved action's
 *     token is verified AND its nonce consumed here, for every tool (Bash included);
 *   - gating receipts: when AGENTGATE_GATE_RECEIPTS is set (supervisor-run turns), an
 *     `invoked` record is appended BEFORE authorization and a `decision` record after, so the
 *     supervisor's tripwire can prove the hook actually ran for every tool it sees. A receipt
 *     that cannot be written blocks the call.
 *   - session: the provider's session id maps to a hook-managed AgentGate session
 *     (key "<provider>:<id>"); AGENTGATE_CONTROL_SESSION (set by the supervisor) is attached to
 *     the action context so approvals surface on the right Control Center session.
 */

const DEADLINE_MARGIN_S = 30;
const MAX_STDIN_BYTES = 8 * 1024 * 1024;

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
  const block = (message: string, reason = "blocked") => {
    log.fail(`hook blocked [${reason}]: ${message}`);
    process.stderr.write(`AgentGate blocked this action: ${message} [${reason}]\n`);
    return HOOK_EXIT_BLOCK;
  };
  const budgetMs = (hookTimeoutSeconds() - DEADLINE_MARGIN_S) * 1000;
  if (budgetMs <= 0) return block("hook timeout too short");
  const started = Date.now();
  let waitingOn: { approvalId: string; sessionId: string; client: AgentGateClient } | null = null;
  const deadline = setTimeout(() => {
    block(`no decision within the hook deadline (${Math.round(budgetMs / 1000)}s)`, "hook_deadline");
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
    // Only PreToolUse gates; anything else (PostToolUse, Stop, …) is ignored, silently.
    if (ev !== undefined && ev !== "PreToolUse" && ev !== "pre_tool_use" && ev !== "pre_tool_call") return EXIT.OK;

    const envSession = process.env.AGENTGATE_SESSION_ID;
    let draftFor: (sid: string) => ActionDraft;
    let providerSession: string | undefined;
    const home = homedir();
    if (provider === "codex") {
      const input = parseCodexHookInput(json);
      const cwd = realpathSync(input.cwd);
      const git = detectGit(cwd);
      const f = codexReceiptFacts(input);
      facts = { ...f, tool_use_id: input.tool_use_id ?? null };
      providerSession = input.session_id;
      draftFor = (sid) =>
        normalizeCodexHook(
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
            onActionId: (id) => (actionId = id),
            onApproval: (approvalId) => {
              waitingOn = { approvalId, sessionId: sid, client };
              markPending({ approval_id: approvalId, session_id: sid, pid: process.pid });
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
