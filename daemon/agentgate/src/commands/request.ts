import type { ActionDraft } from "@agentgate/protocol";
import { buildShellDraft, commandFromArgv } from "../action.ts";
import { authorizeAction, describeError, evaluateLocal } from "../authorize.ts";
import { AgentGateClient } from "../client/index.ts";
import { paths, type LoggedInConfig } from "../config.ts";
import { EXIT, ExitError } from "../exit-codes.ts";
import { detectGit } from "../git.ts";
import { FileNonceStore } from "../nonce-store.ts";
import { c, log } from "../output.ts";
import { loadEffectivePolicy, type EffectivePolicy } from "../policy.ts";
import { executeReported, failBlocked, requireLogin, SignalScope } from "../runtime.ts";
import { gateExecution } from "../verify.ts";
import { gateContext } from "../device-keys.ts";
import { CLI_VERSION } from "../version.ts";
import { bindExecContext, computeExecContext, diffExecContext, gitHooksSetting, scrubbedEnv, type ExecContext } from "../exec-context.ts";

/** Recompute the execution binding with the APPROVED PATH/hook setting; any drift blocks. */
export function recheckBinding(approved: ExecContext, command: string, cwd: string, approvedCommand?: string): ExecContext {
  const now = computeExecContext(command, cwd, { path: approved.path, gitHooks: approved.git_hooks });
  // A different command string is reported by the token check (hash_mismatch) instead.
  if (approvedCommand !== undefined && approvedCommand !== command) return now;
  const d = diffExecContext(approved, now);
  if (d) throw new ExitError(EXIT.BLOCKED, d.detail, d.reason);
  return now;
}

export interface RequestOptions {
  argv: string[];
  agentType: string;
  env?: string;
  repo?: string;
  branch?: string;
  ttl: number;
  dryRun: boolean;
}

/**
 * `agentgate request -- <command>` — the M2 vertical slice.
 *
 * FAIL-CLOSED INVARIANT: `executeReported()` is reached only when
 *   (a) the effective decision is "allow" (local policy AND server), or
 *   (b) the action was approved AND `gateExecution()` verified the token against the
 *       exact command about to be spawned (nonce consumed).
 * Every other path — including every thrown exception — exits non-zero without spawning.
 */
export async function requestCommand(o: RequestOptions): Promise<number> {
  const command = commandFromArgv(o.argv);
  if (!command.trim()) {
    log.fail("usage: agentgate request [options] -- <command...>");
    return EXIT.USAGE;
  }
  const cwd = process.cwd();
  const git = o.repo && o.branch ? {} : detectGit(cwd);
  const repo = o.repo ?? git.repo;
  const branch = o.branch ?? git.branch;

  let policy: EffectivePolicy;
  try {
    policy = loadEffectivePolicy();
  } catch (err) {
    return failBlocked(null, null, new ExitError(EXIT.BLOCKED, (err as Error).message, "invalid_policy"));
  }

  const execCtx = computeExecContext(command, cwd, { path: process.env.PATH ?? "/usr/bin:/bin", gitHooks: gitHooksSetting() });
  const draftFor = (sessionId: string) =>
    bindExecContext(
      buildShellDraft({ sessionId, agentType: o.agentType, agentVersion: CLI_VERSION, command, cwd, environment: o.env, repo, branch }),
      execCtx,
    );

  if (o.dryRun) return dryRun(draftFor("ses_dry_run"), policy);

  let config: LoggedInConfig;
  try {
    config = await requireLogin();
  } catch (err) {
    return failBlocked(null, null, err);
  }

  const client = new AgentGateClient({ server: config.server, accessToken: config.access_token, debug: log.debug });
  const scope = new SignalScope().install();
  let sessionId: string | null = null;
  let actionId: string | null = null;
  try {
    // 1. Session (its id is part of the action hash).
    const session = await client.createSession(config.agent_id);
    sessionId = session.id;
    scope.check();
    log.debug(`session ${session.id}`);

    // 2–4. policy → report → (ask) wait for the human.
    const draft = draftFor(session.id);
    const auth = await authorizeAction(
      { client, config, policy, signal: scope.abort.signal, ttl: o.ttl, onActionId: (id) => (actionId = id) },
      draft,
    );
    if (auth.kind === "allow") {
      recheckBinding(execCtx, draft.action.command!, cwd);
      return await executeReported(client, scope, auth.actionId, draft.action.command!, draft.action.cwd, scrubbedEnv(process.env, execCtx));
    }

    // 5. Final gate: recompute the hash from the exact command that will be spawned.
    let execCommand = draft.action.command!;
    const tamper = process.env.AGENTGATE_DEV === "1" ? process.env.AGENTGATE_TAMPER_COMMAND : undefined;
    if (tamper) {
      log.warn(c.yellow(`DEV tamper hook: replacing command before final check → ${tamper}`));
      execCommand = tamper;
    }
    // Re-derive the binding for what is about to run (TOCTOU during the approval wait).
    const nowCtx = recheckBinding(execCtx, execCommand, cwd, command);
    const executable: ActionDraft = bindExecContext({ ...draft, action: { ...draft.action, command: execCommand } }, nowCtx);
    const gctx = await gateContext(client, config, auth.token);
    const gate = gateExecution({
      ...gctx,
      token: auth.token,
      executable,
      publicKeyPem: config.signing_key.pem,
      approvalId: auth.approvalId,
      actionId: auth.actionId,
      sessionId: session.id,
      nonceStore: new FileNonceStore(paths.nonces()),
    });
    if (!gate.ok) throw new ExitError(EXIT.BLOCKED, `approval token rejected (${gate.reason}): ${gate.detail}`, `token_${gate.reason}`);
    log.ok(`token verified ${c.dim(`(hash ${gate.hash.slice(0, 12)}…, single-use nonce consumed)`)}`);
    return await executeReported(client, scope, auth.actionId, gate.command, gate.cwd, scrubbedEnv(process.env, execCtx));
  } catch (err) {
    // Catch-all: anything unexpected is a block. Never execute from here.
    return await failBlocked(client, actionId, err);
  } finally {
    if (sessionId) {
      // Ending the session cancels any still-pending approval server-side.
      await client.endSession(sessionId, 3_000).catch((e) => log.debug(`end session failed: ${describeError(e)}`));
    }
    scope.uninstall();
  }
}

function dryRun(draft: ActionDraft, policy: EffectivePolicy): number {
  const e = evaluateLocal(policy, draft);
  const color = e.decision === "allow" ? c.green : e.decision === "ask" ? c.yellow : c.red;
  log.step(`dry run — nothing is sent or executed`);
  log.step(`policy: ${color(c.bold(e.decision.toUpperCase()))} ${c.dim(`(${e.rule_id ? `rule ${e.rule_id}` : "default"}, risk ${e.risk.level}, ${policy.source})`)}`);
  log.step(`reason: ${e.reason}`);
  if (e.environment) log.step(`environment: ${e.environment}`);
  for (const s of e.segments) {
    log.step(`  segment ${c.bold(JSON.stringify(s.segment))} → ${s.decision} (${s.rule_id ?? "default"}, ${s.risk.level}: ${s.risk.reason})`);
  }
  log.step(`command: ${draft.action.command}`);
  return EXIT.OK;
}
