import { realpathSync } from "node:fs";
import type { ActionDraft } from "@agentgate/protocol";
import { commandFromArgv } from "../action.ts";
import { deleteApproval, isApprovalId, loadApproval } from "../approval-store.ts";
import { describeError } from "../authorize.ts";
import { AgentGateClient } from "../client/index.ts";
import { paths, type LoggedInConfig } from "../config.ts";
import { EXIT, ExitError } from "../exit-codes.ts";
import { FileNonceStore } from "../nonce-store.ts";
import { c, log } from "../output.ts";
import { executeReported, failBlocked, requireLogin, SignalScope } from "../runtime.ts";
import { gateExecution } from "../verify.ts";
import { gateContext } from "../device-keys.ts";
import { bindExecContext, execContextOf, scrubbedEnv } from "../exec-context.ts";
import { recheckBinding } from "./request.ts";

/**
 * `agentgate exec --approval <apr_id> -- <command>` — the execution boundary for
 * approved Claude Code Bash calls (the hook rewrites the tool call to this).
 *
 * The action hash is recomputed from the command string THIS process received, its own
 * cwd and the approved session; the stored token is verified against it (pinned key,
 * expiry, approval id, action/session binding) and its nonce consumed. Only then is
 * `/bin/sh -c <that exact string>` spawned. Any failure → exit 77, nothing runs.
 */
export async function execCommand(o: { approvalId: string | undefined; argv: string[] }): Promise<number> {
  let config: LoggedInConfig | null = null;
  let client: AgentGateClient | null = null;
  let actionId: string | null = null;
  const scope = new SignalScope().install();
  try {
    if (!o.approvalId || !isApprovalId(o.approvalId)) throw new ExitError(EXIT.BLOCKED, "missing or invalid --approval <apr_id>", "usage");
    let command = commandFromArgv(o.argv);
    if (!command.trim()) throw new ExitError(EXIT.BLOCKED, "no command given after --", "usage");

    config = await requireLogin();
    client = new AgentGateClient({ server: config.server, accessToken: config.access_token, debug: log.debug });

    const rec = loadApproval(o.approvalId);
    if (!rec) throw new ExitError(EXIT.BLOCKED, `no stored approval ${o.approvalId} (already used, or never approved on this machine)`, "approval_not_found");
    actionId = rec.action_id;

    const envSession = process.env.AGENTGATE_SESSION_ID;
    if (envSession && envSession !== rec.session_id) {
      throw new ExitError(EXIT.BLOCKED, "approval belongs to a different AgentGate session", "session_mismatch");
    }

    const tamper = process.env.AGENTGATE_DEV === "1" ? process.env.AGENTGATE_TAMPER_COMMAND : undefined;
    if (tamper) {
      log.warn(c.yellow(`DEV tamper hook: replacing command before final check → ${tamper}`));
      command = tamper;
    }

    const cwd = realpathSync(process.cwd());
    const approvedCtx = execContextOf(rec.draft);
    if (!approvedCtx) throw new ExitError(EXIT.BLOCKED, "approval record has no execution binding (approved by an older agentgate?)", "binding_missing");
    // Re-resolve binaries / scripts / push target for what we were actually given.
    const nowCtx = recheckBinding(approvedCtx, command, cwd, rec.draft.action.command);
    const executable: ActionDraft = bindExecContext(
      { ...rec.draft, session_id: rec.session_id, action: { ...rec.draft.action, command, cwd } },
      nowCtx,
    );
    const gctx = await gateContext(client, config, rec.token);
    const gate = gateExecution({
      ...gctx,
      token: rec.token,
      executable,
      publicKeyPem: config.signing_key.pem,
      approvalId: rec.approval_id,
      actionId: rec.action_id,
      sessionId: rec.session_id,
      nonceStore: new FileNonceStore(paths.nonces()),
    });
    if (!gate.ok) throw new ExitError(EXIT.BLOCKED, `approval token rejected (${gate.reason}): ${gate.detail}`, `token_${gate.reason}`);
    deleteApproval(rec.approval_id);
    log.ok(`approval ${rec.approval_id} verified ${c.dim(`(hash ${gate.hash.slice(0, 12)}…, nonce consumed)`)}`);
    return await executeReported(client, scope, rec.action_id, gate.command, gate.cwd, scrubbedEnv(process.env, approvedCtx));
  } catch (err) {
    return await failBlocked(client, actionId, err);
  } finally {
    scope.uninstall();
  }
}
