import { ApiRequestError, type AgentGateClient } from "./client/index.ts";
import { describeError } from "./authorize.ts";
import { currentChild, execShell } from "./exec.ts";
import { blockedLine, EXIT, ExitError } from "./exit-codes.ts";
import { LoginRequiredError } from "./auth-session.ts";
import { MASKED_STATUS_NOTE, masksEarlierFailures } from "./shell-status.ts";
import { c, log } from "./output.ts";

/** Config with a usable (auto-refreshed) access token. Throws → callers fail closed. */
export { requireLogin } from "./auth-session.ts";

/**
 * Signal handling for a command that may wait (abortable) and then execute a child.
 * Before execution: first SIGINT/SIGTERM/SIGHUP aborts, second forces exit 130.
 * During execution: the child owns the terminal; non-SIGINT signals are forwarded.
 */
export class SignalScope {
  readonly abort = new AbortController();
  executing = false;
  private count = 0;
  private readonly handler = (sig: NodeJS.Signals) => {
    if (this.executing) {
      if (sig !== "SIGINT") currentChild()?.kill(sig);
      return;
    }
    if (++this.count >= 2) {
      log.warn("forced exit");
      process.exit(EXIT.INTERRUPTED);
    }
    this.abort.abort();
  };

  install(): this {
    for (const s of ["SIGINT", "SIGTERM", "SIGHUP"] as const) process.on(s, this.handler);
    return this;
  }

  uninstall() {
    for (const s of ["SIGINT", "SIGTERM", "SIGHUP"] as const) process.off(s, this.handler);
  }

  check() {
    if (this.abort.signal.aborted) throw new ExitError(EXIT.INTERRUPTED, "action not executed; approval cancelled", "interrupted");
  }
}

/**
 * Runs `command` via /bin/sh -c and reports the lifecycle. If the server explicitly
 * refuses the `started` transition (409 not_approved / not_permitted) nothing runs.
 * Other reporting failures are warnings: authorization already happened.
 */
export async function executeReported(
  client: AgentGateClient,
  scope: SignalScope,
  actionId: string,
  command: string,
  cwd: string | undefined,
  env: NodeJS.ProcessEnv = process.env,
): Promise<number> {
  scope.check();
  try {
    await client.reportExecution(actionId, { status: "started" }, 3_000);
  } catch (e) {
    if (e instanceof ApiRequestError && e.status === 409 && (e.code === "not_approved" || e.code === "not_permitted")) {
      throw new ExitError(EXIT.BLOCKED, `server refused execution: ${e.message}`, "server_refused");
    }
    log.warn(`could not report execution start: ${describeError(e)}`);
  }
  scope.check();
  scope.executing = true;
  log.step(`${c.cyan("▶")} executing: ${c.bold(command)}`);
  const r = await execShell(command, cwd, env);
  scope.executing = false;

  const ok = r.exitCode === 0;
  const notes: string[] = [];
  if (r.error) notes.push(`spawn failed: ${r.error.message}`);
  if (r.signal) notes.push(`killed by ${r.signal}`);
  if (r.exitCode === EXIT.BLOCKED) notes.push("exit code 77 came from the command itself (not an AgentGate block)");
  if (masksEarlierFailures(command)) notes.push(MASKED_STATUS_NOTE);
  const detail = notes.length ? notes.join("; ") : undefined;
  await client
    .reportExecution(actionId, { status: ok ? "completed" : "failed", exit_code: r.exitCode, ...(detail ? { detail } : {}) }, 3_000)
    .catch((e) => log.warn(`could not report execution result: ${describeError(e)}`));
  if (ok) log.ok("exit code 0");
  else log.fail(`exit code ${r.exitCode}${detail ? ` (${detail})` : ""}`);
  return r.exitCode;
}

/** Stable reason code + message for any error that stops an action. */
export function blockInfo(err: unknown): { code: number; reason: string; message: string } {
  const message = describeError(err);
  if (err instanceof ExitError) return { code: err.code, reason: err.reason, message };
  if (err instanceof LoginRequiredError) return { code: EXIT.BLOCKED, reason: "login_required", message };
  if (err instanceof ApiRequestError) {
    if (err.kind === "network" || err.kind === "timeout") return { code: EXIT.BLOCKED, reason: "server_unreachable", message };
    if (err.status === 401) return { code: EXIT.BLOCKED, reason: "unauthorized", message };
    return { code: EXIT.BLOCKED, reason: "server_error", message };
  }
  return { code: EXIT.BLOCKED, reason: "internal_error", message };
}

/**
 * Prints the unambiguous block line to stderr (bypassing any log sink), reports
 * `blocked` to the API (best effort) and returns the exit code (77, or 130 if interrupted).
 */
export async function failBlocked(client: AgentGateClient | null, actionId: string | null, err: unknown): Promise<number> {
  const b = blockInfo(err);
  process.stderr.write(`${blockedLine(b.reason, b.message)}\n`);
  if (client) await reportBlocked(client, actionId, `${b.reason}: ${b.message}`);
  return b.code;
}

export async function reportBlocked(client: AgentGateClient, actionId: string | null, detail: string) {
  if (!actionId) return;
  await client
    .reportExecution(actionId, { status: "blocked", exit_code: null, detail }, 3_000)
    .catch((e) => log.debug(`report blocked failed: ${describeError(e)}`));
}
