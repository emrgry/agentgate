/**
 * Process exit codes. `request` propagates the wrapped command's exit code when it
 * actually ran; every "did not run" outcome maps to one of the codes below.
 */
export const EXIT = {
  OK: 0,
  /** Generic failure of a management command (login/status/...). */
  ERROR: 1,
  /** Usage error, or a command that is not available yet (`run`). */
  USAGE: 2,
  /** Action blocked: denied by policy or human, expired, cancelled, verification
   *  failure, server unreachable, WS error, not logged in — anything fail-closed. */
  BLOCKED: 77,
  /** Interrupted by the user (SIGINT) before the action ran. Approval is cancelled. */
  INTERRUPTED: 130,
} as const;

/**
 * Thrown anywhere in the request pipeline to stop with a specific exit code.
 * `reason` is a stable machine-readable block code (printed as
 * `agentgate: BLOCKED [<reason>] <message>` and reported to the API).
 */
export class ExitError extends Error {
  constructor(
    readonly code: number,
    message: string,
    readonly reason: string = code === 130 ? "interrupted" : "blocked",
  ) {
    super(message);
    this.name = "ExitError";
  }
}

/**
 * The one stderr line that marks "AgentGate did not run your command". A wrapped command
 * that itself exits 77 never produces it. Grammar: ^agentgate: BLOCKED \[([a-z0-9_]+)\] (.*)$
 */
export const BLOCKED_PREFIX = "agentgate: BLOCKED";
export function blockedLine(reason: string, message: string): string {
  return `${BLOCKED_PREFIX} [${reason}] ${message.replace(/\s*\n\s*/g, " ")}`;
}
