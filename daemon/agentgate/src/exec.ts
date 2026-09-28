import { spawn, type ChildProcess } from "node:child_process";
import { constants } from "node:os";

export interface ExecResult {
  exitCode: number;
  signal: NodeJS.Signals | null;
  error?: Error;
}

let current: ChildProcess | null = null;

/** The running child, if any (for signal forwarding). */
export function currentChild(): ChildProcess | null {
  return current;
}

/**
 * Runs `command` via `/bin/sh -c <command>` with inherited stdio. `command` is passed
 * verbatim — it must be exactly the string whose hash was verified.
 * Exit code: child's code, 128+signo if killed by a signal, 127 if spawn failed.
 */
export function execShell(command: string, cwd: string | undefined, env: NodeJS.ProcessEnv = process.env): Promise<ExecResult> {
  return new Promise((resolve) => {
    let child: ChildProcess;
    try {
      child = spawn("/bin/sh", ["-c", command], { cwd, stdio: "inherit", env });
    } catch (err) {
      resolve({ exitCode: 127, signal: null, error: err as Error });
      return;
    }
    current = child;
    let settled = false;
    child.once("error", (err) => {
      if (settled) return;
      settled = true;
      current = null;
      resolve({ exitCode: 127, signal: null, error: err });
    });
    child.once("exit", (code, signal) => {
      if (settled) return;
      settled = true;
      current = null;
      if (signal) resolve({ exitCode: 128 + (constants.signals[signal] ?? 0), signal });
      else resolve({ exitCode: code ?? 1, signal: null });
    });
  });
}
