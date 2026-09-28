import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const BIN = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "agentgate.mjs");

export const TEST_POLICY = `version: 1
defaults: { low: allow, medium: allow, high: ask, critical: ask }
rules:
  - id: ask-touch
    match: { command_prefix: touch }
    decision: ask
  - id: deny-rm-rf
    match: { regex: "rm\\\\s+-rf" }
    decision: deny
`;

export interface TestEnv {
  home: string;
  work: string;
}

/** Fresh AGENTGATE_HOME (logged in against `server`) + an empty working directory. */
export function makeEnv(opts: {
  server: string;
  token: string;
  publicKeyPem: string;
  policy?: string | null;
  tokenExpiresAt?: string;
  refreshToken?: string;
}): TestEnv {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "agentgate-test-")));
  const home = join(root, "home");
  const work = join(root, "work");
  mkdirSync(home, { recursive: true, mode: 0o700 });
  mkdirSync(work, { recursive: true });
  writeFileSync(
    join(home, "config.json"),
    JSON.stringify({
      version: 1,
      server: opts.server,
      machine_id: "mch_test",
      email: "dev@agentgate.local",
      user_id: "usr_test",
      access_token: opts.token,
      token_expires_at: opts.tokenExpiresAt ?? new Date(Date.now() + 3_600_000).toISOString(),
      ...(opts.refreshToken ? { refresh_token: opts.refreshToken } : {}),
      agent_id: "agt_test",
      agent_name: "test-host",
      signing_key: { kid: "test-key-1", alg: "Ed25519", pem: opts.publicKeyPem, pinned_at: new Date().toISOString() },
    }),
    { mode: 0o600 },
  );
  if (opts.policy !== null) writeFileSync(join(home, "policy.yaml"), opts.policy ?? TEST_POLICY);
  return { home, work };
}

export interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** Runs the real CLI in a subprocess (async, so an in-process fake server keeps serving). */
export interface RunOpts {
  home: string;
  cwd: string;
  env?: Record<string, string>;
  /** Replace the environment entirely (plus AGENTGATE_HOME unless given). */
  bareEnv?: boolean;
  input?: string;
  onStderr?: (chunk: string, child: ReturnType<typeof spawn>) => void;
}

export function runCli(args: string[], o: RunOpts): Promise<RunResult> {
  return runProcess(process.execPath, [BIN, ...args], o);
}

/** Runs any executable with the test env conventions (async; the fake server keeps serving). */
export function runProcess(file: string, args: string[], o: RunOpts): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const base = o.bareEnv ? {} : (process.env as Record<string, string>);
    const env: Record<string, string> = { ...base, AGENTGATE_HOME: o.home, NO_COLOR: "1", ...o.env };
    for (const k of ["AGENTGATE_DEV", "AGENTGATE_TAMPER_COMMAND", "AGENTGATE_SESSION_ID", "AGENTGATE_NODE", "AGENTGATE_HOOK_TIMEOUT_S", "AGENTGATE_ENV", "AGENTGATE_TTL"]) {
      if (!o.env || !(k in o.env)) delete env[k];
    }
    const child = spawn(file, args, { cwd: o.cwd, env, stdio: [o.input === undefined ? "ignore" : "pipe", "pipe", "pipe"] });
    if (o.input !== undefined) child.stdin!.end(o.input);
    let stdout = "";
    let stderr = "";
    child.stdout!.on("data", (d) => (stdout += d));
    child.stderr!.on("data", (d) => {
      stderr += d;
      o.onStderr?.(d.toString(), child);
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}
