import { execFileSync } from "node:child_process";
import {
  accessSync,
  chmodSync,
  constants as fsc,
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { z } from "zod";
import { describeError } from "../authorize.ts";
import { claudeAgentId } from "../claude-sessions.ts";
import {
  addOurHooks,
  buildInstalledHookCommand,
  commandShim,
  commandVar,
  findOurCommands,
  OUR_EVENTS,
  removeOurHooks,
} from "../claude-settings.ts";
import { AgentGateClient } from "../client/index.ts";
import { agentgateHome, loadConfig, paths } from "../config.ts";
import { EXIT } from "../exit-codes.ts";
import { c, log, out } from "../output.ts";
import { requireLogin } from "../runtime.ts";
import { hookShimPath } from "./run.ts";

/**
 * `agentgate install claude-code [--project <dir> | --user] [--env E] [--ttl N] [--yes]`
 * `agentgate uninstall claude-code [--project <dir> | --user]`
 *
 * Gates Claude Code sessions that were NOT started via `agentgate run` (desktop app,
 * IDE extensions, plain `claude`) by merging a PreToolUse + SessionEnd hook into
 * Claude's settings. Absolute paths (node, shim, AGENTGATE_HOME) are recorded in the
 * hook command because GUI apps don't inherit a shell PATH.
 */

export interface InstallOptions {
  agent: string | undefined;
  project?: string;
  user: boolean;
  env?: string;
  ttl?: number;
  yes: boolean;
}

type Scope = "project" | "user";

const InstallRecord = z.object({
  scope: z.enum(["project", "user"]),
  file: z.string(),
  created_file: z.boolean(),
  created_dir: z.boolean(),
  created_hooks_key: z.boolean(),
  created_events: z.array(z.string()),
  git_exclude: z.string().nullable(),
  installed_at: z.string(),
});
type InstallRecord = z.infer<typeof InstallRecord>;
const InstallsFile = z.record(z.string(), InstallRecord);

function readInstalls(): Record<string, InstallRecord> {
  try {
    return InstallsFile.parse(JSON.parse(readFileSync(paths.installs(), "utf8")));
  } catch {
    return {};
  }
}
function writeInstalls(v: Record<string, InstallRecord>) {
  mkdirSync(agentgateHome(), { recursive: true, mode: 0o700 });
  atomicWrite(paths.installs(), `${JSON.stringify(v, null, 2)}\n`, 0o600);
}

export function userSettingsPath(): string {
  return join(homedir(), ".claude", "settings.json");
}
export function projectSettingsPath(dir: string): string {
  return join(dir, ".claude", "settings.local.json");
}

function target(o: { project?: string; user: boolean }): { scope: Scope; file: string; projectDir?: string } {
  if (o.user) return { scope: "user", file: userSettingsPath() };
  const dir = resolve(o.project ?? process.cwd());
  if (!existsSync(dir) || !statSync(dir).isDirectory()) throw new Error(`project directory not found: ${dir}`);
  const real = realpathSync(dir);
  return { scope: "project", file: projectSettingsPath(real), projectDir: real };
}

function readSettings(file: string): Record<string, unknown> | null {
  if (!existsSync(file)) return null;
  const raw = readFileSync(file, "utf8");
  if (!raw.trim()) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`${file} is not valid JSON (${(err as Error).message}) — not modifying it`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error(`${file} is not a JSON object — not modifying it`);
  return parsed as Record<string, unknown>;
}

function backup(file: string): string {
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  let dest = `${file}.agentgate-backup-${stamp}`;
  for (let i = 1; existsSync(dest); i++) dest = `${file}.agentgate-backup-${stamp}-${i}`;
  copyFileSync(file, dest);
  chmodSync(dest, 0o600);
  return dest;
}

function atomicWrite(file: string, content: string, mode: number) {
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, content, { mode });
  chmodSync(tmp, mode);
  renameSync(tmp, file);
}

function writeSettings(file: string, settings: Record<string, unknown>) {
  const mode = existsSync(file) ? statSync(file).mode & 0o777 : 0o600;
  atomicWrite(file, `${JSON.stringify(settings, null, 2)}\n`, mode);
}

// ── git ignore (project scope) ──────────────────────────────────────────────

function git(cwd: string, args: string[]): { ok: boolean; out: string } {
  try {
    return { ok: true, out: execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 3_000 }).trim() };
  } catch {
    return { ok: false, out: "" };
  }
}

/** Ensures settings.local.json is ignored; uses .git/info/exclude (personal, untracked). */
function ensureGitIgnored(projectDir: string, file: string): string | null {
  if (!git(projectDir, ["rev-parse", "--git-dir"]).ok) return null;
  const rel = relative(projectDir, file);
  if (git(projectDir, ["ls-files", "--error-unmatch", rel]).ok) {
    log.warn(`${rel} is TRACKED by git — it contains machine-local paths; consider \`git rm --cached ${rel}\``);
  }
  if (git(projectDir, ["check-ignore", "-q", rel]).ok) return null; // already ignored
  const ex = git(projectDir, ["rev-parse", "--git-path", "info/exclude"]);
  if (!ex.ok || !ex.out) return null;
  const excludeFile = isAbsolute(ex.out) ? ex.out : join(projectDir, ex.out);
  mkdirSync(dirname(excludeFile), { recursive: true });
  const line = `/${rel.split("\\").join("/")}`;
  const cur = existsSync(excludeFile) ? readFileSync(excludeFile, "utf8") : "";
  writeFileSync(excludeFile, `${cur}${cur && !cur.endsWith("\n") ? "\n" : ""}# added by agentgate install claude-code\n${line}\n`);
  return excludeFile;
}

function removeGitExclude(excludeFile: string, file: string, projectDir: string) {
  try {
    const line = `/${relative(projectDir, file).split("\\").join("/")}`;
    const cur = readFileSync(excludeFile, "utf8");
    const next = cur.replace(`# added by agentgate install claude-code\n${line}\n`, "");
    if (next !== cur) writeFileSync(excludeFile, next);
  } catch {
    /* best effort */
  }
}

// ── install ─────────────────────────────────────────────────────────────────

export async function installCommand(o: InstallOptions): Promise<number> {
  if (o.agent !== "claude-code") {
    log.fail(`unsupported integration '${o.agent ?? ""}'. Supported: claude-code`);
    return EXIT.USAGE;
  }
  if (o.user && o.project) {
    log.fail("choose either --project <dir> or --user");
    return EXIT.USAGE;
  }
  if (o.user) {
    log.warn(c.bold("--user gates EVERY Claude Code session on this machine for this OS user,"));
    log.warn("including the Claude desktop app and IDE extensions. Hooks are FAIL-CLOSED:");
    log.warn("if the AgentGate API is unreachable or you are logged out, Bash/Write/Edit/MCP calls are BLOCKED.");
    log.warn(`Undo with: agentgate uninstall claude-code --user`);
    if (!o.yes) {
      log.fail("refusing without --yes");
      return EXIT.USAGE;
    }
  }

  let t: ReturnType<typeof target>;
  try {
    t = target(o);
  } catch (err) {
    log.fail((err as Error).message);
    return EXIT.USAGE;
  }

  // Preconditions: logged in with a pinned key; the shim + node we record must exist.
  const cfg = loadConfig();
  if (!cfg?.access_token || !cfg.signing_key) {
    log.fail("not logged in — run `agentgate login` first (the hook would block every action)");
    return EXIT.ERROR;
  }
  const shim = hookShimPath();
  const node = process.execPath;
  for (const [what, p] of [
    ["hook shim", shim],
    ["node", node],
  ] as const) {
    try {
      accessSync(p, fsc.X_OK);
    } catch {
      log.fail(`${what} is not executable: ${p}`);
      return EXIT.ERROR;
    }
  }
  if (!cfg.refresh_token) {
    log.warn("no refresh token stored (older API?) — the hook will start blocking when the access token expires; re-run `agentgate login` after the API supports refresh");
  }

  // Refuse a second scope: both hooks would fire for every tool call (double approvals).
  const other = t.scope === "user" ? findInstalled(process.cwd()).filter((i) => i.scope === "project") : findInstalled(t.projectDir!).filter((i) => i.scope === "user");
  if (other.length) {
    log.fail(`already installed at ${other[0]!.scope} scope (${other[0]!.file}); uninstall that first — two installs would ask twice per action`);
    return EXIT.ERROR;
  }

  let existing: Record<string, unknown> | null;
  try {
    existing = readSettings(t.file);
  } catch (err) {
    log.fail((err as Error).message);
    return EXIT.ERROR;
  }

  const command = buildInstalledHookCommand({ shimPath: shim, nodePath: node, home: agentgateHome(), env: o.env, ttl: o.ttl });
  const before = existing ?? {};
  const next = addOurHooks(before, command);
  if (existing && JSON.stringify(existing) === JSON.stringify(next)) {
    log.ok(`already installed in ${t.file} (unchanged)`);
    return EXIT.OK;
  }

  const installs = readInstalls();
  const prev = installs[t.file];
  const dir = dirname(t.file);
  const createdDir = !existsSync(dir);
  mkdirSync(dir, { recursive: true });
  let backupPath: string | null = null;
  if (existing) backupPath = backup(t.file);
  writeSettings(t.file, next);

  const beforeHooks = (before.hooks ?? null) as Record<string, unknown> | null;
  const record: InstallRecord = prev ?? {
    scope: t.scope,
    file: t.file,
    created_file: existing === null,
    created_dir: createdDir,
    created_hooks_key: !beforeHooks,
    created_events: OUR_EVENTS.filter((ev) => !beforeHooks || !(ev in beforeHooks)),
    git_exclude: null,
    installed_at: new Date().toISOString(),
  };
  if (t.scope === "project" && !record.git_exclude) record.git_exclude = ensureGitIgnored(t.projectDir!, t.file);
  installs[t.file] = record;
  writeInstalls(installs);

  // Register the claude-code agent now (also proves the server + token work). Non-fatal.
  try {
    const config = await requireLogin();
    await claudeAgentId(new AgentGateClient({ server: config.server, accessToken: config.access_token, timeoutMs: 5_000 }), config);
  } catch (err) {
    log.warn(`could not reach the AgentGate API now (${describeError(err)}) — hooks will BLOCK until it is reachable`);
  }

  log.ok(`installed AgentGate hooks (PreToolUse + SessionEnd) in ${c.bold(t.file)}`);
  if (backupPath) log.step(c.dim(`backup: ${backupPath}`));
  if (record.git_exclude) log.step(c.dim(`git-ignored via ${record.git_exclude}`));
  log.step(
    t.scope === "project"
      ? `Claude Code sessions in ${t.projectDir} are now gated (desktop app, IDE and CLI).`
      : "ALL Claude Code sessions for this user are now gated.",
  );
  return EXIT.OK;
}

// ── uninstall ───────────────────────────────────────────────────────────────

export function uninstallCommand(o: { agent: string | undefined; project?: string; user: boolean }): number {
  if (o.agent !== "claude-code") {
    log.fail(`unsupported integration '${o.agent ?? ""}'. Supported: claude-code`);
    return EXIT.USAGE;
  }
  let t: ReturnType<typeof target>;
  try {
    t = target(o);
  } catch (err) {
    log.fail((err as Error).message);
    return EXIT.USAGE;
  }
  const installs = readInstalls();
  const rec = installs[t.file];

  let settings: Record<string, unknown> | null;
  try {
    settings = readSettings(t.file);
  } catch (err) {
    log.fail((err as Error).message);
    return EXIT.ERROR;
  }
  if (!settings) {
    log.step(`nothing to uninstall (${t.file} does not exist)`);
    delete installs[t.file];
    writeInstalls(installs);
    return EXIT.OK;
  }
  const { settings: stripped, removed } = removeOurHooks(settings);
  if (removed === 0) {
    log.step(`no AgentGate hooks found in ${t.file}`);
    delete installs[t.file];
    writeInstalls(installs);
    return EXIT.OK;
  }

  // Tidy up only containers we created.
  const hooks = { ...((stripped.hooks as Record<string, unknown>) ?? {}) };
  for (const ev of rec?.created_events ?? []) {
    if (Array.isArray(hooks[ev]) && (hooks[ev] as unknown[]).length === 0) delete hooks[ev];
  }
  const result: Record<string, unknown> = { ...stripped, hooks };
  if (rec?.created_hooks_key && Object.keys(hooks).length === 0) delete result.hooks;

  const backupPath = backup(t.file);
  if (rec?.created_file && Object.keys(result).length === 0) {
    unlinkSync(t.file);
    const dir = dirname(t.file);
    if (rec.created_dir) {
      try {
        if (readdirSync(dir).filter((n) => !n.includes(".agentgate-backup-")).length === 0) {
          for (const n of readdirSync(dir)) unlinkSync(join(dir, n));
          rmdirSync(dir);
        }
      } catch {
        /* leave it */
      }
    }
    log.ok(`removed ${t.file} (it only contained AgentGate hooks)`);
  } else {
    writeSettings(t.file, result);
    log.ok(`removed ${removed} AgentGate hook entr${removed === 1 ? "y" : "ies"} from ${t.file}`);
    log.step(c.dim(`backup: ${backupPath}`));
  }
  if (rec?.git_exclude && t.projectDir) removeGitExclude(rec.git_exclude, t.file, t.projectDir);
  delete installs[t.file];
  writeInstalls(installs);
  return EXIT.OK;
}

// ── state (status / run) ────────────────────────────────────────────────────

export interface InstalledHook {
  scope: Scope;
  file: string;
  command: string;
  problems: string[];
}

/** AgentGate hooks that Claude Code would load for `projectDir` (project local/shared + user). */
export function findInstalled(projectDir: string): InstalledHook[] {
  const candidates: Array<[Scope, string]> = [
    ["project", projectSettingsPath(projectDir)],
    ["project", join(projectDir, ".claude", "settings.json")],
    ["user", userSettingsPath()],
  ];
  const found: InstalledHook[] = [];
  for (const [scope, file] of candidates) {
    let s: Record<string, unknown> | null = null;
    try {
      s = readSettings(file);
    } catch {
      continue;
    }
    const pre = findOurCommands(s).find((h) => h.event === "PreToolUse");
    if (!pre) continue;
    const problems: string[] = [];
    const nodeP = commandVar(pre.command, "AGENTGATE_NODE");
    const shimP = commandShim(pre.command);
    for (const [what, p] of [
      ["node", nodeP],
      ["hook shim", shimP],
    ] as const) {
      if (!p) problems.push(`${what} path missing from hook command`);
      else {
        try {
          accessSync(p, fsc.X_OK);
        } catch {
          problems.push(`${what} not found: ${p} (every gated tool call will be BLOCKED — re-run install)`);
        }
      }
    }
    found.push({ scope, file, command: pre.command, problems });
  }
  return found;
}

export function printInstallState(projectDir: string): boolean {
  const found = findInstalled(projectDir);
  if (found.length === 0) {
    out(`claude-code   ${c.dim("hook not installed here (agentgate install claude-code)")}`);
    return true;
  }
  let ok = true;
  for (const f of found) {
    if (f.problems.length) {
      ok = false;
      out(`claude-code   ${c.red(`BROKEN ${f.scope} install`)} ${f.file}: ${f.problems.join("; ")}`);
    } else {
      out(`claude-code   hook installed (${f.scope}) ${c.dim(f.file)}`);
    }
  }
  if (found.length > 1) out(`claude-code   ${c.yellow("installed in more than one scope — actions will be asked twice")}`);
  return ok;
}
