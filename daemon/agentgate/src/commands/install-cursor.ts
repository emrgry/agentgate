import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
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
import { FILE_TOOL_MATCHER, INSTALL_MARKER, PROVIDER_ARG } from "@agentgate/adapter-cursor";
import { z } from "zod";
import { shellQuote } from "../action.ts";
import { describeError } from "../authorize.ts";
import { claudeAgentId } from "../claude-sessions.ts";
import { findOurCommands } from "../claude-settings.ts";
import { AgentGateClient } from "../client/index.ts";
import { agentgateHome, loadConfig } from "../config.ts";
import { EXIT } from "../exit-codes.ts";
import { layout } from "../install-layout.ts";
import { isWrapped } from "../mcp/install.ts";
import { c, log, out } from "../output.ts";
import { requireLogin } from "../runtime.ts";

/**
 * `agentgate install cursor [--project <dir> (default: cwd) | --user --yes] [--env E] [--ttl N]`
 * `agentgate uninstall cursor [--project <dir> | --user]`
 *
 * Merges AgentGate's gate into Cursor's hooks.json (docs/cursor.md):
 *   beforeShellExecution · beforeMCPExecution · beforeReadFile · preToolUse (file tools)
 *     → `failClosed: true`, timeout 300 s: a crash, timeout or non-0/2 exit BLOCKS
 *   sessionEnd → ends the hook-managed AgentGate session (fire and forget)
 * Entries are recognized by the shim name + INSTALL_MARKER; nothing else in the file is
 * touched. The file is backed up before every change, and uninstall restores the original
 * bytes when the file was not edited since our write (otherwise it removes only our entries).
 * Installs are recorded in $AGENTGATE_HOME/cursor-installs.json for `agentgate uninstall`.
 */

export const CURSOR_GATE_TIMEOUT_S = 300;
export const CURSOR_SESSION_END_TIMEOUT_S = 10;
export const CURSOR_OUR_EVENTS = ["beforeShellExecution", "beforeMCPExecution", "beforeReadFile", "preToolUse", "sessionEnd"] as const;
const SHIM_NAME = "agentgate-hook.sh";

type Json = Record<string, unknown>;
type Scope = "project" | "user";
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

export function userCursorHooksPath(): string {
  return join(homedir(), ".cursor", "hooks.json");
}
export function projectCursorHooksPath(dir: string): string {
  return join(dir, ".cursor", "hooks.json");
}

// ── pure hooks.json merge helpers ───────────────────────────────────────────

export interface CursorHookCommandSpec {
  shimPath: string;
  nodePath: string;
  home: string;
  env?: string;
  ttl?: number;
}

/** Absolute paths only; no tokens. Marker + provider args are read by the shim, not Cursor. */
export function buildCursorHookCommand(s: CursorHookCommandSpec): string {
  const vars: Array<[string, string]> = [
    ["AGENTGATE_HOME", s.home],
    ["AGENTGATE_NODE", s.nodePath],
    ["AGENTGATE_HOOK_TIMEOUT_S", String(CURSOR_GATE_TIMEOUT_S)],
  ];
  if (s.env) vars.push(["AGENTGATE_ENV", s.env]);
  if (s.ttl) vars.push(["AGENTGATE_TTL", String(s.ttl)]);
  return `${vars.map(([k, v]) => `${k}=${shellQuote(v)}`).join(" ")} ${shellQuote(s.shimPath)} ${PROVIDER_ARG} ${INSTALL_MARKER}`;
}

export function isOurCursorCommand(cmd: unknown): boolean {
  return typeof cmd === "string" && cmd.includes(SHIM_NAME) && cmd.includes(INSTALL_MARKER);
}

export function ourCursorEntries(command: string): Record<(typeof CURSOR_OUR_EVENTS)[number], Json> {
  const gate = { command, timeout: CURSOR_GATE_TIMEOUT_S, failClosed: true };
  return {
    beforeShellExecution: { ...gate },
    beforeMCPExecution: { ...gate },
    beforeReadFile: { ...gate },
    preToolUse: { command, matcher: FILE_TOOL_MATCHER, timeout: CURSOR_GATE_TIMEOUT_S, failClosed: true },
    sessionEnd: { command, timeout: CURSOR_SESSION_END_TIMEOUT_S },
  };
}

/** Throws on shapes we refuse to edit (never guess). */
export function validateHooksDoc(doc: unknown, file: string): Json {
  if (!isObj(doc)) throw new Error(`${file} is not a JSON object — not modifying it`);
  if (doc.version !== undefined && doc.version !== 1) throw new Error(`${file}: unsupported hooks.json "version" ${JSON.stringify(doc.version)} (expected 1) — not modifying it`);
  if (doc.hooks !== undefined) {
    if (!isObj(doc.hooks)) throw new Error(`${file}: "hooks" is not an object — not modifying it`);
    for (const [ev, v] of Object.entries(doc.hooks)) if (!Array.isArray(v)) throw new Error(`${file}: hooks.${ev} is not an array — not modifying it`);
  }
  return doc;
}

export function removeOurCursorHooks(doc: Json): { doc: Json; removed: number } {
  if (!isObj(doc.hooks)) return { doc, removed: 0 };
  let removed = 0;
  const hooks: Json = {};
  for (const [ev, list] of Object.entries(doc.hooks)) {
    if (!Array.isArray(list)) {
      hooks[ev] = list;
      continue;
    }
    const kept = list.filter((h) => !(isObj(h) && isOurCursorCommand(h.command)));
    removed += list.length - kept.length;
    hooks[ev] = kept;
  }
  return { doc: { ...doc, hooks }, removed };
}

/** Idempotent: drop any previous AgentGate entries, then append ours (user hooks keep their order). */
export function addOurCursorHooks(doc: Json, command: string): Json {
  const base = removeOurCursorHooks(doc).doc;
  const hooks: Json = isObj(base.hooks) ? { ...base.hooks } : {};
  const ours = ourCursorEntries(command);
  for (const ev of CURSOR_OUR_EVENTS) hooks[ev] = [...(Array.isArray(hooks[ev]) ? (hooks[ev] as unknown[]) : []), ours[ev]];
  return base.version === undefined ? { version: 1, ...base, hooks } : { ...base, hooks };
}

export function findOurCursorCommands(doc: unknown): Array<{ event: string; command: string }> {
  if (!isObj(doc) || !isObj(doc.hooks)) return [];
  const found: Array<{ event: string; command: string }> = [];
  for (const [ev, list] of Object.entries(doc.hooks)) {
    if (!Array.isArray(list)) continue;
    for (const h of list) if (isObj(h) && isOurCursorCommand(h.command)) found.push({ event: ev, command: h.command as string });
  }
  return found;
}

function detectIndent(text: string): number {
  const m = text.match(/\n( +)"/);
  return m ? m[1]!.length : 2;
}

// ── install records ─────────────────────────────────────────────────────────

const Restore = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("bytes"), text: z.string() }),
  z.object({ kind: z.literal("absent") }),
  z.object({ kind: z.literal("semantic") }),
]);
const CursorRecord = z.object({
  scope: z.enum(["project", "user"]),
  file: z.string(),
  project_dir: z.string().nullable(),
  restore: Restore,
  written_sha256: z.string(),
  created_dir: z.boolean(),
  created_version: z.boolean(),
  created_hooks_key: z.boolean(),
  created_events: z.array(z.string()),
  git_exclude: z.string().nullable(),
  installed_at: z.string(),
});
type CursorRecord = z.infer<typeof CursorRecord>;

const recordsPath = () => join(agentgateHome(), "cursor-installs.json");
function readRecords(): Record<string, CursorRecord> {
  try {
    return z.record(z.string(), CursorRecord).parse(JSON.parse(readFileSync(recordsPath(), "utf8")));
  } catch {
    return {};
  }
}
function writeRecords(r: Record<string, CursorRecord>) {
  mkdirSync(agentgateHome(), { recursive: true, mode: 0o700 });
  atomicWrite(recordsPath(), `${JSON.stringify(r, null, 2)}\n`, 0o600);
}

/** Cursor hooks.json files AgentGate installed into (for `agentgate uninstall`). */
export function cursorInstalls(): Array<{ scope: Scope; file: string; projectDir: string | null }> {
  return Object.values(readRecords()).map((r) => ({ scope: r.scope, file: r.file, projectDir: r.project_dir }));
}

function readText(file: string): string | null {
  return existsSync(file) ? readFileSync(file, "utf8") : null;
}

function parseHooks(file: string, text: string | null): Json | null {
  if (text === null) return null;
  if (!text.trim()) return {};
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    throw new Error(`${file} is not valid JSON (${(err as Error).message}) — not modifying it`);
  }
  return validateHooksDoc(doc, file);
}

/** Our hook in this hooks.json? (unreadable/invalid → false) */
export function hasOurCursorHook(file: string): boolean {
  try {
    return findOurCursorCommands(JSON.parse(readFileSync(file, "utf8"))).length > 0;
  } catch {
    return false;
  }
}

/**
 * A native AgentGate Cursor hook applies to a Cursor window with these workspace roots
 * (user file, or a project file in any root). Used to avoid double-gating through
 * Cursor's Claude Code hook import.
 */
export function cursorHookInstalledFor(workspaceRoots: string[]): boolean {
  if (hasOurCursorHook(userCursorHooksPath())) return true;
  return workspaceRoots.some((r) => typeof r === "string" && r && hasOurCursorHook(projectCursorHooksPath(r)));
}

// ── file helpers ────────────────────────────────────────────────────────────

function atomicWrite(file: string, content: string, mode: number) {
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, content, { mode });
  chmodSync(tmp, mode);
  renameSync(tmp, file);
}

function backup(file: string): string {
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  let dest = `${file}.agentgate-backup-${stamp}`;
  for (let i = 1; existsSync(dest); i++) dest = `${file}.agentgate-backup-${stamp}-${i}`;
  copyFileSync(file, dest);
  chmodSync(dest, 0o600);
  return dest;
}

const modeOf = (file: string) => (existsSync(file) ? statSync(file).mode & 0o777 : 0o644);

function target(o: { project?: string; user: boolean }): { scope: Scope; file: string; projectDir: string | null } {
  if (o.user) return { scope: "user", file: userCursorHooksPath(), projectDir: null };
  const dir = resolve(o.project ?? process.cwd());
  if (!existsSync(dir) || !statSync(dir).isDirectory()) throw new Error(`project directory not found: ${dir}`);
  const real = realpathSync(dir);
  return { scope: "project", file: projectCursorHooksPath(real), projectDir: real };
}

function git(cwd: string, args: string[]): { ok: boolean; out: string } {
  try {
    return { ok: true, out: execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 3_000 }).trim() };
  } catch {
    return { ok: false, out: "" };
  }
}

const EXCLUDE_COMMENT = "# added by agentgate install cursor";

/** Keeps the machine-local hooks.json out of commits (.git/info/exclude, personal + untracked). */
function ensureGitIgnored(projectDir: string, file: string): string | null {
  if (!git(projectDir, ["rev-parse", "--git-dir"]).ok) return null;
  const rel = relative(projectDir, file);
  if (git(projectDir, ["ls-files", "--error-unmatch", rel]).ok) {
    log.warn(`${rel} is TRACKED by git — AgentGate's entry contains machine-local paths; don't commit it (teammates without AgentGate would be blocked)`);
    return null;
  }
  if (git(projectDir, ["check-ignore", "-q", rel]).ok) return null;
  const ex = git(projectDir, ["rev-parse", "--git-path", "info/exclude"]);
  if (!ex.ok || !ex.out) return null;
  const excludeFile = isAbsolute(ex.out) ? ex.out : join(projectDir, ex.out);
  mkdirSync(dirname(excludeFile), { recursive: true });
  const cur = existsSync(excludeFile) ? readFileSync(excludeFile, "utf8") : "";
  writeFileSync(excludeFile, `${cur}${cur && !cur.endsWith("\n") ? "\n" : ""}${EXCLUDE_COMMENT}\n/${rel.split("\\").join("/")}\n`);
  return excludeFile;
}

function removeGitExclude(excludeFile: string, file: string, projectDir: string) {
  try {
    const line = `/${relative(projectDir, file).split("\\").join("/")}`;
    const cur = readFileSync(excludeFile, "utf8");
    const next = cur.replace(`${EXCLUDE_COMMENT}\n${line}\n`, "");
    if (next !== cur) writeFileSync(excludeFile, next);
  } catch {
    /* best effort */
  }
}

// ── install ─────────────────────────────────────────────────────────────────

export interface CursorInstallOptions {
  project?: string;
  user: boolean;
  yes: boolean;
  env?: string;
  ttl?: number;
}

export async function installCursorCommand(o: CursorInstallOptions): Promise<number> {
  if (o.user && o.project) {
    log.fail("choose either --project <dir> or --user");
    return EXIT.USAGE;
  }
  if (o.user) {
    log.warn(c.bold("--user gates the Cursor agent in EVERY workspace for this OS user."));
    log.warn("Hooks are FAIL-CLOSED: if the AgentGate server is unreachable or you are logged out,");
    log.warn("the Cursor agent's terminal commands, file edits, sensitive reads and MCP calls are BLOCKED.");
    log.warn("Undo with: agentgate uninstall cursor --user");
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

  const cfg = loadConfig();
  if (!cfg?.access_token || !cfg.signing_key) {
    log.fail("not logged in — run `agentgate login` (or `agentgate setup`) first; the hook would block every action");
    return EXIT.ERROR;
  }
  const l = layout();
  for (const [what, p] of [
    ["hook shim", l.hookShim],
    ["node", l.node],
  ] as const) {
    try {
      accessSync(p, fsc.X_OK);
    } catch {
      log.fail(`${what} is not executable: ${p}`);
      return EXIT.ERROR;
    }
  }

  // One scope only: user + project hooks would both run for every call (two approvals).
  const records = readRecords();
  if (t.scope === "user") {
    const proj = Object.values(records).find((r) => r.scope === "project" && hasOurCursorHook(r.file));
    if (proj) {
      log.fail(`already installed for project ${proj.project_dir} (${proj.file}); uninstall that first — both would ask twice per action`);
      return EXIT.ERROR;
    }
  } else if (hasOurCursorHook(userCursorHooksPath())) {
    log.fail(`already installed for the user (${userCursorHooksPath()}), which covers every workspace; nothing to do for a project`);
    return EXIT.ERROR;
  }

  let text: string | null;
  let doc: Json | null;
  try {
    text = readText(t.file);
    doc = parseHooks(t.file, text);
  } catch (err) {
    log.fail((err as Error).message);
    return EXIT.ERROR;
  }

  const command = buildCursorHookCommand({ shimPath: l.hookShim, nodePath: l.node, home: agentgateHome(), env: o.env, ttl: o.ttl });
  const next = addOurCursorHooks(doc ?? {}, command);
  const prev = records[t.file];
  if (doc && JSON.stringify(doc) === JSON.stringify(next)) {
    if (!prev) {
      // Our entries are there but the record was lost: uninstall can still remove them.
      records[t.file] = newRecord(t, { restore: { kind: "semantic" }, written: text!, createdDir: false, before: doc });
      writeRecords(records);
    }
    log.ok(`already installed in ${t.file} (unchanged)`);
    return EXIT.OK;
  }

  const dir = dirname(t.file);
  const createdDir = !existsSync(dir);
  mkdirSync(dir, { recursive: true });
  const backupPath = text !== null ? backup(t.file) : null;
  const written = `${JSON.stringify(next, null, text ? detectIndent(text) : 2)}\n`;
  atomicWrite(t.file, written, modeOf(t.file));

  // Byte-exact restore is only possible from a state we know: the original file (first
  // install), or our previous write untouched since (re-install with other options).
  const restore: CursorRecord["restore"] = prev
    ? text !== null && sha(text) === prev.written_sha256
      ? prev.restore
      : { kind: "semantic" }
    : text === null
      ? { kind: "absent" }
      : { kind: "bytes", text };
  const record: CursorRecord = prev
    ? { ...prev, restore, written_sha256: sha(written), installed_at: new Date().toISOString() }
    : newRecord(t, { restore, written, createdDir, before: doc });
  if (t.scope === "project" && !record.git_exclude) record.git_exclude = ensureGitIgnored(t.projectDir!, t.file);
  records[t.file] = record;
  writeRecords(records);

  try {
    const config = await requireLogin();
    await claudeAgentId(new AgentGateClient({ server: config.server, accessToken: config.access_token, timeoutMs: 5_000 }), config);
  } catch (err) {
    log.warn(`could not reach the AgentGate server now (${describeError(err)}) — Cursor's gated actions will be BLOCKED until it is reachable`);
  }

  log.ok(`installed AgentGate Cursor hooks (shell, MCP, sensitive reads, file edits) in ${c.bold(t.file)}`);
  if (backupPath) log.step(c.dim(`backup: ${backupPath}`));
  if (record.git_exclude) log.step(c.dim(`git-ignored via ${record.git_exclude}`));
  coexistenceNotes(t);
  log.step(
    t.scope === "project"
      ? `The Cursor agent in ${t.projectDir} is now gated (project hooks only run in TRUSTED workspaces — prefer --user).`
      : "The Cursor agent is now gated in every workspace.",
  );
  log.step(c.dim("Cursor reloads hooks.json automatically; check Cursor Settings → Hooks (or restart Cursor) to confirm."));
  return EXIT.OK;
}

function newRecord(
  t: ReturnType<typeof target>,
  o: { restore: CursorRecord["restore"]; written: string; createdDir: boolean; before: Json | null },
): CursorRecord {
  const beforeHooks = o.before && isObj(o.before.hooks) ? o.before.hooks : null;
  return {
    scope: t.scope,
    file: t.file,
    project_dir: t.projectDir,
    restore: o.restore,
    written_sha256: sha(o.written),
    created_dir: o.createdDir,
    created_version: !o.before || o.before.version === undefined,
    created_hooks_key: !beforeHooks,
    created_events: CURSOR_OUR_EVENTS.filter((ev) => !beforeHooks || !(ev in beforeHooks)),
    git_exclude: null,
    installed_at: new Date().toISOString(),
  };
}

function coexistenceNotes(t: ReturnType<typeof target>) {
  // Cursor also runs Claude Code hooks (Settings → Agents → Third-Party Imports, on by default).
  const claudeFiles = [join(homedir(), ".claude", "settings.json"), ...(t.projectDir ? [join(t.projectDir, ".claude", "settings.local.json"), join(t.projectDir, ".claude", "settings.json")] : [])];
  const withClaude = claudeFiles.filter((f) => {
    try {
      return findOurCommands(JSON.parse(readFileSync(f, "utf8"))).length > 0;
    } catch {
      return false;
    }
  });
  if (withClaude.length) {
    log.step(c.dim(`AgentGate's Claude Code hook (${withClaude.join(", ")}) is also loaded by Cursor; inside Cursor it defers to this hook (no double approvals).`));
  }
  const mcpFiles = [join(homedir(), ".cursor", "mcp.json"), ...(t.projectDir ? [join(t.projectDir, ".cursor", "mcp.json")] : [])];
  const wrapped = mcpFiles.flatMap((f) => {
    try {
      const d = JSON.parse(readFileSync(f, "utf8")) as Json;
      return isObj(d.mcpServers) ? Object.entries(d.mcpServers).filter(([, e]) => isWrapped(e)).map(([n]) => n) : [];
    } catch {
      return [];
    }
  });
  if (wrapped.length) log.step(c.dim(`MCP servers already behind the AgentGate gateway (${wrapped.join(", ")}) are left to the gateway; the hook gates every other MCP server.`));
}

// ── uninstall ───────────────────────────────────────────────────────────────

export function uninstallCursorCommand(o: { project?: string; user: boolean }): number {
  let t: ReturnType<typeof target>;
  try {
    t = target(o);
  } catch (err) {
    log.fail((err as Error).message);
    return EXIT.USAGE;
  }
  const records = readRecords();
  const rec = records[t.file];
  const done = () => {
    if (rec?.git_exclude && t.projectDir) removeGitExclude(rec.git_exclude, t.file, t.projectDir);
    delete records[t.file];
    writeRecords(records);
    return EXIT.OK;
  };

  const text = readText(t.file);
  if (text === null) {
    log.step(`nothing to uninstall (${t.file} does not exist)`);
    return done();
  }

  // Untouched since our write → restore exactly what was there before.
  if (rec && sha(text) === rec.written_sha256 && rec.restore.kind !== "semantic") {
    if (rec.restore.kind === "bytes") {
      const b = backup(t.file);
      atomicWrite(t.file, rec.restore.text, modeOf(t.file));
      log.ok(`restored ${t.file} to its state before \`agentgate install cursor\``);
      log.step(c.dim(`backup: ${b}`));
    } else {
      unlinkSync(t.file);
      removeDirIfCreated(rec);
      log.ok(`removed ${t.file} (it only contained AgentGate hooks)`);
    }
    return done();
  }

  let doc: Json;
  try {
    doc = parseHooks(t.file, text) ?? {};
  } catch (err) {
    log.fail((err as Error).message);
    return EXIT.ERROR;
  }
  const { doc: stripped, removed } = removeOurCursorHooks(doc);
  if (removed === 0) {
    log.step(`no AgentGate hooks found in ${t.file}`);
    return done();
  }
  // Tidy up only containers we created.
  const hooks: Json = { ...((stripped.hooks as Json) ?? {}) };
  for (const ev of rec?.created_events ?? []) if (Array.isArray(hooks[ev]) && (hooks[ev] as unknown[]).length === 0) delete hooks[ev];
  const result: Json = { ...stripped, hooks };
  if (rec?.created_hooks_key && Object.keys(hooks).length === 0) delete result.hooks;
  if (rec?.created_version && result.hooks === undefined) delete result.version;

  if (rec?.restore.kind === "absent" && Object.keys(result).length === 0) {
    unlinkSync(t.file);
    removeDirIfCreated(rec);
    log.ok(`removed ${t.file} (it only contained AgentGate hooks)`);
    return done();
  }
  const b = backup(t.file);
  atomicWrite(t.file, `${JSON.stringify(result, null, detectIndent(text))}\n`, modeOf(t.file));
  log.ok(`removed ${removed} AgentGate hook entr${removed === 1 ? "y" : "ies"} from ${t.file}`);
  log.step(c.dim(`backup: ${b}`));
  return done();
}

function removeDirIfCreated(rec: CursorRecord) {
  if (!rec.created_dir) return;
  try {
    const dir = dirname(rec.file);
    if (readdirSync(dir).length === 0) rmdirSync(dir);
  } catch {
    /* leave it */
  }
}

// ── status ──────────────────────────────────────────────────────────────────

/** One line per scope that gates Cursor for `projectDir` (used by status/tests). */
export function printCursorInstallState(projectDir: string): void {
  const files: Array<[Scope, string]> = [
    ["project", projectCursorHooksPath(projectDir)],
    ["user", userCursorHooksPath()],
  ];
  const found = files.filter(([, f]) => hasOurCursorHook(f));
  if (!found.length) out(`cursor        ${c.dim("hook not installed here (agentgate install cursor)")}`);
  for (const [scope, f] of found) out(`cursor        hook installed (${scope}) ${c.dim(f)}`);
}
