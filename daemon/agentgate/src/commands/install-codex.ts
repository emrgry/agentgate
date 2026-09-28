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
import { compareVersions } from "@agentgate/adapter-codex";
import { z } from "zod";
import { describeError } from "../authorize.ts";
import { claudeAgentId } from "../claude-sessions.ts";
import { AgentGateClient } from "../client/index.ts";
import {
  addOurCodexHooks,
  appendTrustBlock,
  buildCodexHookCommand,
  CODEX_MIN_VERIFIED_VERSION,
  codexTrustEntries,
  findOurCodexCommands,
  hooksDisabledIn,
  otherPreToolUseHooks,
  removeOurCodexHooks,
  removeOurTrust,
  renderTrustBlock,
  trustConflict,
  trustedIn,
  validateCodexHooksDoc,
  type CodexScope,
  type TrustEntry,
} from "../codex-hooks.ts";
import { agentgateHome, loadConfig } from "../config.ts";
import { EXIT } from "../exit-codes.ts";
import { layout } from "../install-layout.ts";
import { c, log, out } from "../output.ts";
import { requireLogin } from "../runtime.ts";

/**
 * `agentgate install codex [--project <dir> (default: cwd) | --user --yes] [--env E] [--ttl N]`
 * `agentgate uninstall codex [--project <dir> | --user]`
 *
 * Gates the user's normal interactive Codex (terminal `codex`, `codex exec`, the IDE
 * extension / app that use the same CODEX_HOME) — not only Control Center turns, which keep
 * their own per-session CODEX_HOME. Two edits, both reversible byte-for-byte:
 *   1. hooks.json (<CODEX_HOME>/hooks.json, or <project>/.codex/hooks.json): a PreToolUse
 *      handler (all tools, timeout 600 s) and a SessionEnd handler (3 s), appended after the
 *      user's own groups; nothing else in the file changes;
 *   2. <CODEX_HOME>/config.toml: a marked block with `[hooks.state."<key>"] trusted_hash`
 *      for exactly those handlers — Codex skips non-managed hooks that are not trusted.
 * Originals are backed up; uninstall restores the original bytes when a file was not
 * edited since our write (otherwise it removes only our entries / our block).
 * Installs are recorded in $AGENTGATE_HOME/codex-installs.json for `agentgate uninstall`.
 */

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

/** The CODEX_HOME Codex resolves: $CODEX_HOME canonicalized, else $HOME/.codex verbatim. */
export function codexHome(): string {
  const env = process.env.CODEX_HOME;
  if (env) {
    try {
      return realpathSync(env);
    } catch {
      return resolve(env);
    }
  }
  return join(homedir(), ".codex");
}
export const userCodexHooksPath = () => join(codexHome(), "hooks.json");
export const codexConfigPath = () => join(codexHome(), "config.toml");
export const projectCodexHooksPath = (dir: string) => join(dir, ".codex", "hooks.json");

// ── install records ─────────────────────────────────────────────────────────

const Restore = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("bytes"), text: z.string() }),
  z.object({ kind: z.literal("absent") }),
  z.object({ kind: z.literal("semantic") }),
]);
const CodexRecord = z.object({
  scope: z.enum(["project", "user"]),
  file: z.string(),
  project_dir: z.string().nullable(),
  restore: Restore,
  written_sha256: z.string(),
  created_dir: z.boolean(),
  config_file: z.string(),
  /** Exact text appended to config.toml (null: nothing written, e.g. trust conflict). */
  config_appended: z.string().nullable(),
  config_created: z.boolean(),
  trust: z.array(z.object({ event: z.string(), key: z.string(), hash: z.string() })),
  git_exclude: z.string().nullable(),
  installed_at: z.string(),
});
type CodexRecord = z.infer<typeof CodexRecord>;

const recordsPath = () => join(agentgateHome(), "codex-installs.json");
function readRecords(): Record<string, CodexRecord> {
  try {
    return z.record(z.string(), CodexRecord).parse(JSON.parse(readFileSync(recordsPath(), "utf8")));
  } catch {
    return {};
  }
}
function writeRecords(r: Record<string, CodexRecord>) {
  mkdirSync(agentgateHome(), { recursive: true, mode: 0o700 });
  atomicWrite(recordsPath(), `${JSON.stringify(r, null, 2)}\n`, 0o600);
}

/** Codex hooks.json files AgentGate installed into (for `agentgate uninstall`). */
export function codexInstalls(): Array<{ scope: CodexScope; file: string; projectDir: string | null }> {
  return Object.values(readRecords()).map((r) => ({ scope: r.scope, file: r.file, projectDir: r.project_dir }));
}

export function hasOurCodexHook(file: string): boolean {
  try {
    return findOurCodexCommands(JSON.parse(readFileSync(file, "utf8"))).length > 0;
  } catch {
    return false;
  }
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

const modeOf = (file: string, dflt: number) => (existsSync(file) ? statSync(file).mode & 0o777 : dflt);
const readText = (file: string): string | null => (existsSync(file) ? readFileSync(file, "utf8") : null);

function parseHooks(file: string, text: string | null): Json | null {
  if (text === null) return null;
  if (!text.trim()) return {};
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    throw new Error(`${file} is not valid JSON (${(err as Error).message}) — not modifying it`);
  }
  return validateCodexHooksDoc(doc, file);
}

function detectIndent(text: string): number {
  const m = text.match(/\n( +)"/);
  return m ? m[1]!.length : 2;
}

interface Target {
  scope: CodexScope;
  file: string;
  projectDir: string | null;
}

function target(o: { project?: string; user: boolean }): Target {
  if (o.user) return { scope: "user", file: userCodexHooksPath(), projectDir: null };
  const dir = resolve(o.project ?? process.cwd());
  if (!existsSync(dir) || !statSync(dir).isDirectory()) throw new Error(`project directory not found: ${dir}`);
  const real = realpathSync(dir);
  return { scope: "project", file: projectCodexHooksPath(real), projectDir: real };
}

function git(cwd: string, args: string[]): { ok: boolean; out: string } {
  try {
    return { ok: true, out: execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 3_000 }).trim() };
  } catch {
    return { ok: false, out: "" };
  }
}

const EXCLUDE_COMMENT = "# added by agentgate install codex";

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

/** `codex --version` of the Codex on PATH (or $AGENTGATE_CODEX_BIN); null when not found. */
export function installedCodexVersion(): string | null {
  try {
    const outp = execFileSync(process.env.AGENTGATE_CODEX_BIN || "codex", ["--version"], { encoding: "utf8", timeout: 5_000, stdio: ["ignore", "pipe", "ignore"] });
    return outp.match(/(\d+\.\d+\.\d+)/)?.[1] ?? null;
  } catch {
    return null;
  }
}

// ── trust (config.toml) ─────────────────────────────────────────────────────

interface TrustResult {
  appended: string | null;
  created: boolean;
  trusted: boolean;
  note: string | null;
  backup: string | null;
}

/**
 * Writes the trust block for `entries` into config.toml. `previous` (our last appended block)
 * is removed first, byte-exact, so re-installs never stack blocks.
 */
function writeTrust(configFile: string, entries: TrustEntry[], previous: { appended: string | null; entries: TrustEntry[] }): TrustResult {
  const original = readText(configFile);
  let text = original;
  // Drop what we wrote before (the recorded block, or — record lost — the entries for the
  // handlers that were in hooks.json before this install).
  if (text !== null) text = removeOurTrust(text, previous.entries, previous.appended) ?? text;
  if (trustedIn(text, entries)) {
    if (text !== original) atomicWrite(configFile, text!, modeOf(configFile, 0o600));
    return { appended: null, created: false, trusted: true, note: "already trusted in config.toml", backup: null };
  }
  const conflict = text === null ? null : trustConflict(text, entries);
  if (conflict) {
    if (text !== original) atomicWrite(configFile, text!, modeOf(configFile, 0o600));
    return { appended: null, created: false, trusted: false, note: conflict, backup: null };
  }
  const { text: next, appended } = appendTrustBlock(text, renderTrustBlock(entries));
  mkdirSync(dirname(configFile), { recursive: true, mode: 0o700 });
  const bak = original !== null ? backup(configFile) : null;
  atomicWrite(configFile, next, modeOf(configFile, 0o600));
  return { appended, created: original === null, trusted: true, note: null, backup: bak };
}

/** Removes our trust block. Returns a note when it could not be removed verbatim. */
function removeTrust(rec: { config_file: string; config_appended: string | null; config_created: boolean; trust: TrustEntry[] }): string | null {
  const text = readText(rec.config_file);
  if (text === null) return null;
  const next = removeOurTrust(text, rec.trust, rec.config_appended);
  if (next === null) {
    return rec.config_appended ? `could not find AgentGate's trust entries in ${rec.config_file} (edited?); anything left only trusts the removed hook and is inert` : null;
  }
  if (rec.config_created && next.trim() === "") unlinkSync(rec.config_file);
  else atomicWrite(rec.config_file, next, modeOf(rec.config_file, 0o600));
  return null;
}

// ── install ─────────────────────────────────────────────────────────────────

export interface CodexInstallOptions {
  project?: string;
  user: boolean;
  yes: boolean;
  env?: string;
  ttl?: number;
}

export async function installCodexCommand(o: CodexInstallOptions): Promise<number> {
  if (o.user && o.project) {
    log.fail("choose either --project <dir> or --user");
    return EXIT.USAGE;
  }
  if (o.user) {
    log.warn(c.bold("--user gates EVERY Codex session for this OS user (terminal `codex`, `codex exec`, IDE extension)."));
    log.warn("The hook is FAIL-CLOSED: if the AgentGate server is unreachable or you are logged out,");
    log.warn("Codex's shell commands, file edits (apply_patch) and MCP calls are BLOCKED.");
    log.warn("Undo with: agentgate uninstall codex --user");
    if (!o.yes) {
      log.fail("refusing without --yes");
      return EXIT.USAGE;
    }
  }
  let t: Target;
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
    const proj = Object.values(records).find((r) => r.scope === "project" && hasOurCodexHook(r.file));
    if (proj) {
      log.fail(`already installed for project ${proj.project_dir} (${proj.file}); uninstall that first — both would ask twice per action`);
      return EXIT.ERROR;
    }
  } else if (hasOurCodexHook(userCodexHooksPath())) {
    log.fail(`already installed for the user (${userCodexHooksPath()}), which covers every project; nothing to do for a project`);
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

  const command = buildCodexHookCommand({ shimPath: l.hookShim, nodePath: l.node, home: agentgateHome(), scope: t.scope, env: o.env, ttl: o.ttl });
  const next = addOurCodexHooks(doc ?? {}, command);
  const entries = codexTrustEntries(next, t.file);
  const configFile = codexConfigPath();
  const prev = records[t.file];
  const oldEntries = [...(prev?.trust ?? []), ...(doc ? codexTrustEntries(doc, t.file) : [])];

  if (doc && JSON.stringify(doc) === JSON.stringify(next) && trustedIn(readText(configFile), entries)) {
    if (!prev) {
      records[t.file] = newRecord(t, { restore: { kind: "semantic" }, written: text!, createdDir: false, configFile, trust: null, entries });
      writeRecords(records);
    }
    log.ok(`already installed in ${t.file} (unchanged, trusted)`);
    return EXIT.OK;
  }

  const dir = dirname(t.file);
  const createdDir = !existsSync(dir);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  let backupPath: string | null = null;
  let written = text ?? "";
  if (!doc || JSON.stringify(doc) !== JSON.stringify(next)) {
    backupPath = text !== null ? backup(t.file) : null;
    written = `${JSON.stringify(next, null, text ? detectIndent(text) : 2)}\n`;
    atomicWrite(t.file, written, modeOf(t.file, 0o600));
  }

  let trust: TrustResult;
  try {
    trust = writeTrust(configFile, entries, { appended: prev?.config_appended ?? null, entries: oldEntries });
  } catch (err) {
    trust = { appended: null, created: false, trusted: false, note: `could not update ${configFile}: ${(err as Error).message}`, backup: null };
  }

  // Byte-exact restore is only possible from a state we know: the original file (first
  // install), or our previous write untouched since (re-install with other options).
  const restore: CodexRecord["restore"] = prev
    ? text !== null && sha(text) === prev.written_sha256
      ? prev.restore
      : { kind: "semantic" }
    : text === null
      ? { kind: "absent" }
      : { kind: "bytes", text };
  const record: CodexRecord = prev
    ? {
        ...prev,
        restore,
        written_sha256: sha(written),
        config_file: configFile,
        config_appended: trust.appended,
        config_created: trust.appended ? trust.created || prev.config_created : false,
        trust: entries,
        installed_at: new Date().toISOString(),
      }
    : newRecord(t, { restore, written, createdDir, configFile, trust, entries });
  if (t.scope === "project" && !record.git_exclude) record.git_exclude = ensureGitIgnored(t.projectDir!, t.file);
  records[t.file] = record;
  writeRecords(records);

  try {
    const config = await requireLogin();
    await claudeAgentId(new AgentGateClient({ server: config.server, accessToken: config.access_token, timeoutMs: 5_000 }), config);
  } catch (err) {
    log.warn(`could not reach the AgentGate server now (${describeError(err)}) — Codex's gated actions will be BLOCKED until it is reachable`);
  }

  log.ok(`installed the AgentGate Codex hook (PreToolUse: shell, apply_patch, MCP, other tools; SessionEnd) in ${c.bold(t.file)}`);
  if (backupPath) log.step(c.dim(`backup: ${backupPath}`));
  if (trust.trusted) {
    log.ok(`hook trusted for Codex in ${configFile}${trust.note ? ` (${trust.note})` : ""}`);
    if (trust.backup) log.step(c.dim(`backup: ${trust.backup}`));
  } else {
    log.warn(c.bold(`NOT trusted yet: ${trust.note ?? "unknown reason"}.`));
    log.warn("Codex skips untrusted hooks, so Codex is NOT gated until you trust it: start `codex`, type /hooks,");
    log.warn("and trust the \"AgentGate\" PreToolUse and SessionEnd hooks.");
  }
  if (record.git_exclude) log.step(c.dim(`git-ignored via ${record.git_exclude}`));
  notes(t, next, readText(configFile));
  log.step(
    t.scope === "project"
      ? `Codex sessions in ${t.projectDir} are now gated (project hooks only load when Codex trusts this project — prefer --user).`
      : "Every Codex session for this user is now gated.",
  );
  log.step(c.dim("Restart running Codex sessions so they load the hook; `agentgate status` shows when it last fired."));
  return EXIT.OK;
}

function newRecord(t: Target, o: { restore: CodexRecord["restore"]; written: string; createdDir: boolean; configFile: string; trust: TrustResult | null; entries: TrustEntry[] }): CodexRecord {
  return {
    scope: t.scope,
    file: t.file,
    project_dir: t.projectDir,
    restore: o.restore,
    written_sha256: sha(o.written),
    created_dir: o.createdDir,
    config_file: o.configFile,
    config_appended: o.trust?.appended ?? null,
    config_created: o.trust?.created ?? false,
    trust: o.entries,
    git_exclude: null,
    installed_at: new Date().toISOString(),
  };
}

function notes(t: Target, doc: Json, config: string | null) {
  const v = installedCodexVersion();
  if (!v) log.step(c.dim(`codex not found on PATH — hooks need Codex ≥ ${CODEX_MIN_VERIFIED_VERSION} (verified 0.131–0.158)`));
  else if (compareVersions(v, CODEX_MIN_VERIFIED_VERSION) < 0) log.warn(`codex ${v} is older than ${CODEX_MIN_VERIFIED_VERSION}, the oldest version whose hooks AgentGate verified — update Codex (\`codex update\`)`);
  if (hooksDisabledIn(config)) log.warn(c.bold("config.toml turns hooks OFF ([features] hooks = false) — Codex is NOT gated until you remove that line"));
  const others = otherPreToolUseHooks(doc);
  if (others) {
    log.warn(`${others} other PreToolUse hook(s) in ${t.file} run next to AgentGate's; if one rewrites the tool input (updatedInput), Codex runs the rewritten call after AgentGate checked the original`);
  }
}

// ── uninstall ───────────────────────────────────────────────────────────────

export function uninstallCodexCommand(o: { project?: string; user: boolean }): number {
  if (o.user && o.project) {
    log.fail("choose either --project <dir> or --user");
    return EXIT.USAGE;
  }
  const records = readRecords();
  let t: Target;
  try {
    t = target(o);
  } catch (err) {
    // The project dir may be gone; fall back to the record.
    const dir = o.project ? resolve(o.project) : null;
    const rec = dir ? Object.values(records).find((r) => r.project_dir === dir) : undefined;
    if (!rec) {
      log.fail((err as Error).message);
      return EXIT.USAGE;
    }
    t = { scope: rec.scope, file: rec.file, projectDir: rec.project_dir };
  }
  // A user install recorded under another CODEX_HOME (env changed since): use the record.
  if (t.scope === "user" && !records[t.file]) {
    const other = Object.values(records).find((r) => r.scope === "user");
    if (other) t = { scope: "user", file: other.file, projectDir: null };
  }
  const rec = records[t.file];

  let text: string | null;
  let doc: Json | null;
  try {
    text = readText(t.file);
    doc = parseHooks(t.file, text);
  } catch (err) {
    log.fail((err as Error).message);
    return EXIT.ERROR;
  }

  let failed = false;
  if (text === null || !doc) {
    log.step(`no hooks file at ${t.file}`);
  } else if (removeOurCodexHooks(doc).removed === 0) {
    log.step(`no AgentGate hooks found in ${t.file}`);
  } else if (rec && sha(text) === rec.written_sha256 && rec.restore.kind !== "semantic") {
    // Untouched since our write: put back exactly what was there.
    if (rec.restore.kind === "bytes") {
      atomicWrite(t.file, rec.restore.text, modeOf(t.file, 0o600));
      log.ok(`restored the original ${t.file}`);
    } else {
      unlinkSync(t.file);
      if (rec.created_dir) tryRemoveDir(dirname(t.file));
      log.ok(`removed ${t.file} (it only contained AgentGate's hook)`);
    }
  } else {
    const bak = backup(t.file);
    const stripped = removeOurCodexHooks(doc);
    const hooks = { ...(stripped.doc.hooks as Json) };
    for (const [ev, groups] of Object.entries(hooks)) if (Array.isArray(groups) && groups.length === 0) delete hooks[ev];
    const result: Json = { ...stripped.doc, hooks };
    if (Object.keys(hooks).length === 0) delete result.hooks;
    if (Object.keys(result).length === 0 && rec?.restore.kind === "absent") {
      unlinkSync(t.file);
      if (rec.created_dir) tryRemoveDir(dirname(t.file));
      log.ok(`removed ${t.file} (it only contained AgentGate's hook)`);
    } else {
      atomicWrite(t.file, `${JSON.stringify(result, null, detectIndent(text))}\n`, modeOf(t.file, 0o600));
      log.ok(`removed ${stripped.removed} AgentGate hook entr${stripped.removed === 1 ? "y" : "ies"} from ${t.file} (${rec ? "it was edited since install" : "no install record"}, so only our entries were removed)`);
    }
    log.step(c.dim(`backup: ${bak}`));
  }

  // Our entries: recorded, plus recomputed from the hooks.json that still holds our handlers.
  const liveEntries = doc ? codexTrustEntries(doc, t.file) : [];
  const trustRec = rec ? { ...rec, trust: [...rec.trust, ...liveEntries] } : { config_file: codexConfigPath(), config_appended: null, config_created: false, trust: liveEntries };
  try {
    const before = readText(trustRec.config_file);
    const note = removeTrust(trustRec);
    if (note) log.warn(note);
    else if (before !== readText(trustRec.config_file)) log.ok(`removed AgentGate's hook trust entries from ${trustRec.config_file}`);
  } catch (err) {
    failed = true;
    log.fail(`could not update ${trustRec.config_file}: ${(err as Error).message}`);
  }
  if (rec) {
    if (rec.git_exclude && rec.project_dir) removeGitExclude(rec.git_exclude, t.file, rec.project_dir);
    delete records[t.file];
    writeRecords(records);
  }
  return failed ? EXIT.ERROR : EXIT.OK;
}

function tryRemoveDir(dir: string) {
  try {
    if (readdirSync(dir).length === 0) rmdirSync(dir);
  } catch {
    /* leave it */
  }
}

// ── status ──────────────────────────────────────────────────────────────────

export const codexHeartbeatPath = () => join(agentgateHome(), "codex-hook-last.json");

/** One line per Codex install relevant here (user + this project). Returns false when broken. */
export function printCodexInstallState(projectDir: string): boolean {
  const files: Array<[CodexScope, string]> = [
    ["user", userCodexHooksPath()],
    ["project", projectCodexHooksPath(projectDir)],
  ];
  const config = readText(codexConfigPath());
  let ok = true;
  let any = false;
  for (const [scope, file] of files) {
    let doc: Json | null = null;
    try {
      doc = parseHooks(file, readText(file));
    } catch {
      continue;
    }
    if (!doc || findOurCodexCommands(doc).length === 0) continue;
    any = true;
    const entries = codexTrustEntries(doc, file);
    const shim = findOurCodexCommands(doc)[0]!.command.match(/'([^']*agentgate-hook\.sh)'|(\S*agentgate-hook\.sh)/);
    const shimPath = shim?.[1] ?? shim?.[2];
    const problems: string[] = [];
    if (shimPath) {
      try {
        accessSync(shimPath, fsc.X_OK);
      } catch {
        problems.push(`hook shim not found: ${shimPath} (Codex would fail OPEN — re-run install)`);
      }
    }
    if (!trustedIn(config, entries)) problems.push("not trusted in config.toml — Codex SKIPS it (run `codex`, /hooks, trust AgentGate; or re-run install)");
    if (hooksDisabledIn(config)) problems.push("hooks are disabled in config.toml ([features] hooks = false)");
    if (problems.length) {
      ok = false;
      out(`codex         ${c.red(`NOT GATING (${scope})`)} ${file}: ${problems.join("; ")}`);
    } else {
      out(`codex         hook installed + trusted (${scope}) ${c.dim(file)}`);
    }
  }
  if (!any) {
    out(`codex         ${c.dim("hook not installed (agentgate install codex)")}`);
    return true;
  }
  try {
    const hb = JSON.parse(readFileSync(codexHeartbeatPath(), "utf8")) as { at?: string };
    out(`codex         ${c.dim(`hook last ran ${hb.at ?? "?"}`)}`);
  } catch {
    out(`codex         ${c.yellow("hook has not run yet — start Codex and let it use a tool to confirm")}`);
  }
  return ok;
}
