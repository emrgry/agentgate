import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import { z } from "zod";
import { agentgateHome } from "../config.ts";
import { EXIT } from "../exit-codes.ts";
import { c, log, out } from "../output.ts";

/**
 * `agentgate mcp install|uninstall|status --client <claude-desktop|cursor|claude-code|codex>`
 *
 * Rewrites selected stdio MCP server entries of a client's config so the client launches
 * `agentgate.sh mcp wrap --name <name> -- <original command…>` instead. The original entry
 * is stored in $AGENTGATE_HOME/mcp-installs.json; uninstall restores it (the whole file
 * byte-for-byte when nothing else changed since install). Remote (url) servers are skipped.
 * Unexpected formats are refused, never guessed.
 */

export const CLIENTS = ["claude-desktop", "cursor", "claude-code", "codex"] as const;
export type McpClient = (typeof CLIENTS)[number];
export const WRAP_MARKER_ENV = "AGENTGATE_MCP_WRAPPED";

export function shimPath(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "bin", "agentgate.sh");
}

export function configPath(client: McpClient, project: string | undefined): string {
  const home = homedir();
  switch (client) {
    case "claude-desktop":
      return process.platform === "darwin"
        ? join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
        : join(process.env.XDG_CONFIG_HOME || join(home, ".config"), "Claude", "claude_desktop_config.json");
    case "cursor":
      return project ? join(resolve(project), ".cursor", "mcp.json") : join(home, ".cursor", "mcp.json");
    case "claude-code":
      return join(resolve(project ?? process.cwd()), ".mcp.json");
    case "codex":
      return join(process.env.CODEX_HOME || join(home, ".codex"), "config.toml");
  }
}

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

const Record_ = z.object({
  client: z.enum(CLIENTS),
  file: z.string(),
  servers: z.record(z.string(), z.object({ original: z.unknown(), original_toml: z.string().optional() })),
  original_text: z.string().nullable(),
  written_sha256: z.string(),
  installed_at: z.string(),
});
type InstallRecord = z.infer<typeof Record_>;

const recordsPath = () => join(agentgateHome(), "mcp-installs.json");
function readRecords(): Record<string, InstallRecord> {
  try {
    return z.record(z.string(), Record_).parse(JSON.parse(readFileSync(recordsPath(), "utf8")));
  } catch {
    return {};
  }
}
function writeRecords(r: Record<string, InstallRecord>) {
  mkdirSync(agentgateHome(), { recursive: true, mode: 0o700 });
  atomicWrite(recordsPath(), `${JSON.stringify(r, null, 2)}\n`, 0o600);
}

const sha = (s: string) => createHash("sha256").update(s).digest("hex");

function atomicWrite(file: string, content: string, mode?: number) {
  const m = mode ?? (existsSync(file) ? statSync(file).mode & 0o777 : 0o600);
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, content, { mode: m });
  chmodSync(tmp, m);
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

function detectIndent(text: string): number {
  const m = text.match(/\n( +)"/);
  return m ? m[1]!.length : 2;
}

export interface Entry {
  command?: unknown;
  args?: unknown;
  env?: unknown;
  url?: unknown;
  type?: unknown;
  [k: string]: unknown;
}

export function isWrapped(e: unknown): boolean {
  return isObj(e) && isObj(e.env) && (e.env as Json)[WRAP_MARKER_ENV] === "1";
}

function remoteReason(e: Entry): string | null {
  if (typeof e.url === "string" || e.type === "http" || e.type === "sse" || e.type === "streamable-http") return "remote (HTTP/SSE) server — out of scope for now";
  if (typeof e.command !== "string" || !e.command) return "no stdio `command`";
  if (e.args !== undefined && !(Array.isArray(e.args) && e.args.every((a) => typeof a === "string"))) return "`args` is not a list of strings";
  if (e.env !== undefined && !(isObj(e.env) && Object.values(e.env).every((v) => typeof v === "string"))) return "`env` is not a string map";
  return null;
}

export function wrapEntry(name: string, e: Entry): Entry {
  const { command, args, env, ...rest } = e;
  return {
    ...rest,
    command: shimPath(),
    args: ["mcp", "wrap", "--name", name, "--", command as string, ...((args as string[] | undefined) ?? [])],
    env: {
      ...((env as Record<string, string> | undefined) ?? {}),
      AGENTGATE_HOME: agentgateHome(),
      AGENTGATE_NODE: process.execPath,
      [WRAP_MARKER_ENV]: "1",
    },
  };
}

interface Selection {
  names?: string[];
  all: boolean;
}

function select(servers: Json, sel: Selection): { chosen: string[]; problems: string[] } {
  const problems: string[] = [];
  const names = sel.all ? Object.keys(servers) : (sel.names ?? []);
  const chosen: string[] = [];
  for (const n of names) {
    const e = servers[n];
    if (!isObj(e)) {
      problems.push(`${n}: not found`);
      continue;
    }
    if (isWrapped(e)) {
      problems.push(`${n}: already wrapped`);
      continue;
    }
    const r = remoteReason(e as Entry);
    if (r) {
      problems.push(`${n}: skipped — ${r}`);
      continue;
    }
    chosen.push(n);
  }
  return { chosen, problems };
}

// ── JSON clients ────────────────────────────────────────────────────────────

function readJsonConfig(file: string): { text: string; doc: Json } | null {
  if (!existsSync(file)) return null;
  const text = readFileSync(file, "utf8");
  let doc: unknown;
  try {
    doc = text.trim() ? JSON.parse(text) : {};
  } catch (err) {
    throw new Error(`${file} is not valid JSON (${(err as Error).message}) — not modifying it`);
  }
  if (!isObj(doc)) throw new Error(`${file} is not a JSON object — not modifying it`);
  if (doc.mcpServers !== undefined && !isObj(doc.mcpServers)) throw new Error(`${file}: "mcpServers" is not an object — not modifying it`);
  return { text, doc };
}

// ── Codex TOML (block-level edit, verified by re-parsing) ───────────────────

const tomlKey = (name: string) => (/^[A-Za-z0-9_-]+$/.test(name) ? name : JSON.stringify(name));

/** Line range [start, end) of `[mcp_servers.<name>]` and its sub-tables; null if absent. */
function tomlBlock(text: string, name: string): { start: number; end: number } | null {
  const linesArr = text.split("\n");
  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const keyRe = `(?:${esc(name)}|"${esc(name)}"|'${esc(name)}')`;
  const own = new RegExp(`^\\s*\\[\\s*mcp_servers\\s*\\.\\s*${keyRe}\\s*(\\]|\\.)`);
  const anyHeader = /^\s*\[/;
  let start = -1;
  let end = linesArr.length;
  for (let i = 0; i < linesArr.length; i++) {
    const l = linesArr[i]!;
    if (start === -1) {
      if (own.test(l)) start = i;
      continue;
    }
    if (anyHeader.test(l) && !own.test(l)) {
      end = i;
      break;
    }
  }
  if (start === -1) return null;
  // Refuse split definitions (another header for this server later in the file).
  for (let i = end; i < linesArr.length; i++) if (own.test(linesArr[i]!)) throw new Error(`[mcp_servers.${name}] is split across the file — refusing to edit`);
  // Trailing blank lines/comments belong to whatever follows; keep them outside our block.
  while (end - 1 > start && /^\s*(#.*)?$/.test(linesArr[end - 1]!)) end--;
  const offsets = (n: number) => linesArr.slice(0, n).reduce((a, l) => a + l.length + 1, 0);
  return { start: offsets(start), end: Math.min(offsets(end), text.length) };
}

function stripServer(doc: Json, name: string): Json {
  const copy = JSON.parse(JSON.stringify(doc)) as Json;
  if (isObj(copy.mcp_servers)) {
    delete (copy.mcp_servers as Json)[name];
    if (Object.keys(copy.mcp_servers as Json).length === 0) delete copy.mcp_servers;
  }
  return copy;
}

function tomlReplaceServer(text: string, name: string, entry: Json): { text: string; originalBlock: string } {
  const before = parseToml(text) as Json;
  const blk = tomlBlock(text, name);
  if (!blk) throw new Error(`[mcp_servers.${name}] is not defined as a table header (inline/dotted definitions are not supported) — edit ${name} manually`);
  const originalBlock = text.slice(blk.start, blk.end);
  const rendered = stringifyToml({ mcp_servers: { [name]: entry } }).trim();
  const next = `${text.slice(0, blk.start)}${rendered}\n${text.slice(blk.end).replace(/^\n?/, text.slice(blk.end).startsWith("\n") ? "\n" : "")}`;
  verifyToml(before, next, name, entry);
  return { text: next, originalBlock };
}

function verifyToml(before: Json, nextText: string, name: string, entry: Json | null) {
  let after: Json;
  try {
    after = parseToml(nextText) as Json;
  } catch (err) {
    throw new Error(`refusing: the edited TOML would not parse (${(err as Error).message})`);
  }
  const got = (after.mcp_servers as Json | undefined)?.[name];
  if (entry && JSON.stringify(sortDeep(got)) !== JSON.stringify(sortDeep(entry))) throw new Error("refusing: TOML round-trip changed the server entry");
  if (JSON.stringify(sortDeep(stripServer(after, name))) !== JSON.stringify(sortDeep(stripServer(before, name)))) {
    throw new Error("refusing: TOML edit would change unrelated settings");
  }
}

function sortDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (isObj(v)) return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortDeep(v[k])]));
  return v;
}

// ── commands ────────────────────────────────────────────────────────────────

export interface McpInstallOptions {
  client: string | undefined;
  project?: string;
  servers: string[];
  all: boolean;
}

function checkClient(c_: string | undefined): McpClient | null {
  return (CLIENTS as readonly string[]).includes(c_ ?? "") ? (c_ as McpClient) : null;
}

export function mcpInstall(o: McpInstallOptions): number {
  const client = checkClient(o.client);
  if (!client) {
    log.fail(`--client must be one of: ${CLIENTS.join(", ")}`);
    return EXIT.USAGE;
  }
  if (!o.all && o.servers.length === 0) {
    log.fail("choose servers with --server <name> (repeatable) or --all");
    return EXIT.USAGE;
  }
  const file = configPath(client, o.project);
  try {
    return client === "codex" ? installToml(file, o) : installJson(client, file, o);
  } catch (err) {
    log.fail((err as Error).message);
    return EXIT.ERROR;
  }
}

function report(client: McpClient, file: string, chosen: string[], problems: string[], backupPath: string | null) {
  for (const p of problems) log.warn(p);
  if (chosen.length === 0) {
    log.step("nothing to wrap");
    return;
  }
  log.ok(`wrapped ${chosen.map((n) => c.bold(n)).join(", ")} in ${file}`);
  if (backupPath) log.step(c.dim(`backup: ${backupPath}`));
  log.step(`Restart ${client === "claude-desktop" ? "the Claude desktop app" : client === "cursor" ? "Cursor" : client === "codex" ? "Codex" : "Claude Code"} to apply. Tool calls of these servers now need AgentGate approval per policy.`);
}

function installJson(client: McpClient, file: string, o: McpInstallOptions): number {
  const cfg = readJsonConfig(file);
  if (!cfg) {
    log.fail(`${file} not found — no MCP servers configured for ${client}`);
    return EXIT.ERROR;
  }
  const servers = (cfg.doc.mcpServers as Json | undefined) ?? {};
  const { chosen, problems } = select(servers, { names: o.servers, all: o.all });
  if (chosen.length === 0) {
    report(client, file, chosen, problems, null);
    return problems.some((p) => p.endsWith("not found")) ? EXIT.ERROR : EXIT.OK;
  }
  const records = readRecords();
  const prev = records[file];
  const nextServers: Json = { ...servers };
  const saved: InstallRecord["servers"] = { ...(prev?.servers ?? {}) };
  for (const n of chosen) {
    saved[n] = { original: servers[n] };
    nextServers[n] = wrapEntry(n, servers[n] as Entry);
  }
  const text = `${JSON.stringify({ ...cfg.doc, mcpServers: nextServers }, null, detectIndent(cfg.text))}\n`;
  const b = backup(file);
  atomicWrite(file, text);
  records[file] = {
    client,
    file,
    servers: saved,
    original_text: prev ? prev.original_text : cfg.text,
    written_sha256: sha(text),
    installed_at: new Date().toISOString(),
  };
  writeRecords(records);
  report(client, file, chosen, problems, b);
  return EXIT.OK;
}

function installToml(file: string, o: McpInstallOptions): number {
  if (!existsSync(file)) {
    log.fail(`${file} not found — no MCP servers configured for codex`);
    return EXIT.ERROR;
  }
  const original = readFileSync(file, "utf8");
  let doc: Json;
  try {
    doc = parseToml(original) as Json;
  } catch (err) {
    throw new Error(`${file} is not valid TOML (${(err as Error).message}) — not modifying it`);
  }
  const servers = (isObj(doc.mcp_servers) ? doc.mcp_servers : {}) as Json;
  const { chosen, problems } = select(servers, { names: o.servers, all: o.all });
  if (chosen.length === 0) {
    report("codex", file, chosen, problems, null);
    return problems.some((p) => p.endsWith("not found")) ? EXIT.ERROR : EXIT.OK;
  }
  const records = readRecords();
  const prev = records[file];
  const saved: InstallRecord["servers"] = { ...(prev?.servers ?? {}) };
  let text = original;
  for (const n of chosen) {
    const r = tomlReplaceServer(text, n, wrapEntry(n, servers[n] as Entry) as Json);
    saved[n] = { original: servers[n], original_toml: r.originalBlock };
    text = r.text;
  }
  const b = backup(file);
  atomicWrite(file, text);
  records[file] = {
    client: "codex",
    file,
    servers: saved,
    original_text: prev ? prev.original_text : original,
    written_sha256: sha(text),
    installed_at: new Date().toISOString(),
  };
  writeRecords(records);
  report("codex", file, chosen, problems, b);
  return EXIT.OK;
}

export function mcpUninstall(o: McpInstallOptions): number {
  const client = checkClient(o.client);
  if (!client) {
    log.fail(`--client must be one of: ${CLIENTS.join(", ")}`);
    return EXIT.USAGE;
  }
  const file = configPath(client, o.project);
  const records = readRecords();
  const rec = records[file];
  if (!rec || !existsSync(file)) {
    log.step(`no AgentGate MCP wrapping recorded for ${file}`);
    return EXIT.OK;
  }
  const current = readFileSync(file, "utf8");
  const all = o.all || o.servers.length === 0;
  const targets = all ? Object.keys(rec.servers) : o.servers.filter((n) => rec.servers[n]);
  try {
    const b = backup(file);
    if (all && rec.original_text !== null && sha(current) === rec.written_sha256) {
      // Untouched since our write: restore the original file byte-for-byte.
      atomicWrite(file, rec.original_text);
    } else if (client === "codex") {
      let text = current;
      for (const n of targets) {
        const s = rec.servers[n]!;
        const before = parseToml(text) as Json;
        const blk = tomlBlock(text, n);
        if (!blk || !isWrapped((before.mcp_servers as Json | undefined)?.[n])) continue;
        text = `${text.slice(0, blk.start)}${s.original_toml ?? stringifyToml({ mcp_servers: { [n]: s.original } }).trim()}${text.slice(blk.end)}`;
        verifyToml(before, text, n, s.original as Json);
      }
      atomicWrite(file, text);
    } else {
      const cfg = readJsonConfig(file)!;
      const servers = { ...((cfg.doc.mcpServers as Json | undefined) ?? {}) };
      for (const n of targets) if (isWrapped(servers[n])) servers[n] = rec.servers[n]!.original;
      atomicWrite(file, `${JSON.stringify({ ...cfg.doc, mcpServers: servers }, null, detectIndent(cfg.text))}\n`);
    }
    for (const n of targets) delete rec.servers[n];
    if (Object.keys(rec.servers).length === 0) delete records[file];
    else {
      // Partially restored: the original bytes no longer correspond to a state we can
      // reproduce (the user may also have edited the file) → semantic restore from now on.
      rec.original_text = null;
      rec.written_sha256 = sha(readFileSync(file, "utf8"));
    }
    writeRecords(records);
    log.ok(`restored ${targets.join(", ") || "(nothing)"} in ${file}`);
    log.step(c.dim(`backup: ${b}`));
    log.step("Restart the client app to apply.");
    return EXIT.OK;
  } catch (err) {
    log.fail((err as Error).message);
    return EXIT.ERROR;
  }
}

export function mcpStatus(o: { project?: string }): number {
  for (const client of CLIENTS) {
    const file = configPath(client, o.project);
    if (!existsSync(file)) {
      out(`${client.padEnd(15)} ${c.dim(`no config (${file})`)}`);
      continue;
    }
    let servers: Json = {};
    try {
      if (client === "codex") {
        const d = parseToml(readFileSync(file, "utf8")) as Json;
        servers = isObj(d.mcp_servers) ? (d.mcp_servers as Json) : {};
      } else {
        servers = ((readJsonConfig(file)?.doc.mcpServers as Json | undefined) ?? {}) as Json;
      }
    } catch (err) {
      out(`${client.padEnd(15)} ${c.red(`unreadable: ${(err as Error).message}`)}`);
      continue;
    }
    const names = Object.keys(servers);
    out(`${client.padEnd(15)} ${file}`);
    if (names.length === 0) out(`${"".padEnd(15)} ${c.dim("(no MCP servers)")}`);
    for (const n of names) {
      const e = servers[n] as Entry;
      const state = isWrapped(e) ? c.green("gated by AgentGate") : remoteReason(e) ? c.dim(`not wrappable (${remoteReason(e)})`) : c.yellow("NOT gated");
      out(`${"".padEnd(15)} ${n.padEnd(24)} ${state}`);
    }
  }
  return EXIT.OK;
}
