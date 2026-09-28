import type { ActionSpec, Risk } from "@agentgate/protocol";
import { analyzeShell } from "./shell.ts";
import { assessShellSegment, classifyTargets, maxRisk, RISK_ORDER } from "./risk.ts";
import { normalizePath, structuredPaths, type PathContext } from "./paths.ts";

/**
 * MCP tool calls (`mcp.invoke`), as produced by the MCP gateway:
 *   action.tool      = "<server>/<tool>"
 *   action.arguments = { server, tool, arguments, annotations }
 * Annotations (readOnlyHint, destructiveHint, openWorldHint, …) come from the MCP server
 * and are UNTRUSTED: they may raise risk, never lower the name / argument based floor.
 */

export interface McpIdentity {
  server: string;
  tool: string;
}

export function isMcpInvoke(a: Pick<ActionSpec, "category" | "operation">): boolean {
  return a.category === "mcp" && a.operation === "invoke";
}

export function mcpIdentity(action: ActionSpec): McpIdentity | null {
  if (!isMcpInvoke(action)) return null;
  const args = action.arguments ?? {};
  const [tServer, ...tRest] = (action.tool ?? "").split("/");
  const server = typeof args.server === "string" ? args.server : tRest.length ? tServer ?? "" : "";
  const tool = typeof args.tool === "string" ? args.tool : tRest.length ? tRest.join("/") : (action.tool ?? "");
  return { server, tool };
}

/** Case-sensitive glob: `*` any run of characters, `?` one character. */
export function globMatch(pattern: string, value: string): boolean {
  const re = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${re}$`).test(value);
}

/** Split a tool name into lowercase words: `deleteAllRepos` / `repos.delete-all` → [delete, all, repos]. */
export function toolWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

const READ_VERBS = new Set(["get", "list", "search", "read", "fetch", "describe", "view", "show", "find", "query", "count", "lookup", "check", "inspect", "preview", "download"]);
/** Verbs that are dangerous wherever they appear in the name. */
const DESTRUCTIVE = new Set(["delete", "drop", "remove", "destroy", "purge", "wipe", "truncate", "erase", "rm", "del", "unlink", "kill", "terminate"]);
const FINANCIAL = new Set(["transfer", "pay", "refund", "payout", "withdraw", "wire"]);
const OUTBOUND = new Set(["send", "publish", "tweet", "broadcast"]);
const DEPLOY = new Set(["deploy", "rollout", "promote"]);
const ACCESS = new Set(["grant", "revoke", "impersonate", "chmod", "chown"]);
const EXEC = new Set(["exec", "execute", "eval", "shell", "bash", "sh", "spawn", "subprocess"]);
/** Nouns that are dangerous only when not preceded by a read verb (`create_charge` vs `get_charge`). */
const AMBIGUOUS: Record<string, "financial" | "outbound" | "deploy" | "access" | "exec"> = {
  comment: "outbound",
  reply: "outbound",
  notify: "outbound",
  dm: "outbound",
  terminal: "exec",
  charge: "financial",
  payment: "financial",
  invoice: "financial",
  post: "outbound",
  email: "outbound",
  message: "outbound",
  mail: "outbound",
  sms: "outbound",
  release: "deploy",
  permission: "access",
  permissions: "access",
  role: "access",
  roles: "access",
  acl: "access",
  collaborator: "access",
  member: "access",
};
const BULK = new Set(["all", "bulk", "batch", "everything", "mass"]);

/** Name-based floor for an MCP tool, or null when the name says nothing. */
export function mcpNameFloor(tool: string): Risk | null {
  const words = toolWords(tool);
  if (words.length === 0) return null;
  const readish = READ_VERBS.has(words[0]!);
  const kinds = new Set<string>();
  for (let i = 0; i < words.length; i++) {
    const w = words[i]!;
    if (DESTRUCTIVE.has(w)) kinds.add("destructive");
    if (FINANCIAL.has(w)) kinds.add("financial");
    if (OUTBOUND.has(w)) kinds.add("outbound");
    if (DEPLOY.has(w)) kinds.add("deploy");
    if (ACCESS.has(w)) kinds.add("access");
    if (EXEC.has(w)) kinds.add("exec");
    if (w === "run" && ["command", "cmd", "script", "code", "shell", "sql", "query"].includes(words[i + 1] ?? "")) kinds.add("exec");
    const amb = AMBIGUOUS[w];
    if (amb && !readish) kinds.add(amb);
  }
  if (kinds.size === 0) return null;
  const bulk = words.some((w) => BULK.has(w));
  if (kinds.has("financial")) return { level: "critical", reason: `MCP tool ${tool} moves money` };
  if (kinds.has("destructive") && bulk) return { level: "critical", reason: `MCP tool ${tool} deletes in bulk` };
  const what = [...kinds].join(" / ");
  return { level: "high", reason: `MCP tool ${tool} is ${what} by name` };
}

const SQL_KEY_RE = /^(sql|query|statement|stmt|sql_query|raw_sql|sql_statement)$/i;
const COMMAND_KEY_RE = /^(command|cmd|script|shell|bash|command_line|commandline|shell_command)$/i;

/** Risk of a SQL string, or null for reads. */
export function sqlRisk(sql: string): Risk | null {
  const s = sql.replace(/--[^\n]*|\/\*[\s\S]*?\*\//g, " ");
  const statements = s.split(";").map((x) => x.trim()).filter(Boolean);
  let out: Risk | null = null;
  const bump = (r: Risk) => (out = out ? maxRisk(out, r) : r);
  for (const st of statements) {
    // Only real SQL shapes count, so a search query like "update readme" is not a mutation.
    if (/^(drop\s+(table|database|schema|index|view|user|role)|truncate(\s+table)?\s+[\w."`\[]+)/i.test(st)) {
      bump({ level: "critical", reason: "SQL drop / truncate" });
    } else if (/^(delete\s+from\b|update\s+[\w."`\[\]]+\s+set\b)/i.test(st)) {
      bump(/\bwhere\b/i.test(st) ? { level: "high", reason: "SQL delete / update" } : { level: "critical", reason: "SQL delete / update without WHERE" });
    } else if (/^(alter\s+(table|database|schema|user|role|index|view)|grant\s+\S+.*\s(on|to)\s|revoke\s+\S+.*\s(on|from)\s|insert\s+into\b|create\s+(table|database|schema|user|role|index|view|function|trigger|or\s+replace)|replace\s+into\b|merge\s+into\b|copy\s+\S+\s+(from|to)\b|call\s+\w+\s*\()/i.test(st)) {
      bump({ level: "high", reason: "SQL mutation" });
    }
  }
  return out;
}

/** Risk from scanning argument values (SQL, shell commands). Also returns the commands found. */
export function scanMcpArguments(value: unknown, ctx: PathContext = {}): { risk: Risk | null; commands: string[] } {
  let risk: Risk | null = null;
  const commands: string[] = [];
  const bump = (r: Risk | null) => {
    if (r) risk = risk ? maxRisk(risk, r) : r;
  };
  const walk = (v: unknown, key: string, depth: number) => {
    if (depth > 8 || v === null || v === undefined) return;
    if (typeof v === "string") {
      if (SQL_KEY_RE.test(key)) bump(sqlRisk(v));
      if (COMMAND_KEY_RE.test(key) && v.trim()) {
        commands.push(v);
        bump(shellRisk(v, ctx));
      }
      return;
    }
    if (Array.isArray(v)) {
      if (COMMAND_KEY_RE.test(key) && v.every((x) => typeof x === "string") && v.length) {
        const cmd = (v as string[]).map((x) => (/[\s'"\\$`;|&<>()]/.test(x) ? `'${x.replace(/'/g, "'\\''")}'` : x)).join(" ");
        commands.push(cmd);
        bump(shellRisk(cmd, ctx));
        return;
      }
      for (const x of v) walk(x, key, depth + 1);
      return;
    }
    if (typeof v === "object") for (const [k, x] of Object.entries(v as Record<string, unknown>)) walk(x, k, depth + 1);
  };
  walk(value, "", 0);
  return { risk, commands };
}

function shellRisk(command: string, ctx: PathContext): Risk {
  const a = analyzeShell(command);
  let r: Risk = { level: "medium", reason: "runs a shell command" };
  for (const seg of a.segments) r = maxRisk(r, assessShellSegment(seg, undefined, ctx).risk);
  if (a.opaque) r = maxRisk(r, { level: "high", reason: `shell command cannot be statically analyzed: ${a.opaqueReason}` });
  return maxRisk({ level: "high", reason: "MCP tool runs a shell command" }, r);
}

const WRITE_VERBS = new Set(["write", "edit", "create", "update", "save", "put", "move", "rename", "copy", "append", "patch", "set", "upload", "mkdir", "replace", "insert", "overwrite"]);
const DELETE_VERBS = new Set(["delete", "remove", "rm", "unlink", "trash", "rmdir", "erase", "wipe", "purge"]);

export interface McpAssessment {
  risk: Risk;
  /** False when nothing (annotations, name) marks the call as known-safe: defaults.unrecognized applies. */
  recognized: boolean;
  identity: McpIdentity;
  /** Normalized paths the tool writes / removes (for `writes_to` rules), inferred from verb + path arguments. */
  writes: string[];
  deletes: string[];
  /** Shell commands found in arguments (evaluated as shell segments too). */
  commands: string[];
}

export function assessMcp(action: ActionSpec, ctx: PathContext = {}): McpAssessment {
  const identity = mcpIdentity(action) ?? { server: "", tool: action.tool ?? "" };
  const args = action.arguments ?? {};
  const inner = "arguments" in args ? args.arguments : undefined;
  const ann = (typeof args.annotations === "object" && args.annotations !== null ? args.annotations : {}) as Record<string, unknown>;
  const label = `${identity.server ? `${identity.server}/` : ""}${identity.tool}`;

  // 1. Annotations (untrusted): only an explicit boolean true counts.
  let risk: Risk;
  let recognized = false;
  if (ann.destructiveHint === true) {
    risk = { level: "high", reason: `MCP tool ${label} declares itself destructive` };
    recognized = true;
  } else if (ann.readOnlyHint === true) {
    risk = ann.openWorldHint === true
      ? { level: "medium", reason: `read-only MCP tool ${label} (open world)` }
      : { level: "low", reason: `read-only MCP tool ${label}` };
    recognized = true;
  } else {
    risk = { level: "medium", reason: `MCP tool ${label} (no read-only annotation)` };
  }

  // 2. Name floor — annotations can never lower it.
  const name = mcpNameFloor(identity.tool);
  if (name) {
    risk = maxRisk(risk, name);
    recognized = true;
  }

  // 3. Argument scanning.
  const scan = scanMcpArguments(inner, ctx);
  if (scan.risk) {
    risk = maxRisk(risk, scan.risk);
    if (RISK_ORDER[scan.risk.level] >= RISK_ORDER.high) recognized = true;
  }

  // 4. File targets for write/delete-looking tools (protected paths, outside the project).
  const words = toolWords(identity.tool);
  const paths =
    inner && typeof inner === "object" && !Array.isArray(inner)
      ? structuredPaths(inner as Record<string, unknown>).map((p) => normalizePath(p, ctx))
      : [];
  const deletes = words.some((w) => DELETE_VERBS.has(w)) ? paths : [];
  const writes = deletes.length === 0 && words.some((w) => WRITE_VERBS.has(w)) ? paths : [];
  const t = classifyTargets(writes, ctx, "writes") ?? null;
  const d = classifyTargets(deletes, ctx, "removes") ?? null;
  for (const x of [t, d]) {
    if (x && RISK_ORDER[x.level] > RISK_ORDER.medium) {
      risk = maxRisk(risk, x);
      recognized = true;
    }
  }
  return { risk, recognized, identity, writes, deletes, commands: scan.commands };
}
