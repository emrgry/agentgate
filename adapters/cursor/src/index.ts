import { createHash } from "node:crypto";
import { isAbsolute, join, resolve } from "node:path";
import type { AdapterContext } from "@agentgate/adapters";
import { ClaudeCodeAdapter, PreToolUseInput, sensitivePathRisk, type GuardVerdict } from "@agentgate/adapter-claude-code";
import { ActionDraft, type Risk } from "@agentgate/protocol";
import { z } from "zod";

/**
 * Cursor adapter: Cursor agent-hook input → canonical ActionDraft, and AgentGate decisions →
 * Cursor hook output. Pure: no network, no filesystem, no env access.
 *
 * Contract (https://cursor.com/docs/hooks — see docs/cursor.md for what is verified):
 *   stdin  common: {conversation_id, generation_id, hook_event_name, cursor_version,
 *                   workspace_roots[], user_email, transcript_path, model, …}
 *          beforeShellExecution {command, cwd, sandbox}
 *          beforeMCPExecution   {tool_name, tool_input (JSON string), mcp_server_name,
 *                                command (stdio) | url + mcp_server_url (HTTP/SSE)}
 *          beforeReadFile       {file_path, content, attachments[]}
 *          preToolUse           {tool_name, tool_input{…}, tool_use_id, cwd}
 *   stdout {"permission":"allow"|"deny", "user_message"?, "agent_message"?}
 *          (beforeReadFile only documents permission + user_message)
 *
 * AgentGate never answers Cursor's own "ask": the human decision happens on the phone
 * while the hook blocks, and the hook then answers allow or deny.
 *
 * Shell / Read / file-path risk / self-protection logic is shared with the Claude Code
 * adapter (the Cursor event is translated into the equivalent Claude tool call).
 */

export const AGENT_TYPE = "cursor";

/** Identifies AgentGate's entries in hooks.json (ignored by the hook shim). */
export const INSTALL_MARKER = "--agentgate-install=cursor/v1";
/** Selects the Cursor handler in bin/agentgate-hook.sh. */
export const PROVIDER_ARG = "--agentgate-provider=cursor";

/** Events whose response is a permission decision (all installed with failClosed). */
export const GATE_EVENTS = ["beforeShellExecution", "beforeMCPExecution", "beforeReadFile", "preToolUse"] as const;
export type GateEvent = (typeof GATE_EVENTS)[number];
/** Fire-and-forget events we listen to (session cleanup only). */
export const LIFECYCLE_EVENTS = ["sessionEnd"] as const;

/**
 * preToolUse matcher (regex against Cursor's tool type): file-mutating tools only. Shell and
 * MCP have dedicated before* hooks with richer payloads; Read has beforeReadFile. The
 * handler re-classifies whatever matched, so over-matching (e.g. "TodoWrite") is harmless.
 */
export const FILE_TOOL_MATCHER = "Write|Edit|Delete|Patch|Replace|Notebook|Create|Move|Rename";
const FILE_TOOL_RE = new RegExp(FILE_TOOL_MATCHER);
/** Tools that match the file-tool regex but never touch files. */
const NOT_A_FILE_TOOL_RE = /todo/i;
const DELETE_TOOL_RE = /delete|remove/i;

/** Cursor hook config files (user, project, enterprise) — the guard denies agent edits. */
export { CURSOR_HOOKS_PATH_RE, CURSOR_HOOKS_REF_RE } from "@agentgate/adapter-claude-code";

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === "string" && v.length > 0 ? v : undefined);

/** Cursor-native (camelCase) event name for a Cursor or Claude-style hook_event_name. */
export function canonicalEvent(name: unknown): string {
  if (typeof name !== "string" || !name) return "";
  const claude: Record<string, string> = { UserPromptSubmit: "beforeSubmitPrompt" };
  return claude[name] ?? name.charAt(0).toLowerCase() + name.slice(1);
}

export function isGateEvent(e: string): e is GateEvent {
  return (GATE_EVENTS as readonly string[]).includes(e);
}

/** True for payloads sent by Cursor (every Cursor hook carries `cursor_version`). */
export function isCursorPayload(json: unknown): boolean {
  return isObj(json) && typeof json.cursor_version === "string";
}

// ── input schemas ────────────────────────────────────────────────────────────

const Common = z
  .object({
    hook_event_name: z.string(),
    conversation_id: z.string().optional(),
    generation_id: z.string().optional(),
    session_id: z.string().optional(),
    cursor_version: z.string().optional(),
    workspace_roots: z.array(z.unknown()).optional(),
  })
  .passthrough();

export const ShellInput = Common.extend({ command: z.string(), cwd: z.string().optional(), sandbox: z.boolean().optional() });
export const McpInput = Common.extend({
  tool_name: z.string().min(1).max(256),
  tool_input: z.union([z.string(), z.record(z.string(), z.unknown())]).optional(),
  mcp_server_name: z.string().optional(),
  command: z.string().optional(),
  url: z.string().optional(),
  mcp_server_url: z.string().optional(),
});
export const ReadFileInput = Common.extend({ file_path: z.string().min(1) });
export const ToolInput = Common.extend({
  tool_name: z.string().min(1).max(256),
  tool_input: z.record(z.string(), z.unknown()).default({}),
  tool_use_id: z.string().optional(),
  cwd: z.string().optional(),
});

export type CursorGateInput =
  | { event: "beforeShellExecution"; input: z.infer<typeof ShellInput> }
  | { event: "beforeMCPExecution"; input: z.infer<typeof McpInput> }
  | { event: "beforeReadFile"; input: z.infer<typeof ReadFileInput> }
  | { event: "preToolUse"; input: z.infer<typeof ToolInput> };

/** Parses a gating event (throws on anything malformed → the caller denies). */
export function parseGateInput(json: unknown): CursorGateInput {
  const event = canonicalEvent(isObj(json) ? json.hook_event_name : undefined);
  const parse = <T extends z.ZodTypeAny>(schema: T): z.infer<T> => {
    const r = schema.safeParse(json);
    if (!r.success) throw new Error(`invalid ${event} input (${r.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ")})`);
    return r.data;
  };
  switch (event) {
    case "beforeShellExecution":
      return { event, input: parse(ShellInput) };
    case "beforeMCPExecution":
      return { event, input: parse(McpInput) };
    case "beforeReadFile":
      return { event, input: parse(ReadFileInput) };
    case "preToolUse":
      return { event, input: parse(ToolInput) };
    default:
      throw new Error(`not a gating Cursor event: '${event}'`);
  }
}

/** The Cursor conversation (stable across turns) — the key for the AgentGate session. */
export function conversationKey(json: unknown): string | null {
  if (!isObj(json)) return null;
  const id = str(json.conversation_id) ?? str(json.session_id);
  return id ? `cursor:${id.slice(0, 200)}` : null;
}

/** Working directory of the call: payload cwd, else the first workspace root. */
export function cwdOf(g: CursorGateInput): string | undefined {
  const i = g.input as Json;
  if (g.event === "preToolUse" && isObj(i.tool_input)) {
    const wd = str((i.tool_input as Json).working_directory);
    if (wd) return wd;
  }
  return str(i.cwd) ?? (Array.isArray(i.workspace_roots) ? i.workspace_roots.map(str).find(Boolean) : undefined);
}

/** MCP arguments: Cursor sends them as a JSON string. Unparseable → kept raw (still hashed). */
export function mcpArguments(v: unknown): Json {
  if (isObj(v)) return v;
  if (typeof v !== "string" || !v.trim()) return {};
  try {
    const p = JSON.parse(v) as unknown;
    return isObj(p) ? p : { value: p };
  } catch {
    return { raw: v };
  }
}

// ── output ───────────────────────────────────────────────────────────────────

export interface CursorPermissionOutput {
  permission: "allow" | "deny";
  user_message?: string;
  agent_message?: string;
}

/** Only fields documented for the event (a response that doesn't match the schema blocks). */
export function renderAllow(): CursorPermissionOutput {
  return { permission: "allow" };
}

export function renderDeny(event: string, userMessage: string, agentMessage: string): CursorPermissionOutput {
  const user = userMessage.slice(0, 2000);
  if (event === "beforeReadFile") return { permission: "deny", user_message: user };
  return { permission: "deny", user_message: user, agent_message: agentMessage.slice(0, 4000) };
}

// ── adapter ──────────────────────────────────────────────────────────────────

export interface CursorAdapterOptions {
  homeDir: string;
  projectRoot?: string;
  agentgateHome?: string;
  protectedDirs?: string[];
}

export interface NormalizeOptions {
  /**
   * "native": installed in hooks.json — Shell/MCP/Read have dedicated hooks, so preToolUse
   *   only governs file-mutating tools.
   * "claude-import": Cursor ran AgentGate's Claude Code hook (Third-Party Imports) and no
   *   native AgentGate Cursor hook exists — preToolUse must govern everything itself.
   */
  mode: "native" | "claude-import";
}

export class CursorAdapter {
  readonly type = AGENT_TYPE;
  private readonly claude: ClaudeCodeAdapter;

  constructor(private readonly opts: CursorAdapterOptions) {
    this.claude = new ClaudeCodeAdapter(opts);
  }

  /**
   * Canonical draft, or null when AgentGate does not govern the call (answer allow without
   * touching the network).
   */
  normalize(g: CursorGateInput, ctx: AdapterContext, o: NormalizeOptions = { mode: "native" }): ActionDraft | null {
    const base = {
      session_id: ctx.session_id,
      agent: { type: AGENT_TYPE, ...(str(g.input.cursor_version) ? { version: g.input.cursor_version!.slice(0, 64) } : {}) },
      context: contextOf(g, ctx),
    };
    const env = ctx.environment ? { environment: ctx.environment } : {};

    switch (g.event) {
      case "beforeShellExecution":
        return this.shell(g.input.command, "Shell", base, ctx);
      case "beforeReadFile":
        return this.read(g.input.file_path, base, ctx);
      case "beforeMCPExecution":
        return this.mcp(g.input.mcp_server_name, g.input.tool_name, g.input.tool_input, base, ctx, g.input.url ?? g.input.mcp_server_url);
      case "preToolUse": {
        const tool = g.input.tool_name;
        const ti = g.input.tool_input;
        if (o.mode === "claude-import") {
          if (tool === "Shell" || tool === "Bash") return this.shell(typeof ti.command === "string" ? ti.command : "", tool, base, ctx);
          if (tool === "Read") return this.read(firstString(ti.file_path, ti.path, ti.target_file) ?? "", base, ctx);
          const mcp = parseCursorMcpTool(tool);
          if (mcp) return this.mcp(mcp.server, mcp.tool, ti, base, ctx);
        }
        if (!isFileTool(tool)) return null;
        const paths = filePaths(ti).map((p) => this.absolute(p, ctx.cwd));
        const del = DELETE_TOOL_RE.test(tool);
        let risk: Risk | undefined = paths.length ? undefined : { level: "high", reason: `${tool} without a recognizable file path` };
        for (const p of paths) {
          const r = sensitivePathRisk(p, this.pathOpts(ctx.cwd));
          if (r && !risk) risk = r;
        }
        const args: Json = { path: paths[0] ?? "(unknown)", input_sha256: sha256Json(ti) };
        if (paths.length > 1) args.paths = paths;
        const content = firstString(ti.contents, ti.content, ti.new_string, ti.code_edit);
        if (content !== undefined) args.bytes = Buffer.byteLength(content, "utf8");
        return ActionDraft.parse({
          ...base,
          action: { category: "filesystem", operation: del ? "delete" : "write", tool: tool.slice(0, 128), arguments: args, cwd: ctx.cwd },
          resource: { type: "file", ...(paths[0] ? { name: paths[0].slice(0, 512) } : {}), ...env },
          ...(risk ? { risk } : {}),
        });
      }
    }
  }

  /**
   * Self-protection floor (never loosens policy): the same rules as the Claude Code guard
   * (agentgate self-management, credential/approval endpoints, AgentGate files, hook
   * settings — including Cursor's hooks.json), applied to the Cursor tool.
   */
  guard(g: CursorGateInput, cwd: string, o: NormalizeOptions = { mode: "native" }): GuardVerdict | null {
    const viaClaude = (tool_name: string, tool_input: Json) =>
      this.claude.guard(PreToolUseInput.parse({ hook_event_name: "PreToolUse", tool_name, tool_input, cwd }), cwd);
    switch (g.event) {
      case "beforeShellExecution":
        return viaClaude("Bash", { command: g.input.command });
      case "beforeReadFile":
        return viaClaude("Read", { file_path: g.input.file_path });
      case "beforeMCPExecution":
        return this.mcpGuard(g.input.tool_input);
      case "preToolUse": {
        const tool = g.input.tool_name;
        const ti = g.input.tool_input;
        if (o.mode === "claude-import") {
          if (tool === "Shell" || tool === "Bash") return viaClaude("Bash", { command: typeof ti.command === "string" ? ti.command : "" });
          if (tool === "Read") return viaClaude("Read", { file_path: firstString(ti.file_path, ti.path, ti.target_file) ?? "" });
          if (parseCursorMcpTool(tool)) return this.mcpGuard(ti);
        }
        if (!isFileTool(tool)) return null;
        let worst: GuardVerdict | null = null;
        for (const p of filePaths(ti)) {
          const v = viaClaude("Write", { file_path: p });
          if (v && (!worst || (v.decision === "deny" && worst.decision !== "deny"))) worst = v;
        }
        return worst;
      }
    }
  }

  private mcpGuard(toolInput: unknown): GuardVerdict | null {
    // MCP file/shell tools pointed at the gate's own config: ask (the policy engine also
    // classifies structured writes to protected paths).
    const text = typeof toolInput === "string" ? toolInput : JSON.stringify(toolInput ?? {});
    const refs = [".cursor/hooks.json", "/.agentgate", "~/.agentgate", this.opts.agentgateHome ?? join(this.opts.homeDir, ".agentgate"), ...(this.opts.protectedDirs ?? [])];
    const hit = refs.find((r) => r && text.includes(r));
    return hit ? { decision: "ask", reason: `MCP call references an AgentGate-protected path (${hit})` } : null;
  }

  private shell(command: string, tool: string, base: Json, ctx: AdapterContext): ActionDraft {
    return ActionDraft.parse({
      ...base,
      action: { category: "shell", operation: "execute", tool, command, cwd: ctx.cwd },
      resource: { ...(ctx.environment ? { environment: ctx.environment } : {}) },
    });
  }

  private read(filePath: string, base: Json, ctx: AdapterContext): ActionDraft | null {
    if (!filePath) return null;
    const path = this.absolute(filePath, ctx.cwd);
    const reason = this.claude.sensitiveReadReason(path);
    if (!reason) return null;
    return ActionDraft.parse({
      ...base,
      action: { category: "filesystem", operation: "read", tool: "Read", arguments: { path }, cwd: ctx.cwd },
      resource: { type: "file", name: path.slice(0, 512), ...(ctx.environment ? { environment: ctx.environment } : {}) },
      risk: { level: "high", reason },
    });
  }

  private mcp(server: string | undefined, tool: string, rawArgs: unknown, base: Json, ctx: AdapterContext, url?: string): ActionDraft {
    const srv = server && server.trim() ? server.slice(0, 128) : "(unknown)";
    const risk: Risk | undefined = srv === "(unknown)" ? { level: "high", reason: "MCP call without a recognizable server name" } : undefined;
    return ActionDraft.parse({
      ...base,
      context: { ...(base.context as Json), ...(url ? { mcp_url: url.slice(0, 1024) } : {}) },
      action: {
        category: "mcp",
        operation: "invoke",
        tool: `${srv}/${tool}`.slice(0, 128),
        arguments: { server: srv, tool, arguments: mcpArguments(rawArgs) },
        cwd: ctx.cwd,
      },
      resource: { type: "mcp_server", name: srv, ...(ctx.environment ? { environment: ctx.environment } : {}) },
      ...(risk ? { risk } : {}),
    });
  }

  private pathOpts(cwd: string) {
    return {
      homeDir: this.opts.homeDir,
      projectRoot: this.opts.projectRoot ?? cwd,
      agentgateHome: this.opts.agentgateHome ?? join(this.opts.homeDir, ".agentgate"),
      protectedDirs: this.opts.protectedDirs ?? [],
    };
  }

  private absolute(p: string, cwd: string): string {
    if (p === "~") return this.opts.homeDir;
    if (p.startsWith("~/")) return resolve(this.opts.homeDir, p.slice(2));
    return isAbsolute(p) ? resolve(p) : resolve(cwd, p);
  }
}

// ── helpers (exported for tests / the hook) ──────────────────────────────────

export function isFileTool(tool: string): boolean {
  return FILE_TOOL_RE.test(tool) && !NOT_A_FILE_TOOL_RE.test(tool) && !tool.startsWith("MCP:");
}

/** preToolUse MCP tool names use `MCP:<tool>` (server not included). */
export function parseCursorMcpTool(tool: string): { server: string | undefined; tool: string } | null {
  if (tool.startsWith("MCP:")) return { server: undefined, tool: tool.slice(4) || "(unknown)" };
  if (tool.startsWith("mcp__")) {
    const rest = tool.slice(5);
    const i = rest.indexOf("__");
    if (i > 0) return { server: rest.slice(0, i), tool: rest.slice(i + 2) };
  }
  return null;
}

/**
 * Every file path a file tool's input names. Cursor's tool_input shapes for Write/Delete are
 * not documented (docs/cursor.md), so the common spellings are all accepted.
 */
export function filePaths(ti: Json): string[] {
  const out: string[] = [];
  for (const k of ["file_path", "path", "target_file", "filePath", "targetFile", "notebook_path", "target_notebook", "relative_workspace_path", "old_path", "new_path"]) {
    const v = ti[k];
    if (typeof v === "string" && v.trim()) out.push(v);
  }
  for (const k of ["paths", "files", "file_paths"]) {
    const v = ti[k];
    if (Array.isArray(v)) for (const x of v) if (typeof x === "string" && x.trim()) out.push(x);
  }
  return [...new Set(out)];
}

function firstString(...v: unknown[]): string | undefined {
  for (const x of v) if (typeof x === "string") return x;
  return undefined;
}

function contextOf(g: CursorGateInput, ctx: AdapterContext): Record<string, string> {
  const c: Record<string, string> = {};
  const i = g.input as Json;
  if (ctx.repo) c.repo = ctx.repo;
  if (ctx.branch) c.branch = ctx.branch;
  const conv = str(i.conversation_id) ?? str(i.session_id);
  if (conv) c.cursor_conversation_id = conv.slice(0, 256);
  if (str(i.generation_id)) c.cursor_generation_id = (i.generation_id as string).slice(0, 256);
  if (str(i.tool_use_id)) c.tool_use_id = (i.tool_use_id as string).slice(0, 256);
  c.cursor_hook = g.event;
  if (typeof i.sandbox === "boolean") c.cursor_sandbox = String(i.sandbox);
  return c;
}

/** SHA-256 of a key-sorted JSON rendering (binds the exact edit without storing content). */
export function sha256Json(v: unknown): string {
  return createHash("sha256").update(stableStringify(v), "utf8").digest("hex");
}

function stableStringify(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  const o = v as Json;
  return `{${Object.keys(o)
    .filter((k) => o[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${stableStringify(o[k])}`)
    .join(",")}}`;
}
