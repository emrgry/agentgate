import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import type { AgentProvider, NormalizedEvent, TurnCommand } from "@agentgate/adapters";
import {
  AGENTGATE_DIR_REF_RE,
  API_ABUSE_RE,
  CODEX_HOOKS_PATH_RE,
  CODEX_HOOKS_REF_RE,
  CURSOR_HOOKS_PATH_RE,
  CURSOR_HOOKS_REF_RE,
  isQuestion,
  SELF_MANAGEMENT_RE,
  sensitivePathRisk,
} from "@agentgate/adapter-claude-code";
import { ActionDraft } from "@agentgate/protocol";

/**
 * OpenAI Codex CLI provider (docs/control-center.md, Phase 2). Research-verified facts
 * (not run here — no `codex` binary on this machine; tests use a fake):
 *   turn:   codex exec --json -C <cwd> --sandbox workspace-write --skip-git-repo-check
 *                      --dangerously-bypass-hook-trust [-m model] -        (prompt on stdin)
 *   resume: codex exec resume --json -C <cwd> <thread_id> -
 *   JSONL:  thread.started{thread_id} · turn.started · item.started|updated|completed{item} ·
 *           turn.completed{usage} (no cost) · turn.failed{error.message} · error{message}
 *   items:  agent_message{text} · reasoning · command_execution{command,aggregated_output,
 *           exit_code,status} · file_change{changes[{path,kind}],status} ·
 *           mcp_tool_call{server,tool,arguments,result?,error?,status} · web_search{query} ·
 *           todo_list{items[{text,completed}]} · collab_tool_call · error
 * Never passes --yolo / --dangerously-bypass-approvals-and-sandbox / danger-full-access /
 * --ephemeral (breaks resume). `--dangerously-bypass-hook-trust` only bypasses hook TRUST
 * (so our non-managed hook isn't silently skipped), not approvals or the sandbox.
 */

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown) => (typeof v === "string" ? v : undefined);
const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);
const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/** Arguments that would remove the sandbox, approvals or resumability — always dropped. */
export const FORBIDDEN_CODEX_ARGS = /^(--yolo|--dangerously-bypass-approvals-and-sandbox|--ephemeral|--full-auto)$|danger-full-access/;

export function filterCodexArgs(args: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (FORBIDDEN_CODEX_ARGS.test(a)) continue;
    // We always set the sandbox ourselves: drop user-supplied --sandbox/-s and its value.
    if (a === "--sandbox" || a === "-s") {
      i++;
      continue;
    }
    if (a.startsWith("--sandbox=")) continue;
    out.push(a);
  }
  return out;
}

function commandText(v: unknown): string {
  if (typeof v === "string") return v;
  if (Array.isArray(v)) return v.map((x) => String(x)).join(" ");
  return "";
}

/** Paths touched by a Codex apply_patch payload ("*** Add|Update|Delete File: <path>", "*** Move to: <path>"). */
export function patchPaths(patch: string): string[] {
  const out = new Set<string>();
  for (const m of patch.matchAll(/^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$/gm)) {
    const p = (m[1] ?? m[2] ?? "").trim();
    if (p) out.add(p);
  }
  return [...out];
}

/** Stateless line mapper (codex JSONL → normalized events). Unknown types → []. */
export function parseCodexLine(line: string): NormalizedEvent[] {
  const s = line.trim();
  if (!s.startsWith("{")) return [];
  let o: unknown;
  try {
    o = JSON.parse(s);
  } catch {
    return [];
  }
  if (!isObj(o)) return [];
  switch (o.type) {
    case "thread.started":
      return str(o.thread_id) ? [{ type: "provider.session", payload: { provider_session_id: o.thread_id } }] : [];
    case "turn.completed": {
      const u = isObj(o.usage) ? o.usage : {};
      return [
        {
          type: "provider.turn_result",
          payload: { ok: true, text: null, error: null, usage: { cost_usd: null, input_tokens: num(u.input_tokens), output_tokens: num(u.output_tokens), duration_ms: null, num_turns: null } },
        },
      ];
    }
    case "turn.failed":
    case "error": {
      const msg = str(isObj(o.error) ? o.error.message : undefined) ?? str(o.message) ?? "codex turn failed";
      return [{ type: "provider.turn_result", payload: { ok: false, text: null, error: clip(msg, 2000), usage: { cost_usd: null, input_tokens: null, output_tokens: null, duration_ms: null, num_turns: null } } }];
    }
    case "item.started":
    case "item.updated":
    case "item.completed":
      return isObj(o.item) ? mapItem(o.type, o.item) : [];
    default:
      return []; // turn.started and future event types
  }
}

function mapItem(phase: string, it: Json): NormalizedEvent[] {
  const id = str(it.id) ?? null;
  const started = phase === "item.started";
  const completed = phase === "item.completed";
  switch (it.type) {
    case "agent_message":
      return completed && str(it.text)?.trim() ? [{ type: "message.assistant", payload: { text: it.text } }] : [];
    case "command_execution": {
      const command = commandText(it.command);
      if (started) {
        return [
          { type: "tool.call", payload: { tool: "Bash", summary: clip(command.replace(/\s+/g, " "), 300), tool_use_id: id } },
          { type: "provider.tool_started", payload: { kind: "shell", item_id: id, text: command } },
        ];
      }
      if (!completed) return [];
      const status = str(it.status) ?? "completed";
      return [
        {
          type: "tool.result",
          payload: {
            tool_use_id: id,
            ok: status === "completed" && (it.exit_code === 0 || it.exit_code === undefined),
            summary: clip(str(it.aggregated_output)?.trim() ?? "", 500),
            status,
            output_tail: (str(it.aggregated_output) ?? "").slice(-8192),
          },
        },
        { type: "provider.tool_completed", payload: { kind: "shell", item_id: id, text: command, status } },
      ];
    }
    case "file_change": {
      const paths = Array.isArray(it.changes) ? it.changes.map((c) => (isObj(c) ? str(c.path) : undefined)).filter((p): p is string => !!p) : [];
      if (started) {
        return [
          { type: "tool.call", payload: { tool: "apply_patch", summary: clip(paths.join(", ") || "file change", 300), tool_use_id: id } },
          { type: "provider.tool_started", payload: { kind: "file", item_id: id, paths } },
        ];
      }
      if (!completed) return [];
      const status = str(it.status) ?? "completed";
      return [
        { type: "tool.result", payload: { tool_use_id: id, ok: status === "completed", summary: clip(paths.join(", "), 500), status } },
        { type: "provider.tool_completed", payload: { kind: "file", item_id: id, paths, status } },
      ];
    }
    case "mcp_tool_call": {
      const tool = `mcp__${str(it.server) ?? "server"}__${str(it.tool) ?? "tool"}`;
      if (started) {
        return [
          { type: "tool.call", payload: { tool, summary: tool, tool_use_id: id } },
          { type: "provider.tool_started", payload: { kind: "mcp", item_id: id, text: tool } },
        ];
      }
      if (!completed) return [];
      const status = str(it.status) ?? (it.error ? "failed" : "completed");
      return [
        { type: "tool.result", payload: { tool_use_id: id, ok: !it.error && status === "completed", summary: clip(str(it.error) ?? "", 500), status } },
        { type: "provider.tool_completed", payload: { kind: "mcp", item_id: id, text: tool, status } },
      ];
    }
    case "web_search":
      // Hosted search: no local tool runs (and hooks don't fire for it); shown, not gated.
      return started ? [{ type: "tool.call", payload: { tool: "web_search", summary: clip(str(it.query) ?? "", 300), tool_use_id: id } }] : [];
    case "todo_list":
      return phase !== "item.started" && Array.isArray(it.items)
        ? [{ type: "todo.updated", payload: { items: it.items.filter(isObj).map((t) => ({ text: clip(str(t.text) ?? "", 300), completed: t.completed === true })).slice(0, 50) } }]
        : [];
    default:
      return []; // reasoning, collab_tool_call, error items, future types
  }
}

export interface CodexProviderOptions {
  binary: string;
  extraArgs?: string[];
  /** Supervisor-owned CODEX_HOME for a managed session (auth/config copy + AgentGate hooks.json). */
  codexHome?: (agentSessionId: string) => string;
  /** Minimum `codex --version`; older or unparseable → turns fail closed. */
  minVersion?: string;
}

export function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map((x) => Number.parseInt(x, 10) || 0);
  const pb = b.split(".").map((x) => Number.parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

export function codexProvider(o: CodexProviderOptions): AgentProvider {
  const extra = filterCodexArgs(o.extraArgs ?? []);
  let versionCache: { at: number; version: string | null } | null = null;
  return {
    id: "codex",
    binary: o.binary,
    displayName: "Codex",
    capabilities: { resume: true, pause: "signal", observe: false, cost: false },
    gated: true,
    buildTurnCommand(req): TurnCommand {
      const common = ["--json", "-C", req.cwd, "--sandbox", "workspace-write", "--skip-git-repo-check", "--dangerously-bypass-hook-trust", ...extra];
      const args = req.providerSessionId ? ["exec", "resume", ...common, req.providerSessionId, "-"] : ["exec", ...common, "-"];
      const home = req.sessionId && o.codexHome ? o.codexHome(req.sessionId) : undefined;
      return {
        cmd: o.binary,
        args,
        stdin: req.instruction,
        ...(home ? { env: { CODEX_HOME: home, AGENTGATE_GATE_RECEIPTS: `${home}/agentgate-receipts.jsonl` }, gateReceipts: `${home}/agentgate-receipts.jsonl` } : {}),
      };
    },
    parseOutputLine: parseCodexLine,
    isQuestion,
    preflight(env) {
      if (!versionCache || Date.now() - versionCache.at > 60_000) {
        let version: string | null = null;
        try {
          const out = execFileSync(o.binary, ["--version"], { env, encoding: "utf8", timeout: 5_000, stdio: ["ignore", "pipe", "ignore"] });
          version = out.match(/(\d+\.\d+(?:\.\d+)?)/)?.[1] ?? null;
        } catch {
          version = null;
        }
        versionCache = { at: Date.now(), version };
      }
      const v = versionCache.version;
      if (!v) return { ok: false, reason: "codex version unknown (`codex --version` failed) — refusing to run ungated" };
      if (o.minVersion && compareVersions(v, o.minVersion) < 0) return { ok: false, reason: `codex ${v} is older than the required ${o.minVersion}` };
      return { ok: true };
    },
  };
}

// ── PreToolUse hook (gating) ─────────────────────────────────────────────────────────
//
// Verified against the Codex hooks docs (developers.openai.com/codex/hooks) and by running
// codex-cli 0.131.0–0.158.0 against a mock model (docs/control-center.md, "Codex hooks"):
//   stdin   {session_id, turn_id, transcript_path, cwd, hook_event_name:"PreToolUse", model,
//            permission_mode, tool_name, tool_input, tool_use_id}
//   tools   shell/unified exec → tool_name "Bash", tool_input {command: string} (the model's
//           `workdir` is NOT included); apply_patch → tool_input {command: <patch text>};
//           MCP → "mcp__<server>__<tool>" with the arguments; other local tools by name.
//   block   exit 2 + non-empty stderr, or {"hookSpecificOutput":{…"permissionDecision":"deny",
//           "permissionDecisionReason":…}}. Exit 2 with EMPTY stderr, any other exit code,
//           a crash or the hook timeout all FAIL OPEN (the tool runs).

export interface CodexHookInput {
  session_id?: string;
  cwd: string;
  hook_event_name: string;
  tool_name: string;
  tool_input: Record<string, unknown>;
  tool_use_id?: string;
  turn_id?: string;
  model?: string;
  permission_mode?: string;
}

export function parseCodexHookInput(raw: unknown): CodexHookInput {
  if (!isObj(raw)) throw new Error("hook input is not an object");
  if (raw.hook_event_name !== "PreToolUse") throw new Error(`unexpected hook event ${String(raw.hook_event_name)}`);
  if (typeof raw.tool_name !== "string" || !raw.tool_name) throw new Error("missing tool_name");
  if (typeof raw.cwd !== "string" || !raw.cwd) throw new Error("missing cwd");
  const ti = isObj(raw.tool_input) ? raw.tool_input : typeof raw.tool_input === "string" ? { input: raw.tool_input } : {};
  return { ...(raw as unknown as CodexHookInput), tool_input: ti };
}

const sha = (v: unknown) => createHash("sha256").update(JSON.stringify(v)).digest("hex");

/**
 * The apply_patch payload. Real Codex sends it as `tool_input.command` (verified 0.131–0.158);
 * `input`/`patch`/`content` are kept for older/synthetic payloads.
 */
export function codexPatchText(ti: Record<string, unknown>): string {
  return str(ti.command) ?? str(ti.input) ?? str(ti.patch) ?? str(ti.content) ?? "";
}

/**
 * Codex PreToolUse → canonical action. Bash → shell.execute; apply_patch (aliases
 * Edit/Write) → filesystem.write with the paths from the patch; mcp__server__tool →
 * mcp.invoke. Anything else is still governed (unknown tool → mcp-like generic action
 * with high risk) — Codex runs in a sandbox, but we never silently wave tools through.
 */
export function normalizeCodexHook(
  input: CodexHookInput,
  ctx: { session_id: string; homeDir: string; projectRoot: string; repo?: string; branch?: string; environment?: string },
): ActionDraft {
  const tool = input.tool_name;
  const ti = input.tool_input;
  const context: Record<string, string> = {};
  if (ctx.repo) context.repo = ctx.repo;
  if (ctx.branch) context.branch = ctx.branch;
  if (input.session_id) context.codex_session_id = input.session_id.slice(0, 256);
  if (input.tool_use_id) context.tool_use_id = input.tool_use_id.slice(0, 256);
  const env = ctx.environment ? { environment: ctx.environment } : {};
  const base = { session_id: ctx.session_id, agent: { type: "codex" }, context };

  if (tool === "Bash" || tool === "shell" || tool === "exec_command") {
    const command = commandText(ti.command ?? ti.cmd);
    return ActionDraft.parse({ ...base, action: { category: "shell", operation: "execute", tool: "Bash", command, cwd: input.cwd }, resource: { ...env } });
  }
  if (tool === "apply_patch" || tool === "Edit" || tool === "Write") {
    const patch = codexPatchText(ti);
    const rel = patchPaths(patch);
    const direct = str(ti.file_path) ?? str(ti.path);
    const paths = (rel.length ? rel : direct ? [direct] : []).map((p) => (isAbsolute(p) ? resolve(p) : resolve(input.cwd, p)));
    const risks = paths.map((p) => sensitivePathRisk(p, { homeDir: ctx.homeDir, projectRoot: ctx.projectRoot })).filter(Boolean);
    const risk = paths.length === 0 ? { level: "high" as const, reason: "patch without recognizable file paths" } : risks[0];
    return ActionDraft.parse({
      ...base,
      action: { category: "filesystem", operation: "write", tool, arguments: { paths: paths.slice(0, 50), path: paths[0] ?? "(unknown)", input_sha256: sha(ti) }, cwd: input.cwd },
      resource: { type: "file", ...(paths[0] ? { name: paths[0] } : {}), ...env },
      ...(risk ? { risk } : {}),
    });
  }
  const m = tool.match(/^mcp__([^_]+(?:_[^_]+)*)__(.+)$/);
  if (m) {
    return ActionDraft.parse({
      ...base,
      action: { category: "mcp", operation: "invoke", tool, arguments: { server: m[1], tool: m[2], arguments: ti }, cwd: input.cwd },
      resource: { type: "mcp_server", name: m[1], ...env },
    });
  }
  return ActionDraft.parse({
    ...base,
    action: { category: "tool", operation: "invoke", tool: tool.slice(0, 128), arguments: { input_sha256: sha(ti) }, cwd: input.cwd },
    resource: { ...env },
    risk: { level: "high", reason: `unrecognized Codex tool ${tool}` },
  });
}

/** Summary text for gating receipts (supervisor tripwire matching). */
export function codexReceiptFacts(input: CodexHookInput): { kind: "shell" | "file" | "mcp" | "other"; text: string; paths: string[] } {
  const t = input.tool_name;
  if (t === "Bash" || t === "shell" || t === "exec_command") return { kind: "shell", text: commandText(input.tool_input.command ?? input.tool_input.cmd), paths: [] };
  if (t === "apply_patch" || t === "Edit" || t === "Write") {
    const patch = codexPatchText(input.tool_input);
    const direct = str(input.tool_input.file_path) ?? str(input.tool_input.path);
    return { kind: "file", text: "", paths: patchPaths(patch).concat(direct ? [direct] : []) };
  }
  if (t.startsWith("mcp__")) return { kind: "mcp", text: t, paths: [] };
  return { kind: "other", text: t, paths: [] };
}

// ── Interactive Codex (`agentgate install codex`): tool classes + self-protection ─────

const SHELL_TOOLS = new Set(["Bash", "shell", "exec_command"]);
const PATCH_TOOLS = new Set(["apply_patch", "Edit", "Write"]);

/**
 * Local Codex tools that run nothing and write nothing: planning, goals, questions to the
 * user, tool discovery and subagent orchestration (subagents' own tool calls are hooked
 * separately). The interactive hook lets them through without a round trip; everything
 * else — including tools Codex adds later — is governed (unknown → high risk → ask).
 */
export const CODEX_BENIGN_TOOLS: ReadonlySet<string> = new Set([
  "update_plan",
  "request_user_input",
  "get_goal",
  "create_goal",
  "update_goal",
  "tool_search",
  "multi_agent_v1",
  "spawn_agent",
  "send_input",
  "wait",
  "wait_agent",
  "close_agent",
  "resume_agent",
  "list_agents",
]);

export interface CodexGuardOptions {
  homeDir: string;
  /** $AGENTGATE_HOME (config, tokens, nonces, server data). */
  agentgateHome: string;
  /** AgentGate code/install/secrets dirs (see install-layout.ts). */
  protectedDirs: string[];
  /** The CODEX_HOME in effect (default ~/.codex). */
  codexHome?: string;
}

export interface CodexGuardVerdict {
  decision: "ask" | "deny";
  reason: string;
}

/**
 * `codex` started with a different hook/config home or with hooks bypassed/disabled — that
 * nested Codex would run without the installed AgentGate hook.
 */
export const CODEX_UNGATED_LAUNCH_RE =
  /(?:^|[^\w./-])(?:CODEX_HOME=|codex\b[^\n;&|]*?(?:--dangerously-bypass-hook-trust|--disable[= ]+(?:codex_)?hooks|(?:-c|--config)[= ]+['"]?(?:features\.(?:codex_)?hooks|hooks[.=]|allow_managed_hooks_only)))/;
/** An interactive interpreter with no script/command: its later input (write_stdin) is never hooked. */
export const INTERACTIVE_SHELL_RE = /^\s*(?:bash|sh|zsh|dash|ksh|fish|python3?|node|irb|ruby|perl|php|lua|R|psql|mysql|sqlite3|redis-cli|mongosh)(?:\s+-i)?\s*$/;

function within(root: string, p: string): boolean {
  const rel = relative(resolve(root), resolve(p));
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

function absPath(p: string, cwd: string, home: string): string {
  if (p === "~") return home;
  if (p.startsWith("~/")) return resolve(home, p.slice(2));
  return isAbsolute(p) ? resolve(p) : resolve(cwd, p);
}

/** Paths an interactive tool call would touch (apply_patch targets, view_image path). */
export function codexToolPaths(input: CodexHookInput, home: string): string[] {
  const ti = input.tool_input;
  if (PATCH_TOOLS.has(input.tool_name)) {
    const rel = patchPaths(codexPatchText(ti));
    const direct = str(ti.file_path) ?? str(ti.path);
    return (rel.length ? rel : direct ? [direct] : []).map((p) => absPath(p, input.cwd, home));
  }
  const p = str(ti.path) ?? str(ti.file_path);
  return p ? [absPath(p, input.cwd, home)] : [];
}

function sensitiveRead(p: string, o: CodexGuardOptions): string | null {
  const base = basename(p);
  if (within(o.agentgateHome, p)) return "reads AgentGate's own config/tokens";
  if (within(join(o.homeDir, ".ssh"), p)) return "reads inside ~/.ssh";
  if (/^\.env(\..*)?$/.test(base) || base.endsWith(".env")) return `reads environment/secrets file ${base}`;
  return null;
}

/**
 * "benign": let through without asking anyone (interactive installs only).
 * "gated":  normalize → policy → maybe the phone.
 */
export function codexToolClass(input: CodexHookInput, o: CodexGuardOptions): "benign" | "gated" {
  if (CODEX_BENIGN_TOOLS.has(input.tool_name)) return "benign";
  if (input.tool_name === "view_image") {
    const paths = codexToolPaths(input, o.homeDir);
    return paths.length === 1 && !sensitiveRead(paths[0]!, o) ? "benign" : "gated";
  }
  return "gated";
}

/**
 * Self-protection floor for Codex hooks (managed and interactive). Mirrors the Claude
 * adapter guard: the agent must not reconfigure, bypass or impersonate its own gate —
 * `agentgate install/uninstall/…`, AgentGate's credential/approval endpoints, AgentGate's
 * files, and the Codex/Claude/Cursor hook configuration are denied; anything else touching
 * AgentGate paths, nested ungated Codex launches and bare interactive interpreters are
 * asked. Pure; can only make a decision stricter.
 */
export function codexGuard(input: CodexHookInput, o: CodexGuardOptions): CodexGuardVerdict | null {
  const tool = input.tool_name;
  const codexHome = o.codexHome ?? join(o.homeDir, ".codex");
  if (SHELL_TOOLS.has(tool)) {
    const cmd = commandText(input.tool_input.command ?? input.tool_input.cmd);
    const m = SELF_MANAGEMENT_RE.exec(cmd);
    if (m) return { decision: "deny", reason: `agents may not run \`agentgate ${m[1]}\` (it would reconfigure their own gate)` };
    const api = API_ABUSE_RE.exec(cmd);
    if (api) return { decision: "deny", reason: `agents may not call AgentGate credential/approval endpoints directly (${api[0]})` };
    if (CODEX_HOOKS_REF_RE.test(cmd) || (cmd.includes(codexHome) && /hooks['"]?\.json|config['"]?\.toml/.test(cmd))) {
      return { decision: "deny", reason: "agents may not touch Codex hook settings (~/.codex/hooks.json, config.toml)" };
    }
    if (CURSOR_HOOKS_REF_RE.test(cmd)) return { decision: "deny", reason: "agents may not touch Cursor hook settings (.cursor/hooks.json)" };
    if (CODEX_UNGATED_LAUNCH_RE.test(cmd)) return { decision: "ask", reason: "starts Codex with a different hook configuration (that Codex would run without AgentGate)" };
    const refs = [o.agentgateHome, "/.agentgate", "~/.agentgate", ".claude/settings", ...o.protectedDirs];
    const hit = refs.find((r) => r && cmd.includes(r)) ?? (AGENTGATE_DIR_REF_RE.test(cmd) ? ".agentgate" : undefined);
    if (hit) return { decision: "ask", reason: `command touches AgentGate-protected path (${hit})` };
    if (INTERACTIVE_SHELL_RE.test(cmd)) {
      return { decision: "ask", reason: "starts an interactive session: what Codex types into it later (write_stdin) is not checked by AgentGate" };
    }
    return null;
  }
  if (PATCH_TOOLS.has(tool)) {
    for (const p of codexToolPaths(input, o.homeDir)) {
      if (within(o.agentgateHome, p)) return { decision: "deny", reason: "agents may not modify AgentGate's config/tokens" };
      for (const d of o.protectedDirs) if (within(d, p)) return { decision: "deny", reason: `agents may not modify AgentGate itself (${d})` };
      if (CODEX_HOOKS_PATH_RE.test(p) || (within(codexHome, p) && /^(hooks\.json|config\.toml|requirements\.toml)$/.test(basename(p)))) {
        return { decision: "deny", reason: "agents may not modify Codex hook settings" };
      }
      if (/(^|\/)\.claude\/settings(\.local)?\.json$/.test(p)) return { decision: "deny", reason: "agents may not modify Claude Code hook settings" };
      if (CURSOR_HOOKS_PATH_RE.test(p)) return { decision: "deny", reason: "agents may not modify Cursor hook settings" };
    }
    return null;
  }
  if (tool === "view_image") {
    const [p] = codexToolPaths(input, o.homeDir);
    const reason = p ? sensitiveRead(p, o) : null;
    return reason ? { decision: "ask", reason } : null;
  }
  return null;
}
