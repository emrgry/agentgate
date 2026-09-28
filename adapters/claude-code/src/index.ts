import { createHash } from "node:crypto";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { AdapterContext, AdapterDecision, AgentAdapter } from "@agentgate/adapters";
import { ActionDraft, type Risk } from "@agentgate/protocol";
import { z } from "zod";

/**
 * Claude Code adapter: PreToolUse hook input → canonical ActionDraft, and AgentGate
 * decisions → PreToolUse hook output. Pure: no network, no filesystem, no env access.
 *
 * Hook contract (Claude Code docs):
 *   stdin  {session_id, cwd, permission_mode, hook_event_name, tool_name, tool_input,
 *           tool_use_id, transcript_path, agent_id?, agent_type?}   (unknown fields ignored)
 *   stdout {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":
 *           "allow"|"deny"|"ask"|"defer","permissionDecisionReason":"…","updatedInput":{…}}}
 */

export const AGENT_TYPE = "claude-code";

/**
 * Tools the hook is registered for (settings matcher). `Read` is included only so that
 * reads of sensitive files can be gated; every other Read gets no output (normal flow).
 */
export const HOOK_MATCHER = "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|mcp__.*";

export const PreToolUseInput = z
  .object({
    hook_event_name: z.literal("PreToolUse"),
    tool_name: z.string().min(1).max(256),
    tool_input: z.record(z.string(), z.unknown()),
    cwd: z.string().min(1),
    session_id: z.string().optional(),
    tool_use_id: z.string().optional(),
    transcript_path: z.string().optional(),
    permission_mode: z.string().optional(),
    agent_id: z.string().optional(),
    agent_type: z.string().optional(),
  })
  .passthrough();
export type PreToolUseInput = z.infer<typeof PreToolUseInput>;

export interface PreToolUseOutput {
  hookSpecificOutput: {
    hookEventName: "PreToolUse";
    permissionDecision: "allow" | "deny" | "ask" | "defer";
    permissionDecisionReason: string;
    updatedInput?: Record<string, unknown>;
  };
}

export interface ClaudeCodeAdapterOptions {
  /** User home, for ~ expansion and ~/.ssh etc. */
  homeDir: string;
  /** Project root (git toplevel or launch dir). Writes outside it are high risk. Defaults to ctx.cwd. */
  projectRoot?: string;
  /** $AGENTGATE_HOME (config, tokens, nonces). Default ~/.agentgate. */
  agentgateHome?: string;
  /**
   * AgentGate's own code/data the agent must never modify: the code the hook runs
   * (daemon, adapter, packages, node_modules), the API data dir and the API secrets dir.
   */
  protectedDirs?: string[];
}

/** Adapter guard verdict: a floor applied on top of policy (never loosens it). */
export interface GuardVerdict {
  decision: "ask" | "deny";
  reason: string;
}

const WRITE_TOOLS = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);

export class ClaudeCodeAdapter implements AgentAdapter<PreToolUseInput, PreToolUseOutput> {
  readonly type = AGENT_TYPE;

  constructor(private readonly opts: ClaudeCodeAdapterOptions) {}

  normalize(event: PreToolUseInput, ctx: AdapterContext): ActionDraft | null {
    const tool = event.tool_name;
    const input = event.tool_input;
    const cwd = ctx.cwd;

    const base = {
      session_id: ctx.session_id,
      agent: ctx.agent_version ? { type: AGENT_TYPE, version: ctx.agent_version } : { type: AGENT_TYPE },
      context: contextOf(event, ctx),
    };
    const env = ctx.environment ? { environment: ctx.environment } : {};

    if (tool === "Bash") {
      const command = typeof input.command === "string" ? input.command : "";
      return ActionDraft.parse({
        ...base,
        action: { category: "shell", operation: "execute", tool: "Bash", command, cwd },
        resource: { ...env },
      });
    }

    if (WRITE_TOOLS.has(tool)) {
      const raw = firstString(input.file_path, input.path, input.notebook_path);
      const path = raw ? this.absolute(raw, cwd) : null;
      const risk: Risk | undefined = path
        ? sensitivePathRisk(path, this.pathOpts(cwd))
        : { level: "high", reason: `${tool} without a recognizable file path` };
      const args: Record<string, unknown> = { path: path ?? "(unknown)", input_sha256: sha256Json(input) };
      if (typeof input.content === "string") args.bytes = Buffer.byteLength(input.content, "utf8");
      if (Array.isArray(input.edits)) args.edits = input.edits.length;
      return ActionDraft.parse({
        ...base,
        action: { category: "filesystem", operation: "write", tool, arguments: args, cwd },
        resource: { type: "file", ...(path ? { name: path } : {}), ...env },
        ...(risk ? { risk } : {}),
      });
    }

    if (tool === "Read") {
      // Only sensitive reads are governed; everything else is not AgentGate's business.
      const raw = firstString(input.file_path, input.path);
      if (!raw) return null;
      const path = this.absolute(raw, cwd);
      const reason = this.sensitiveReadReason(path);
      if (!reason) return null;
      return ActionDraft.parse({
        ...base,
        action: { category: "filesystem", operation: "read", tool, arguments: { path }, cwd },
        resource: { type: "file", name: path, ...env },
        risk: { level: "high", reason },
      });
    }

    const mcp = parseMcpToolName(tool);
    if (mcp) {
      return ActionDraft.parse({
        ...base,
        action: {
          category: "mcp",
          operation: "invoke",
          tool,
          arguments: { server: mcp.server, tool: mcp.tool, arguments: input },
          cwd,
        },
        resource: { type: "mcp_server", name: mcp.server, ...env },
      });
    }
    return null;
  }

  /**
   * Render a decision as hook output. `rewrittenCommand` (Bash only) becomes
   * `updatedInput.command`, preserving every other tool_input field.
   */
  render(decision: AdapterDecision, event?: PreToolUseInput): PreToolUseOutput {
    if (decision.kind === "deny") {
      return { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: decision.reason } };
    }
    const out: PreToolUseOutput = {
      hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", permissionDecisionReason: decision.reason },
    };
    if (decision.rewrittenCommand !== undefined) {
      if (!event || event.tool_name !== "Bash") throw new Error("rewrittenCommand requires the original Bash event");
      out.hookSpecificOutput.updatedInput = { ...event.tool_input, command: decision.rewrittenCommand };
    }
    return out;
  }

  private pathOpts(cwd: string) {
    return {
      homeDir: this.opts.homeDir,
      projectRoot: this.opts.projectRoot ?? cwd,
      agentgateHome: this.agentgateHome(),
      protectedDirs: this.opts.protectedDirs ?? [],
    };
  }

  private agentgateHome(): string {
    return this.opts.agentgateHome ?? join(this.opts.homeDir, ".agentgate");
  }

  /** Reads that could leak credentials or AgentGate's own secrets. */
  sensitiveReadReason(absPath: string): string | null {
    const p = resolve(absPath);
    const base = basename(p);
    if (isWithin(this.agentgateHome(), p)) return "reads AgentGate's own config/tokens";
    for (const d of this.opts.protectedDirs ?? []) {
      if (isWithin(d, p) && (/key|secret|token/i.test(base) || /\.data|agentgate-api/.test(d))) return `reads AgentGate secret material (${base})`;
    }
    if (/(^|\/)\.data\//.test(p) && (/key/i.test(base) || base === "auth-secret")) return `reads server secret material (${base})`;
    if (isWithin(join(this.opts.homeDir, ".ssh"), p)) return "reads inside ~/.ssh";
    if (/^\.env(\..*)?$/.test(base) || base.endsWith(".env")) return `reads environment/secrets file ${base}`;
    return null;
  }

  /**
   * Self-protection floor. The agent must not reconfigure, bypass or impersonate its own
   * gate: AgentGate login/logout/install/uninstall/pair/devices/setup/update/restart, direct calls to credential or
   * approval endpoints, and edits to AgentGate files or Claude hook settings are denied;
   * anything else touching AgentGate paths must be asked. Pure; never loosens policy.
   */
  guard(event: PreToolUseInput, cwd: string): GuardVerdict | null {
    const tool = event.tool_name;
    const input = event.tool_input;
    if (tool === "Bash") {
      const cmd = typeof input.command === "string" ? input.command : "";
      const m = SELF_MANAGEMENT_RE.exec(cmd);
      if (m) return { decision: "deny", reason: `agents may not run \`agentgate ${m[1]}\` (it would reconfigure their own gate)` };
      const api = API_ABUSE_RE.exec(cmd);
      if (api) return { decision: "deny", reason: `agents may not call AgentGate credential/approval endpoints directly (${api[0]})` };
      const refs = [this.agentgateHome(), "/.agentgate", "~/.agentgate", ".claude/settings", ...(this.opts.protectedDirs ?? [])];
      const hit = refs.find((r) => r && cmd.includes(r)) ?? (AGENTGATE_DIR_REF_RE.test(cmd) ? ".agentgate" : undefined);
      if (hit) return { decision: "ask", reason: `command touches AgentGate-protected path (${hit})` };
      return null;
    }
    if (WRITE_TOOLS.has(tool)) {
      const raw = firstString(input.file_path, input.path, input.notebook_path);
      if (!raw) return null;
      const p = this.absolute(raw, cwd);
      if (isWithin(this.agentgateHome(), p)) return { decision: "deny", reason: "agents may not modify AgentGate's config/tokens" };
      for (const d of this.opts.protectedDirs ?? []) {
        if (isWithin(d, p)) return { decision: "deny", reason: `agents may not modify AgentGate itself (${d})` };
      }
      if (/(^|\/)\.claude\/settings(\.local)?\.json$/.test(p)) return { decision: "deny", reason: "agents may not modify Claude Code hook settings" };
      return null;
    }
    if (tool === "Read") {
      const raw = firstString(input.file_path, input.path);
      const reason = raw ? this.sensitiveReadReason(this.absolute(raw, cwd)) : null;
      return reason ? { decision: "ask", reason } : null;
    }
    return null;
  }

  private absolute(p: string, cwd: string): string {
    if (p === "~") return this.opts.homeDir;
    if (p.startsWith("~/")) return resolve(this.opts.homeDir, p.slice(2));
    return isAbsolute(p) ? resolve(p) : resolve(cwd, p);
  }
}

// ── helpers (exported for tests / reuse) ─────────────────────────────────────

export function parseMcpToolName(name: string): { server: string; tool: string } | null {
  if (!name.startsWith("mcp__")) return null;
  const rest = name.slice(5);
  const i = rest.indexOf("__");
  if (i <= 0 || i + 2 >= rest.length) return null;
  return { server: rest.slice(0, i), tool: rest.slice(i + 2) };
}

/**
 * High risk for paths whose modification is a classic escalation/persistence/secret
 * vector. Returns undefined when nothing stands out (the engine classifies normally).
 */
export interface PathOpts {
  homeDir: string;
  projectRoot: string;
  agentgateHome?: string;
  protectedDirs?: string[];
}

export function sensitivePathRisk(absPath: string, o: PathOpts): Risk | undefined {
  const reason = sensitivePathReason(absPath, o);
  return reason ? { level: "high", reason } : undefined;
}

export function sensitivePathReason(absPath: string, o: PathOpts): string | null {
  const p = resolve(absPath);
  const base = basename(p);
  const parts = p.split(sep);
  const within = (root: string) => {
    const rel = relative(resolve(root), p);
    return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
  };

  if (within(o.agentgateHome ?? join(o.homeDir, ".agentgate"))) return "writes AgentGate's own config";
  for (const d of o.protectedDirs ?? []) if (within(d)) return `writes AgentGate itself (${d})`;
  if (within(join(o.homeDir, ".claude")) || parts.includes(".claude")) return "writes Claude Code configuration (.claude/)";
  if (/^\.env(\..*)?$/.test(base) || base.endsWith(".env")) return `writes environment/secrets file ${base}`;
  if (/\.(pem|key|p12|pfx|jks|keystore)$/i.test(base)) return `writes key material ${base}`;
  if (/^id_[A-Za-z0-9_-]+(\.pub)?$/.test(base)) return `writes SSH key ${base}`;
  if (within(join(o.homeDir, ".ssh"))) return "writes inside ~/.ssh";
  const gi = parts.lastIndexOf(".git");
  if (gi !== -1 && parts[gi + 1] === "hooks") return "writes a git hook (runs code on git operations)";
  if (gi !== -1) return "writes git internals";
  if (within(join(o.homeDir, ".aws")) || within(join(o.homeDir, ".config", "gcloud")) || within(join(o.homeDir, ".kube"))) {
    return "writes cloud credentials/config";
  }
  if ([".npmrc", ".netrc", ".pypirc", "credentials", ".git-credentials"].includes(base)) return `writes credentials file ${base}`;
  if (
    within(o.homeDir) &&
    [".zshrc", ".bashrc", ".bash_profile", ".profile", ".zprofile", ".zshenv"].includes(base) &&
    relative(o.homeDir, p) === base
  ) {
    return `writes shell startup file ~/${base}`;
  }
  if (!within(o.projectRoot)) return "writes outside the project root";
  return null;
}

function firstString(...v: unknown[]): string | undefined {
  for (const x of v) if (typeof x === "string" && x.trim()) return x;
  return undefined;
}

function contextOf(event: PreToolUseInput, ctx: AdapterContext): Record<string, string> {
  const c: Record<string, string> = {};
  if (ctx.repo) c.repo = ctx.repo;
  if (ctx.branch) c.branch = ctx.branch;
  if (event.session_id) c.claude_session_id = event.session_id.slice(0, 256);
  if (event.tool_use_id) c.tool_use_id = event.tool_use_id.slice(0, 256);
  if (event.permission_mode) c.permission_mode = event.permission_mode.slice(0, 64);
  return c;
}

/** SHA-256 of a key-sorted JSON rendering (binds the exact edit without storing content). */
function sha256Json(v: unknown): string {
  return createHash("sha256").update(stableStringify(v), "utf8").digest("hex");
}

function stableStringify(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .filter((k) => o[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${stableStringify(o[k])}`)
    .join(",")}}`;
}

function isWithin(root: string, p: string): boolean {
  const rel = relative(resolve(root), resolve(p));
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

/**
 * `agentgate [flags] [--] <login|logout|install|uninstall|pair|devices|setup|update|restart>`
 * anywhere in a command (`uninstall` also covers `uninstall-server`). `update` would let an
 * agent swap or roll back the code that gates it; `setup`/`restart` reconfigure the server.
 */
export const SELF_MANAGEMENT_RE =
  /(?:^|[^\w.-])agentgate(?:\.sh|\.mjs)?['"]?(?:\s+-{1,2}[\w-]+(?:=\S+)?)*\s+(?:--\s+)?(login|logout|install|uninstall|pair|devices|setup|update|restart)\b/;
/** A relative reference to an AgentGate install/config dir (`cd ~ && ln -sfn x .agentgate/current`). */
export const AGENTGATE_DIR_REF_RE = /(?:^|[\s'"=:;&|(])\.agentgate(?:\/|['"\s;&|)]|$)/;
/** Direct use of AgentGate's credential / approval endpoints. */
export const API_ABUSE_RE = /\/v1\/(?:pairing|auth\/(?:login|refresh)|devices|approvals\/[^\s/'"]+\/(?:approve|deny|cancel))\b/;
export * from "./provider.ts";
export * from "./prices.ts";
