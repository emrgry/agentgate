import { HOOK_MATCHER } from "@agentgate/adapter-claude-code";
import { shellQuote } from "./action.ts";

/**
 * Pure helpers for merging AgentGate's hooks into a Claude Code settings JSON object
 * without disturbing anything else. Our hook commands are identified by BOTH the shim
 * name and an explicit marker argument (ignored by the shim), so uninstall removes only
 * entries we wrote — never a user's own hook that happens to call agentgate.
 */

export const INSTALL_MARKER = "--agentgate-install=claude-code/v1";
export const SHIM_NAME = "agentgate-hook.sh";
export const PRE_TOOL_USE_TIMEOUT_S = 600;
export const SESSION_END_TIMEOUT_S = 10;
export const POST_TOOL_USE_TIMEOUT_S = 10;
/** PostToolUse reports execution of non-Bash calls (approved Bash is reported by `exec`). */
export const POST_TOOL_USE_MATCHER = "Write|Edit|MultiEdit|NotebookEdit|mcp__.*";
/** Observe-only events (Control Center observed sessions): never block, always exit 0. */
export const OBSERVE_EVENTS = ["SessionStart", "UserPromptSubmit", "Notification", "Stop"] as const;
export const OBSERVE_ARG = "--agentgate-observe";
export const OBSERVE_TIMEOUT_S = 10;
export const OUR_EVENTS = ["PreToolUse", "PostToolUse", "SessionEnd", ...OBSERVE_EVENTS] as const;

type Json = Record<string, unknown>;
interface HookCmd {
  type?: unknown;
  command?: unknown;
  [k: string]: unknown;
}
interface Group {
  matcher?: unknown;
  hooks?: unknown;
  [k: string]: unknown;
}

export interface HookCommandSpec {
  shimPath: string;
  nodePath: string;
  home: string;
  env?: string;
  ttl?: number;
}

/** Absolute paths only; no tokens. The marker arg is ignored by the shim. */
export function buildInstalledHookCommand(s: HookCommandSpec): string {
  const vars: Array<[string, string]> = [
    ["AGENTGATE_HOME", s.home],
    ["AGENTGATE_NODE", s.nodePath],
    ["AGENTGATE_HOOK_TIMEOUT_S", String(PRE_TOOL_USE_TIMEOUT_S)],
  ];
  if (s.env) vars.push(["AGENTGATE_ENV", s.env]);
  if (s.ttl) vars.push(["AGENTGATE_TTL", String(s.ttl)]);
  return `${vars.map(([k, v]) => `${k}=${shellQuote(v)}`).join(" ")} ${shellQuote(s.shimPath)} ${INSTALL_MARKER}`;
}

export function isOurCommand(cmd: unknown): boolean {
  return typeof cmd === "string" && cmd.includes(SHIM_NAME) && cmd.includes(INSTALL_MARKER);
}

export function ourGroups(command: string): Record<(typeof OUR_EVENTS)[number], Group> {
  const observe = `${command} ${OBSERVE_ARG}`;
  const obs = { hooks: [{ type: "command", command: observe, timeout: OBSERVE_TIMEOUT_S }] };
  return {
    SessionStart: obs,
    UserPromptSubmit: obs,
    Notification: obs,
    Stop: obs,
    PreToolUse: { matcher: HOOK_MATCHER, hooks: [{ type: "command", command, timeout: PRE_TOOL_USE_TIMEOUT_S }] },
    PostToolUse: { matcher: POST_TOOL_USE_MATCHER, hooks: [{ type: "command", command, timeout: POST_TOOL_USE_TIMEOUT_S }] },
    SessionEnd: { hooks: [{ type: "command", command, timeout: SESSION_END_TIMEOUT_S }] },
  };
}

function isObj(v: unknown): v is Json {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Removes our hook commands from every event; drops groups that became empty because of
 * that (groups that were already empty are left alone). Returns a new object.
 */
export function removeOurHooks(settings: Json): { settings: Json; removed: number } {
  if (!isObj(settings.hooks)) return { settings, removed: 0 };
  let removed = 0;
  const hooks: Json = {};
  for (const [event, groups] of Object.entries(settings.hooks)) {
    if (!Array.isArray(groups)) {
      hooks[event] = groups;
      continue;
    }
    const kept: unknown[] = [];
    for (const g of groups as unknown[]) {
      if (!isObj(g) || !Array.isArray((g as Group).hooks)) {
        kept.push(g);
        continue;
      }
      const inner = (g as Group).hooks as HookCmd[];
      const rest = inner.filter((h) => !(isObj(h) && isOurCommand(h.command)));
      removed += inner.length - rest.length;
      if (rest.length === inner.length) kept.push(g);
      else if (rest.length > 0) kept.push({ ...g, hooks: rest });
    }
    hooks[event] = kept;
  }
  return { settings: { ...settings, hooks }, removed };
}

/** Idempotent install: remove any previous AgentGate entries, then append ours. */
export function addOurHooks(settings: Json, command: string): Json {
  const base = removeOurHooks(settings).settings;
  const hooks: Json = isObj(base.hooks) ? { ...base.hooks } : {};
  const groups = ourGroups(command);
  for (const ev of OUR_EVENTS) {
    const existing = Array.isArray(hooks[ev]) ? (hooks[ev] as unknown[]) : [];
    hooks[ev] = [...existing, groups[ev]];
  }
  return { ...base, hooks };
}

/** Our hook commands currently present (for status / run). */
export function findOurCommands(settings: unknown): { event: string; command: string }[] {
  if (!isObj(settings) || !isObj(settings.hooks)) return [];
  const out: { event: string; command: string }[] = [];
  for (const [event, groups] of Object.entries(settings.hooks)) {
    if (!Array.isArray(groups)) continue;
    for (const g of groups) {
      if (!isObj(g) || !Array.isArray(g.hooks)) continue;
      for (const h of g.hooks as unknown[]) {
        if (isObj(h) && isOurCommand(h.command)) out.push({ event, command: h.command as string });
      }
    }
  }
  return out;
}

/** Extracts `VAR='value'` / `VAR=value` from an installed command (for health checks). */
export function commandVar(command: string, name: string): string | undefined {
  const m = command.match(new RegExp(`(?:^|\\s)${name}=('((?:[^']|'\\\\'')*)'|(\\S+))`));
  if (!m) return undefined;
  return m[2] !== undefined ? m[2].replace(/'\\''/g, "'") : m[3];
}

/** The quoted shim path in an installed command. */
export function commandShim(command: string): string | undefined {
  const m = command.match(/'([^']*agentgate-hook\.sh)'|(\S*agentgate-hook\.sh)/);
  return m?.[1] ?? m?.[2];
}
