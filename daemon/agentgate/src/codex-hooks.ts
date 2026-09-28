import { createHash } from "node:crypto";
import { shellQuote } from "./action.ts";

/**
 * Pure helpers for `agentgate install codex`: merging AgentGate's hook into a Codex
 * `hooks.json` without touching anything else, and computing the hook TRUST entries Codex
 * requires before it runs a non-managed hook (docs/control-center.md, "Codex hooks").
 *
 * Verified against codex-cli 0.131.0–0.158.0 (real binary, mock model):
 *   - hooks.json top level allows only `description` and `hooks` (serde deny_unknown_fields);
 *   - user/project hooks run only when `[hooks.state."<key>"] trusted_hash = "<hash>"` is in
 *     the USER config.toml (untrusted hooks are skipped silently → the tool runs ungated);
 *   - key  = "<absolute hooks.json path>:<event_label>:<group index>:<handler index>";
 *   - hash = "sha256:" + hex(sha256(canonical JSON of {event_name, [matcher], hooks:[handler]}))
 *     with the handler normalized (timeout defaulted/clamped, commandWindows dropped).
 * Our entries are recognized by the shim name AND an explicit marker argument (ignored by
 * the shim), so uninstall removes only what we wrote.
 */

export const CODEX_INSTALL_MARKER = "--agentgate-install=codex/v1";
export const CODEX_PROVIDER_ARG = "--agentgate-provider=codex";
export const CODEX_SHIM_NAME = "agentgate-hook.sh";
/** Codex's own default (and our hook budget: the node hook stops itself 30 s earlier). */
export const CODEX_PRE_TOOL_USE_TIMEOUT_S = 600;
/** Codex clamps SessionEnd hooks to 1–3 s. */
export const CODEX_SESSION_END_TIMEOUT_S = 3;
export const CODEX_STATUS_MESSAGE = "AgentGate: checking policy (approve on your phone if asked)";
export const CODEX_OUR_EVENTS = ["PreToolUse", "SessionEnd"] as const;
/** Earliest Codex whose hook contract we verified by running it. */
export const CODEX_MIN_VERIFIED_VERSION = "0.131.0";

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

export type CodexScope = "user" | "project";

export interface CodexHookCommandSpec {
  shimPath: string;
  nodePath: string;
  home: string;
  scope: CodexScope;
  env?: string;
  ttl?: number;
}

/**
 * Absolute paths only; no tokens. `AGENTGATE_CODEX_INSTALL` tells the hook it gates an
 * interactive Codex (not a Control Center turn); the two args are read by the shim.
 */
export function buildCodexHookCommand(s: CodexHookCommandSpec): string {
  const vars: Array<[string, string]> = [
    ["AGENTGATE_HOME", s.home],
    ["AGENTGATE_NODE", s.nodePath],
    ["AGENTGATE_HOOK_TIMEOUT_S", String(CODEX_PRE_TOOL_USE_TIMEOUT_S)],
    ["AGENTGATE_CODEX_INSTALL", s.scope],
  ];
  if (s.env) vars.push(["AGENTGATE_ENV", s.env]);
  if (s.ttl) vars.push(["AGENTGATE_TTL", String(s.ttl)]);
  return `${vars.map(([k, v]) => `${k}=${shellQuote(v)}`).join(" ")} ${shellQuote(s.shimPath)} ${CODEX_PROVIDER_ARG} ${CODEX_INSTALL_MARKER}`;
}

export function isOurCodexCommand(cmd: unknown): boolean {
  return typeof cmd === "string" && cmd.includes(CODEX_SHIM_NAME) && cmd.includes(CODEX_INSTALL_MARKER);
}

/** Our matcher groups. No `matcher`: every tool (unknown future tools are governed too). */
export function ourCodexGroups(command: string): Record<(typeof CODEX_OUR_EVENTS)[number], Json> {
  return {
    PreToolUse: { hooks: [{ type: "command", command, timeout: CODEX_PRE_TOOL_USE_TIMEOUT_S, statusMessage: CODEX_STATUS_MESSAGE }] },
    SessionEnd: { hooks: [{ type: "command", command, timeout: CODEX_SESSION_END_TIMEOUT_S }] },
  };
}

/** Throws on shapes we refuse to edit (never guess). Codex itself rejects unknown top-level keys. */
export function validateCodexHooksDoc(doc: unknown, file: string): Json {
  if (!isObj(doc)) throw new Error(`${file} is not a JSON object — not modifying it`);
  const extra = Object.keys(doc).filter((k) => k !== "description" && k !== "hooks");
  if (extra.length) throw new Error(`${file}: unexpected top-level key(s) ${extra.join(", ")} (Codex only accepts "description" and "hooks") — not modifying it`);
  if (doc.hooks !== undefined) {
    if (!isObj(doc.hooks)) throw new Error(`${file}: "hooks" is not an object — not modifying it`);
    for (const [ev, groups] of Object.entries(doc.hooks)) {
      if (!Array.isArray(groups)) throw new Error(`${file}: hooks.${ev} is not an array — not modifying it`);
      for (const g of groups) {
        if (!isObj(g) || (g.hooks !== undefined && !Array.isArray(g.hooks))) throw new Error(`${file}: hooks.${ev} has a malformed matcher group — not modifying it`);
      }
    }
  }
  return doc;
}

/** Removes our handlers; drops groups that became empty because of that. Returns a new object. */
export function removeOurCodexHooks(doc: Json): { doc: Json; removed: number } {
  if (!isObj(doc.hooks)) return { doc, removed: 0 };
  let removed = 0;
  const hooks: Json = {};
  for (const [ev, groups] of Object.entries(doc.hooks)) {
    if (!Array.isArray(groups)) {
      hooks[ev] = groups;
      continue;
    }
    const kept: unknown[] = [];
    for (const g of groups) {
      if (!isObj(g) || !Array.isArray(g.hooks)) {
        kept.push(g);
        continue;
      }
      const rest = (g.hooks as unknown[]).filter((h) => !(isObj(h) && isOurCodexCommand(h.command)));
      removed += (g.hooks as unknown[]).length - rest.length;
      if (rest.length === (g.hooks as unknown[]).length) kept.push(g);
      else if (rest.length > 0) kept.push({ ...g, hooks: rest });
    }
    hooks[ev] = kept;
  }
  return { doc: { ...doc, hooks }, removed };
}

/** Idempotent: drop previous AgentGate entries, then append ours (user groups keep their order and indices). */
export function addOurCodexHooks(doc: Json, command: string): Json {
  const base = removeOurCodexHooks(doc).doc;
  const hooks: Json = isObj(base.hooks) ? { ...base.hooks } : {};
  const ours = ourCodexGroups(command);
  for (const ev of CODEX_OUR_EVENTS) hooks[ev] = [...(Array.isArray(hooks[ev]) ? (hooks[ev] as unknown[]) : []), ours[ev]];
  return { ...base, hooks };
}

export function findOurCodexCommands(doc: unknown): Array<{ event: string; command: string }> {
  if (!isObj(doc) || !isObj(doc.hooks)) return [];
  const found: Array<{ event: string; command: string }> = [];
  for (const [ev, groups] of Object.entries(doc.hooks)) {
    if (!Array.isArray(groups)) continue;
    for (const g of groups) {
      if (!isObj(g) || !Array.isArray(g.hooks)) continue;
      for (const h of g.hooks) if (isObj(h) && isOurCodexCommand(h.command)) found.push({ event: ev, command: h.command as string });
    }
  }
  return found;
}

/** Other (non-AgentGate) PreToolUse handlers: they run concurrently and a later `updatedInput` from them wins. */
export function otherPreToolUseHooks(doc: unknown): number {
  if (!isObj(doc) || !isObj(doc.hooks) || !Array.isArray(doc.hooks.PreToolUse)) return 0;
  let n = 0;
  for (const g of doc.hooks.PreToolUse) {
    if (isObj(g) && Array.isArray(g.hooks)) n += g.hooks.filter((h) => !(isObj(h) && isOurCodexCommand(h.command))).length;
  }
  return n;
}

// ── hook trust (Codex hooks.state) ──────────────────────────────────────────

const EVENT_LABEL: Record<string, string> = {
  PreToolUse: "pre_tool_use",
  PermissionRequest: "permission_request",
  PostToolUse: "post_tool_use",
  PreCompact: "pre_compact",
  PostCompact: "post_compact",
  SessionStart: "session_start",
  SessionEnd: "session_end",
  UserPromptSubmit: "user_prompt_submit",
  SubagentStart: "subagent_start",
  SubagentStop: "subagent_stop",
  Stop: "stop",
  Interrupt: "interrupt",
};
/** Events whose handlers may carry additionalContextLimit into the identity. */
const CONTEXT_EVENTS = new Set(["PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit", "SubagentStart"]);
const DEFAULT_CONTEXT_LIMIT = 2500;

function canonical(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonical);
  if (isObj(v)) return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k])]));
  return v;
}

/** Codex's normalized timeout: SessionEnd/Interrupt default 1 s, clamped to 1–3 s; others default 600, min 1. */
function normalizedTimeout(event: string, t: unknown): number {
  const v = typeof t === "number" && Number.isInteger(t) && t >= 0 ? t : undefined;
  if (event === "SessionEnd" || event === "Interrupt") return Math.min(3, Math.max(1, v ?? 1));
  return Math.max(1, v ?? 600);
}

/**
 * Codex's trust hash for one command handler of a group WITHOUT a matcher (ours never has
 * one): sha256 of the key-sorted, compact JSON of the normalized identity.
 */
export function codexHookTrustHash(event: string, handler: Json): string {
  const label = EVENT_LABEL[event];
  if (!label) throw new Error(`unknown Codex hook event ${event}`);
  const h: Json = {
    type: "command",
    command: String(handler.command ?? ""),
    timeout: normalizedTimeout(event, handler.timeout),
    async: handler.async === true,
  };
  if (typeof handler.statusMessage === "string") h.statusMessage = handler.statusMessage;
  const limit = handler.additionalContextLimit;
  if (CONTEXT_EVENTS.has(event) && typeof limit === "number" && limit !== DEFAULT_CONTEXT_LIMIT) h.additionalContextLimit = limit;
  const identity = { event_name: label, hooks: [h] };
  return `sha256:${createHash("sha256").update(JSON.stringify(canonical(identity))).digest("hex")}`;
}

export interface TrustEntry {
  event: string;
  key: string;
  hash: string;
}

/** Trust entries for OUR handlers at their current positions in `doc` (key uses `hooksFile` verbatim). */
export function codexTrustEntries(doc: Json, hooksFile: string): TrustEntry[] {
  if (!isObj(doc.hooks)) return [];
  const out: TrustEntry[] = [];
  for (const [ev, groups] of Object.entries(doc.hooks)) {
    if (!Array.isArray(groups) || !EVENT_LABEL[ev]) continue;
    groups.forEach((g, gi) => {
      if (!isObj(g) || !Array.isArray(g.hooks) || (g.matcher !== undefined && g.matcher !== null && g.matcher !== "" && g.matcher !== "*")) return;
      g.hooks.forEach((h, hi) => {
        if (isObj(h) && isOurCodexCommand(h.command)) out.push({ event: ev, key: `${hooksFile}:${EVENT_LABEL[ev]}:${gi}:${hi}`, hash: codexHookTrustHash(ev, h) });
      });
    });
  }
  return out;
}

export const TRUST_BEGIN = "# >>> agentgate: Codex hook trust (written by `agentgate install codex`; removed by `agentgate uninstall codex`) >>>";
export const TRUST_END = "# <<< agentgate: Codex hook trust <<<";

/** TOML basic string. */
export function tomlString(s: string): string {
  return `"${s.replace(/[\\"\u0000-\u001f\u007f]/g, (ch) => {
    if (ch === "\\") return "\\\\";
    if (ch === '"') return '\\"';
    if (ch === "\n") return "\\n";
    if (ch === "\t") return "\\t";
    if (ch === "\r") return "\\r";
    return `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`;
  })}"`;
}

export function renderTrustBlock(entries: TrustEntry[]): string {
  const body = entries.map((e) => `[hooks.state.${tomlString(e.key)}]\ntrusted_hash = ${tomlString(e.hash)}\n`).join("\n");
  return `${TRUST_BEGIN}\n${body}${TRUST_END}\n`;
}

/**
 * Why appending `[hooks.state."<key>"]` tables to this config.toml might produce invalid or
 * conflicting TOML (null = safe). Conservative text checks, no TOML parser: an inline
 * `hooks = {…}` / `state = {…}` table or dotted `hooks.…` keys can't be extended by a table
 * header, and an existing entry for one of our keys must not be duplicated.
 */
export function trustConflict(config: string, entries: TrustEntry[]): string | null {
  // Track the current table header; only keys that could (re)define `hooks` / `hooks.state`
  // as an inline table or via dotted keys matter.
  let table = "";
  for (const raw of config.split("\n")) {
    const line = raw.replace(/^\s+/, "");
    if (line === "" || line.startsWith("#")) continue;
    const header = line.match(/^\[\[?\s*([^\]]*?)\s*\]\]?\s*(?:#.*)?$/);
    if (header) {
      table = header[1]!.replace(/\s*\.\s*/g, ".").replace(/"/g, "");
      continue;
    }
    const key = line.match(/^("?)([A-Za-z0-9_-]+)\1\s*([.=])/);
    if (!key) continue;
    if (table === "" && key[2] === "hooks") return "config.toml defines `hooks` with an inline table or dotted keys";
    if (table === "hooks" && key[2] === "state") return "config.toml defines `hooks.state` as an inline table or dotted keys";
  }
  const hit = entries.find((e) => config.includes(e.key) || config.includes(tomlString(e.key).slice(1, -1)));
  if (hit) return `config.toml already has a hook-state entry for ${hit.key}`;
  return null;
}

/** Appends the block; returns the new text and the exact appended string (for byte-exact removal). */
export function appendTrustBlock(config: string | null, block: string): { text: string; appended: string } {
  const cur = config ?? "";
  const sep = cur === "" ? "" : cur.endsWith("\n\n") ? "" : cur.endsWith("\n") ? "\n" : "\n\n";
  const appended = `${sep}${block}`;
  return { text: `${cur}${appended}`, appended };
}

/** Removes the exact appended string (last occurrence). null = not found verbatim. */
export function removeTrustBlock(config: string, appended: string): string | null {
  const i = config.lastIndexOf(appended);
  if (i === -1) return null;
  return config.slice(0, i) + config.slice(i + appended.length);
}

/** One of our generated tables, verbatim (as renderTrustBlock writes it). */
const ourTable = (e: TrustEntry) => `[hooks.state.${tomlString(e.key)}]\ntrusted_hash = ${tomlString(e.hash)}\n`;

/**
 * Removes our trust entries from config.toml:
 *   1. the exact block we appended, when still verbatim → the original bytes;
 *   2. otherwise surgically: exactly our `[hooks.state."<key>"] trusted_hash = "<hash>"` tables
 *      and our two marker lines. Codex edits config.toml itself (toml_edit), e.g. recording a
 *      trusted project, and inserts new tables INSIDE our block (above the end marker) — that
 *      content is kept.
 * `entries` must be the exact key/hash pairs we wrote (install record and/or recomputed from
 * the hooks.json that still contains our handlers). Returns null when nothing of ours was found.
 */
export function removeOurTrust(config: string, entries: TrustEntry[], appended?: string | null): string | null {
  if (appended) {
    const exact = removeTrustBlock(config, appended);
    if (exact !== null) return exact;
  }
  let text = config;
  let found = false;
  for (const e of entries) {
    const t = ourTable(e);
    for (let i = text.indexOf(t); i !== -1; i = text.indexOf(t)) {
      found = true;
      const after = text.slice(i + t.length);
      text = text.slice(0, i) + (after.startsWith("\n") && !after.startsWith(`\n${TRUST_END}`) ? after.slice(1) : after);
    }
  }
  const emptyBlock = `${TRUST_BEGIN}\n${TRUST_END}\n`;
  if (text.includes(emptyBlock)) {
    found = true;
    const i = text.indexOf(emptyBlock);
    let from = i;
    if (text.slice(0, i).endsWith("\n\n")) from = i - 1; // the blank line appendTrustBlock added
    text = text.slice(0, from) + text.slice(i + emptyBlock.length);
  } else {
    for (const marker of [`${TRUST_BEGIN}\n`, `${TRUST_END}\n`]) {
      const i = text.indexOf(marker);
      if (i !== -1 && (i === 0 || text[i - 1] === "\n")) {
        found = true;
        text = text.slice(0, i) + text.slice(i + marker.length);
      }
    }
  }
  return found ? text : null;
}

/** Does config.toml trust each entry with exactly this hash? (text check for status) */
export function trustedIn(config: string | null, entries: TrustEntry[]): boolean {
  if (!config || entries.length === 0) return false;
  return entries.every((e) => {
    const i = config.indexOf(tomlString(e.key));
    if (i === -1) return false;
    const after = config.slice(i, i + e.key.length + 400);
    return after.includes(e.hash);
  });
}

/** `[features] hooks = false` / `codex_hooks = false` turns every hook off. */
export function hooksDisabledIn(config: string | null): boolean {
  if (!config) return false;
  const features = config.match(/^\s*\[\s*features\s*\]\s*$([\s\S]*?)(?=^\s*\[|$(?![\s\S]))/m)?.[1] ?? "";
  return /^\s*(?:codex_)?hooks\s*=\s*false\b/m.test(features) || /^\s*features\.(?:codex_)?hooks\s*=\s*false\b/m.test(config);
}
