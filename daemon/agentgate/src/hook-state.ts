import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, readdirSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { agentgateHome } from "./config.ts";

/**
 * Small 0600 JSON records shared between hook invocations (separate processes):
 *   pending/<approval_id>.json   approvals a PreToolUse hook is currently waiting on
 *                                (SessionEnd cancels them)
 *   tooluse/<tool_use_id>.json   allowed/approved non-Bash calls awaiting PostToolUse
 *                                (correlates Claude's tool_use_id → AgentGate action)
 */

const dirOf = (kind: "pending" | "tooluse") => join(agentgateHome(), kind);

function stem(id: string): string {
  return /^[A-Za-z0-9_-]{1,128}$/.test(id) ? id : `h_${createHash("sha256").update(id).digest("hex").slice(0, 40)}`;
}

function write(kind: "pending" | "tooluse", id: string, value: unknown) {
  const dir = dirOf(kind);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const target = join(dir, `${stem(id)}.json`);
  const tmp = `${target}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(value), { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, target);
}

function read<T>(kind: "pending" | "tooluse", id: string): T | null {
  try {
    return JSON.parse(readFileSync(join(dirOf(kind), `${stem(id)}.json`), "utf8")) as T;
  } catch {
    return null;
  }
}

function remove(kind: "pending" | "tooluse", id: string) {
  try {
    unlinkSync(join(dirOf(kind), `${stem(id)}.json`));
  } catch {
    /* gone */
  }
}

// ── pending approvals ───────────────────────────────────────────────────────

export interface PendingRecord {
  approval_id: string;
  session_id: string;
  claude_session_id?: string;
  pid: number;
}

export const markPending = (r: PendingRecord) => write("pending", r.approval_id, r);
export const clearPending = (approvalId: string) => remove("pending", approvalId);

/** Pending approvals of an AgentGate session and/or Claude session. */
export function listPending(match: { session_id?: string; claude_session_id?: string }): PendingRecord[] {
  let names: string[] = [];
  try {
    names = readdirSync(dirOf("pending"));
  } catch {
    return [];
  }
  const out: PendingRecord[] = [];
  for (const n of names) {
    if (!n.endsWith(".json")) continue;
    const r = read<PendingRecord>("pending", n.slice(0, -5));
    if (!r) continue;
    if ((match.session_id && r.session_id === match.session_id) || (match.claude_session_id && r.claude_session_id === match.claude_session_id)) {
      out.push(r);
    }
  }
  return out;
}

// ── tool_use_id correlation ─────────────────────────────────────────────────

export interface ToolUseRecord {
  tool_use_id: string;
  action_id: string;
  session_id: string;
  tool_name: string;
  created_at: string;
}

export const rememberToolUse = (r: ToolUseRecord) => write("tooluse", r.tool_use_id, r);

/** Returns and deletes the record (a tool_use_id is reported at most once). */
export function takeToolUse(toolUseId: string): ToolUseRecord | null {
  const r = read<ToolUseRecord>("tooluse", toolUseId);
  if (r) remove("tooluse", toolUseId);
  return r && r.tool_use_id === toolUseId ? r : null;
}

/** Drop records older than a day (tool never ran / PostToolUse never came). Best effort. */
export function pruneToolUse(maxAgeMs = 24 * 3600_000) {
  const dir = dirOf("tooluse");
  let names: string[] = [];
  try {
    names = readdirSync(dir);
  } catch {
    return;
  }
  const now = Date.now();
  for (const n of names) {
    try {
      if (now - statSync(join(dir, n)).mtimeMs > maxAgeMs) unlinkSync(join(dir, n));
    } catch {
      /* ignore */
    }
  }
}
