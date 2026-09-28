import { readFileSync } from "node:fs";
import { basename } from "node:path";

/**
 * Gating tripwire helpers. The Codex/generic PreToolUse hook (`agentgate hook <provider>`)
 * appends JSONL receipts to AGENTGATE_GATE_RECEIPTS: `invoked` before it asks anyone, then
 * `decision`. The supervisor matches every tool the provider reports against them.
 */

export interface GateReceipt {
  phase: "invoked" | "decision";
  kind: string; // shell | file | mcp | tool | other
  text: string;
  paths: string[];
  tool_use_id: string | null;
  decision?: "allow" | "deny";
}

export interface ToolSighting {
  phase: "started" | "completed";
  kind: string;
  item_id?: string | null;
  text?: string;
  paths?: string[];
  status?: string;
}

const MAX_RECEIPTS_BYTES = 4 * 1024 * 1024;

export function readReceipts(file: string): GateReceipt[] {
  const raw = readFileSync(file, "utf8").slice(0, MAX_RECEIPTS_BYTES);
  const out: GateReceipt[] = [];
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    try {
      const o = JSON.parse(line) as Partial<GateReceipt>;
      if (o.phase !== "invoked" && o.phase !== "decision") continue;
      out.push({
        phase: o.phase,
        kind: typeof o.kind === "string" ? o.kind : "other",
        text: typeof o.text === "string" ? o.text : "",
        paths: Array.isArray(o.paths) ? o.paths.filter((p): p is string => typeof p === "string") : [],
        tool_use_id: typeof o.tool_use_id === "string" ? o.tool_use_id : null,
        ...(o.decision === "allow" || o.decision === "deny" ? { decision: o.decision } : {}),
      });
    } catch {
      /* partial line: ignored */
    }
  }
  return out;
}

const norm = (s: string) => s.replace(/\s+/g, " ").trim();

function pathsOverlap(a: string[], b: string[]): boolean {
  if (!a.length || !b.length) return false;
  return a.some((x) => b.some((y) => x === y || x.endsWith(`/${y}`) || y.endsWith(`/${x}`) || basename(x) === basename(y)));
}

function kindCompatible(receiptKind: string, sightingKind: string): boolean {
  // Generic providers report every tool as "tool": any receipt kind qualifies.
  return sightingKind === "tool" || receiptKind === sightingKind || receiptKind === "other" || receiptKind === "tool";
}

/**
 * Index of the unconsumed `invoked` receipt for this tool, or -1. Preference: same tool id;
 * then same kind with matching command text / overlapping paths; then the oldest unconsumed
 * receipt of a compatible kind (hooks may see a differently formatted command than the
 * provider's JSON stream — e.g. a shell wrapper — so exact text is not required).
 */
export function matchReceipt(receipts: GateReceipt[], consumed: Set<number>, t: ToolSighting): number {
  const open = receipts.map((r, i) => ({ r, i })).filter(({ r, i }) => r.phase === "invoked" && !consumed.has(i));
  if (t.item_id) {
    const byId = open.find(({ r }) => r.tool_use_id === t.item_id);
    if (byId) return byId.i;
  }
  const compatible = open.filter(({ r }) => kindCompatible(r.kind, t.kind));
  const text = t.text ? norm(t.text) : "";
  if (text) {
    const exact = compatible.find(({ r }) => r.text && (norm(r.text) === text || text.includes(norm(r.text)) || norm(r.text).includes(text)));
    if (exact) return exact.i;
  }
  if (t.paths?.length) {
    const byPath = compatible.find(({ r }) => pathsOverlap(r.paths, t.paths!));
    if (byPath) return byPath.i;
  }
  return compatible[0]?.i ?? -1;
}
