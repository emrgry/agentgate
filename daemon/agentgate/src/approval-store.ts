import { chmodSync, mkdirSync, readdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ActionDraft } from "@agentgate/protocol";
import { z } from "zod";
import { paths } from "./config.ts";

/**
 * Approved-but-not-yet-executed Bash actions, handed from `agentgate hook claude-code`
 * to `agentgate exec --approval <id>`. The signed token lives here (0600, never in the
 * rewritten command or Claude's transcript). The stored draft supplies the hash inputs
 * that exec does not re-derive itself (agent, tool, resource); exec substitutes the
 * command it actually received and its own cwd, so any change to either is a mismatch.
 */

const ID_RE = /^apr_[A-Za-z0-9_-]{4,64}$/;

export const StoredApproval = z.object({
  v: z.literal(1),
  approval_id: z.string().regex(ID_RE),
  action_id: z.string(),
  session_id: z.string(),
  token: z.string(),
  draft: ActionDraft,
  stored_at: z.string(),
});
export type StoredApproval = z.infer<typeof StoredApproval>;

export function isApprovalId(id: string): boolean {
  return ID_RE.test(id);
}

function fileFor(id: string): string {
  if (!ID_RE.test(id)) throw new Error(`invalid approval id: ${id}`);
  return join(paths.approvals(), `${id}.json`);
}

export function saveApproval(rec: StoredApproval): void {
  const dir = paths.approvals();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  const target = fileFor(rec.approval_id);
  const tmp = `${target}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(StoredApproval.parse(rec)), { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, target);
}

/** Returns null if missing. Throws on a corrupt record (callers fail closed). */
export function loadApproval(id: string): StoredApproval | null {
  let raw: string;
  try {
    raw = readFileSync(fileFor(id), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  return StoredApproval.parse(JSON.parse(raw));
}

export function deleteApproval(id: string): void {
  try {
    unlinkSync(fileFor(id));
  } catch {
    /* already gone */
  }
}

/** Remove stored approvals of a session (e.g. when `run` exits). Best effort. */
export function pruneApprovals(sessionId: string): number {
  let n = 0;
  let names: string[] = [];
  try {
    names = readdirSync(paths.approvals());
  } catch {
    return 0;
  }
  for (const name of names) {
    if (!name.endsWith(".json")) continue;
    const id = name.slice(0, -5);
    try {
      const rec = loadApproval(id);
      if (rec && rec.session_id === sessionId) {
        deleteApproval(id);
        n++;
      }
    } catch {
      /* ignore */
    }
  }
  return n;
}
