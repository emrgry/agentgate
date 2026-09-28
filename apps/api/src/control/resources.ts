import { execFile } from "node:child_process";

/**
 * Phase 4 resource sampling: one `ps` snapshot of all processes, then per turn the sum of
 * %CPU and RSS over its process group plus every descendant found by a ppid walk (catches
 * children that left the group via setsid). No native deps; macOS + Linux (procps) `ps`.
 */

export interface PsRow {
  pid: number;
  ppid: number;
  pgid: number;
  cpu: number;
  rssKb: number;
  /** Process start time (identity guard against pid reuse). */
  start: string;
  /** Command line (may be empty with a minimal ps). */
  command: string;
}

export type PsRunner = () => Promise<string>;

export const PS_ARGS = ["-A", "-o", "pid=,ppid=,pgid=,%cpu=,rss=,lstart=,command="];

export const realPs: PsRunner = () =>
  new Promise((res, rej) =>
    execFile("ps", PS_ARGS, { encoding: "utf8", timeout: 5_000, maxBuffer: 16 * 1024 * 1024, env: { ...process.env, LC_ALL: "C" } }, (err, out) => (err ? rej(err) : res(out))),
  );

export function parsePs(out: string): PsRow[] {
  const rows: PsRow[] = [];
  for (const line of out.split("\n")) {
    const m = line.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+([\d.,]+)\s+(\d+)\s*(.*)$/);
    if (!m) continue;
    // lstart is always 5 tokens ("Sat Sep 26 12:00:00 2026"); the command follows.
    const rest = m[6]!.trim().split(/\s+/);
    const start = rest.slice(0, 5).join(" ");
    const command = m[6]!.trim().replace(/^(\S+\s+){0,4}\S+\s*/, "");
    rows.push({ pid: Number(m[1]), ppid: Number(m[2]), pgid: Number(m[3]), cpu: Number(m[4]!.replace(",", ".")) || 0, rssKb: Number(m[5]) || 0, start, command: rest.length > 5 ? command : "" });
  }
  return rows;
}

/** The turn's processes: its group + all descendants of the leader (ppid walk). */
export function processTree(rows: PsRow[], leader: number): PsRow[] {
  if (!leader) return [];
  const children = new Map<number, PsRow[]>();
  for (const r of rows) {
    const list = children.get(r.ppid);
    if (list) list.push(r);
    else children.set(r.ppid, [r]);
  }
  const out = new Map<number, PsRow>();
  for (const r of rows) if (r.pgid === leader || r.pid === leader) out.set(r.pid, r);
  const stack = [...out.keys()];
  while (stack.length) {
    const p = stack.pop()!;
    for (const c of children.get(p) ?? []) {
      if (!out.has(c.pid)) {
        out.set(c.pid, c);
        stack.push(c.pid);
      }
    }
  }
  return [...out.values()];
}

/**
 * The turn's tree in parent-before-child order (BFS from the leader by ppid), then any other
 * members of the leader's process group. SIGSTOP should be sent in reverse (children first),
 * SIGCONT in this order (parent first).
 */
export function orderedTree(rows: PsRow[], leader: number): PsRow[] {
  if (!leader) return [];
  const byPid = new Map(rows.map((r) => [r.pid, r]));
  const children = new Map<number, PsRow[]>();
  for (const r of rows) {
    const list = children.get(r.ppid);
    if (list) list.push(r);
    else children.set(r.ppid, [r]);
  }
  const out: PsRow[] = [];
  const seen = new Set<number>();
  const root = byPid.get(leader);
  const queue: number[] = [];
  if (root) {
    out.push(root);
    seen.add(root.pid);
  }
  queue.push(leader);
  while (queue.length) {
    const p = queue.shift()!;
    for (const c of children.get(p) ?? []) {
      if (seen.has(c.pid)) continue;
      seen.add(c.pid);
      out.push(c);
      queue.push(c.pid);
    }
  }
  for (const r of rows) if (r.pgid === leader && !seen.has(r.pid)) out.push(r);
  return out;
}

export function summarize(tree: PsRow[], at: Date): { at: string; cpu_percent: number; rss_mb: number; processes: number } {
  const cpu = tree.reduce((a, r) => a + r.cpu, 0);
  const rss = tree.reduce((a, r) => a + r.rssKb, 0) / 1024;
  return { at: at.toISOString(), cpu_percent: Math.round(cpu * 10) / 10, rss_mb: Math.round(rss * 10) / 10, processes: tree.length };
}
