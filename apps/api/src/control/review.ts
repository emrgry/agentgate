import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { copyFileSync, existsSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";
import { redactCommandSecrets, type ChangedFile } from "@agentgate/protocol";
import { DomainError } from "../domain/errors.ts";

/**
 * Phase 3 review: what a session / task changed, relative to the git BASE captured when it
 * started — not HEAD — so files that were already dirty before the session only show the
 * session's own edits.
 *
 * Base = a snapshot tree of the whole working copy (tracked + untracked, .gitignore
 * respected) written with a throwaway index (`GIT_INDEX_FILE=<tmp> git add -A && git
 * write-tree`). Nothing touches the user's index, stash or refs; the tree objects are
 * unreferenced and eventually pruned by `git gc` (then we fall back to HEAD).
 */

export interface GitBase {
  /** Snapshot tree of the working copy at capture time. */
  tree: string | null;
  head: string | null;
  branch: string | null;
  /** Repo root (realpath). */
  top: string;
  at: string;
  /** Tasks: snapshot when the task ended (stable diff after later tasks ran). */
  end_tree?: string | null;
}

type Env = NodeJS.ProcessEnv;

function git(args: string[], cwd: string, o: { env?: Env; timeout?: number; maxBuffer?: number } = {}): Promise<string> {
  return new Promise((res, rej) => {
    execFile(
      "git",
      args,
      { cwd, env: { ...process.env, ...o.env, GIT_OPTIONAL_LOCKS: "0", GIT_TERMINAL_PROMPT: "0", LC_ALL: "C" }, timeout: o.timeout ?? 20_000, maxBuffer: o.maxBuffer ?? 64 * 1024 * 1024, encoding: "utf8" },
      (err, stdout, stderr) => (err ? rej(Object.assign(err, { stderr })) : res(stdout)),
    );
  });
}

export async function repoTop(cwd: string): Promise<string | null> {
  try {
    return realpathSync((await git(["rev-parse", "--show-toplevel"], cwd, { timeout: 5_000 })).trim());
  } catch {
    return null;
  }
}

/** Snapshot of the working copy as a tree object (throwaway index; user's index untouched). */
export async function snapshotTree(top: string): Promise<string | null> {
  const idx = join(tmpdir(), `agentgate-idx-${randomBytes(8).toString("hex")}`);
  try {
    // Start from the real index (stat cache → fast), then stage everything into the copy.
    const real = (await git(["rev-parse", "--git-path", "index"], top, { timeout: 5_000 })).trim();
    const realAbs = isAbsolute(real) ? real : join(top, real);
    if (existsSync(realAbs)) copyFileSync(realAbs, idx);
    const env = { GIT_INDEX_FILE: idx };
    await git(["add", "-A", "--", "."], top, { env, timeout: 60_000 });
    return (await git(["write-tree"], top, { env })).trim() || null;
  } catch {
    return null;
  } finally {
    rmSync(idx, { force: true });
    rmSync(`${idx}.lock`, { force: true });
  }
}

export async function captureBase(cwd: string, now: Date): Promise<GitBase | null> {
  const top = await repoTop(cwd);
  if (!top) return null;
  const head = (await git(["rev-parse", "--verify", "-q", "HEAD"], top, { timeout: 5_000 }).catch(() => "")).trim() || null;
  const branchRaw = (await git(["rev-parse", "--abbrev-ref", "HEAD"], top, { timeout: 5_000 }).catch(() => "")).trim();
  return { tree: await snapshotTree(top), head, branch: branchRaw && branchRaw !== "HEAD" ? branchRaw : null, top, at: now.toISOString() };
}

async function objectExists(top: string, sha: string | null | undefined): Promise<boolean> {
  if (!sha) return false;
  try {
    await git(["cat-file", "-e", sha], top, { timeout: 5_000 });
    return true;
  } catch {
    return false;
  }
}

/** The two trees to compare: base (fallback HEAD, then empty tree) → end snapshot or now. */
async function diffEnds(base: GitBase | null, cwd: string): Promise<{ top: string; from: string; to: string; baseRef: string | null } | null> {
  const top = base?.top && existsSync(base.top) ? base.top : await repoTop(cwd);
  if (!top) return null;
  let from = base?.tree && (await objectExists(top, base.tree)) ? base.tree : null;
  let baseRef = from ? (base?.head ?? from) : null;
  if (!from) {
    const head = (await git(["rev-parse", "--verify", "-q", "HEAD"], top).catch(() => "")).trim();
    from = head || (await git(["hash-object", "-t", "tree", "/dev/null"], top)).trim(); // empty tree
    baseRef = head || null;
  }
  const to = base?.end_tree && (await objectExists(top, base.end_tree)) ? base.end_tree : await snapshotTree(top);
  if (!to) return null;
  return { top, from, to, baseRef };
}

const STATUS: Record<string, string> = { A: "added", M: "modified", D: "deleted", R: "renamed", C: "copied", T: "typechange", U: "unmerged" };

export interface ChangeSetData {
  base_ref: string | null;
  files: ChangedFile[];
  totals: { files: number; additions: number; deletions: number };
  truncated: boolean;
}

export const MAX_FILES = 1000;

/** `git diff --numstat` (+ name-status) with rename detection between base and now/end. */
export async function changeSet(base: GitBase | null, cwd: string): Promise<ChangeSetData | null> {
  const ends = await diffEnds(base, cwd);
  if (!ends) return null;
  const { top, from, to, baseRef } = ends;
  const [ns, num] = await Promise.all([git(["diff", "--name-status", "-z", "-M", from, to], top), git(["diff", "--numstat", "-z", "-M", from, to], top)]);
  // name-status -z: STATUS\0path\0  or  Rxxx\0old\0new\0
  const statusByPath = new Map<string, { status: string; old: string | null }>();
  const a = ns.split("\0");
  for (let i = 0; i < a.length - 1; ) {
    const code = a[i]!;
    if (!code) break;
    const letter = code[0]!;
    if (letter === "R" || letter === "C") {
      statusByPath.set(a[i + 2]!, { status: STATUS[letter]!, old: a[i + 1]! });
      i += 3;
    } else {
      statusByPath.set(a[i + 1]!, { status: STATUS[letter] ?? letter, old: null });
      i += 2;
    }
  }
  // numstat -z: "add\tdel\tpath\0"  or  "add\tdel\t\0old\0new\0"
  const files: ChangedFile[] = [];
  let additions = 0;
  let deletions = 0;
  let total = 0;
  const b = num.split("\0");
  for (let i = 0; i < b.length; ) {
    const rec = b[i];
    if (!rec) break;
    const [ad, de, p] = rec.split("\t");
    let path = p ?? "";
    let old: string | null = null;
    if (path === "") {
      old = b[i + 1] ?? null;
      path = b[i + 2] ?? "";
      i += 3;
    } else i += 1;
    const binary = ad === "-" && de === "-";
    const add = binary ? null : Number(ad) || 0;
    const del = binary ? null : Number(de) || 0;
    additions += add ?? 0;
    deletions += del ?? 0;
    total++;
    if (files.length < MAX_FILES) {
      const st = statusByPath.get(path);
      files.push({ path, old_path: old ?? st?.old ?? null, status: st?.status ?? "modified", additions: add, deletions: del, binary });
    }
  }
  return { base_ref: baseRef, files, totals: { files: total, additions, deletions }, truncated: total > MAX_FILES };
}

/**
 * Validates a repo-relative path from the phone: relative, normalized, no `..`, no NUL,
 * and — resolving symlinks of the file or its nearest existing parent — inside the repo.
 */
export function safeRepoPath(top: string, p: string): string {
  const bad = () => new DomainError(400, "invalid_path", "path must be a file inside the repository");
  if (!p || p.length > 4096 || p.includes("\0") || isAbsolute(p) || p.startsWith("~")) throw bad();
  const norm = normalize(p);
  if (norm === "." || norm.startsWith("..") || norm.split(sep).includes("..") || norm.split(sep).includes(".git")) throw bad();
  const root = realpathSync(top);
  let probe = resolve(root, norm);
  // Deleted files don't exist any more: check the nearest existing ancestor instead.
  while (!existsSync(probe) && probe !== root) probe = dirname(probe);
  const real = realpathSync(probe);
  const rel = relative(root, real);
  if (rel.startsWith("..") || isAbsolute(rel)) throw bad();
  return norm.split(sep).join("/");
}

export const MAX_PATCH = 256 * 1024;
const SENSITIVE_FILE = /(^|\/)(\.env(\.[^/]*)?|\.npmrc|\.pypirc|\.netrc|credentials(\.[a-z]+)?|secrets?\.(ya?ml|json|toml)|id_(rsa|ecdsa|ed25519)|[^/]*\.(pem|key|p12|pfx))$/i;

/** Redacts a unified diff: known secret formats everywhere; every value in sensitive files. */
export function redactPatch(path: string, patch: string): string {
  const sensitive = SENSITIVE_FILE.test(path);
  return patch
    .split("\n")
    .map((line) => {
      if (/^(\+\+\+|---|@@|diff |index )/.test(line)) return line;
      if (sensitive && /^[+ -]/.test(line)) {
        const m = line.match(/^([+ -]\s*(?:export\s+)?[A-Za-z0-9_.-]+\s*[=:]\s*).+$/);
        return m ? `${m[1]}***` : `${line[0]}***`;
      }
      return redactCommandSecrets(line);
    })
    .join("\n");
}

export async function fileDiff(base: GitBase | null, cwd: string, path: string): Promise<{ path: string; patch: string; truncated: boolean; binary: boolean }> {
  const ends = await diffEnds(base, cwd);
  if (!ends) throw new DomainError(409, "not_a_repo", "the session's directory is not a git repository");
  const rel = safeRepoPath(ends.top, path);
  const num = await git(["diff", "--numstat", ends.from, ends.to, "--", rel], ends.top);
  const binary = /^-\t-\t/.test(num);
  if (binary) return { path: rel, patch: "", truncated: false, binary: true };
  let raw = await git(["diff", "--no-color", "--no-ext-diff", ends.from, ends.to, "--", rel], ends.top, { maxBuffer: 16 * 1024 * 1024 }).catch((err: { stdout?: string }) => {
    if (err.stdout) return err.stdout;
    throw err;
  });
  let truncated = false;
  raw = redactPatch(rel, raw);
  if (Buffer.byteLength(raw) > MAX_PATCH) {
    raw = Buffer.from(raw).subarray(0, MAX_PATCH - 64).toString("utf8").replace(/�+$/, "");
    raw = `${raw.slice(0, raw.lastIndexOf("\n") + 1)}… diff truncated …\n`;
    truncated = true;
  }
  return { path: rel, patch: raw, truncated, binary: false };
}

/** Summary numbers for a base (used for session/task summaries). */
export async function diffStat(base: GitBase | null, cwd: string): Promise<{ files: number; additions: number; deletions: number; changed: string[] } | null> {
  try {
    const cs = await changeSet(base, cwd);
    if (!cs) return null;
    return { files: cs.totals.files, additions: cs.totals.additions, deletions: cs.totals.deletions, changed: cs.files.slice(0, 200).map((f) => f.path) };
  } catch {
    return null;
  }
}

