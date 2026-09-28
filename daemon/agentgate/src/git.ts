import { execFileSync } from "node:child_process";
import { basename } from "node:path";

function git(cwd: string, args: string[]): string | undefined {
  try {
    const out = execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 2_000,
    }).trim();
    return out || undefined;
  } catch {
    return undefined;
  }
}

/** "owner/name" from a remote URL (https or scp-like ssh), else undefined. */
export function repoFromRemote(url: string): string | undefined {
  const m = url.trim().match(/[:/]([^/:]+\/[^/]+?)(?:\.git)?\/?$/);
  return m?.[1];
}

/** Best-effort repo/branch detection. Informational only (not part of the action hash). */
export function detectGit(cwd: string): { repo?: string; branch?: string; root?: string } {
  const top = git(cwd, ["rev-parse", "--show-toplevel"]);
  if (!top) return {};
  const remote = git(cwd, ["config", "--get", "remote.origin.url"]);
  const repo = (remote && repoFromRemote(remote)) ?? basename(top);
  let branch = git(cwd, ["rev-parse", "--abbrev-ref", "HEAD"]);
  if (branch === "HEAD") branch = git(cwd, ["rev-parse", "--short", "HEAD"]);
  return { repo, branch, root: top };
}
