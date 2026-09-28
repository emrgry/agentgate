import { closeSync, linkSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from "node:fs";
import { mkdirSync } from "node:fs";
import { ApiRequestError, AgentGateClient } from "./client/index.ts";
import { agentgateHome, isLoggedIn, loadConfig, paths, saveConfig, type LoggedInConfig } from "./config.ts";
import { log } from "./output.ts";

/**
 * Access-token lifecycle for long-lived callers (installed hooks run for days; agent
 * access tokens live 1 h).
 *
 * `requireLogin()` returns a config whose access token is valid for at least
 * REFRESH_MARGIN_MS, refreshing it with the rotating refresh token if needed.
 * Refresh is serialized across processes with an O_EXCL lock file (parallel Claude hooks),
 * and the config is re-read after taking the lock: whoever refreshed first wins, the rest
 * reuse its result instead of double-rotating (which the server would treat as token
 * reuse and revoke the family). If a rotation still races (e.g. a concurrent login), we
 * re-read and retry once. Any other failure → throw (callers fail closed).
 */

export const REFRESH_MARGIN_MS = 5 * 60_000;
const LOCK_TIMEOUT_MS = 15_000;
const LOCK_STALE_MS = 30_000;

export class LoginRequiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LoginRequiredError";
  }
}

function msLeft(c: { token_expires_at?: string }, now = Date.now()): number {
  if (!c.token_expires_at) return Number.POSITIVE_INFINITY;
  const t = Date.parse(c.token_expires_at);
  return Number.isFinite(t) ? t - now : Number.NEGATIVE_INFINITY;
}

export function needsRefresh(c: { token_expires_at?: string }, now = Date.now()): boolean {
  return msLeft(c, now) < REFRESH_MARGIN_MS;
}

export async function requireLogin(): Promise<LoggedInConfig> {
  const cfg = loadConfig();
  if (!isLoggedIn(cfg)) throw new LoginRequiredError("not logged in — run `agentgate login` first");
  if (!needsRefresh(cfg)) return cfg;
  if (!cfg.refresh_token) {
    if (msLeft(cfg) > 0) return cfg;
    throw new LoginRequiredError("access token expired (no refresh token) — run `agentgate login` again");
  }
  return refreshLocked();
}

async function refreshLocked(): Promise<LoggedInConfig> {
  const release = await acquireLock(paths.configLock());
  try {
    const first = loadConfig();
    if (!isLoggedIn(first)) throw new LoginRequiredError("not logged in — run `agentgate login` first");
    if (!needsRefresh(first)) return first; // someone else refreshed while we waited
    let cur: LoggedInConfig = first;
    let lastErr: unknown = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      if (!cur.refresh_token) break;
      const presented = cur.refresh_token;
      try {
        const client = new AgentGateClient({ server: cur.server, debug: log.debug });
        const r = await client.refresh(presented);
        const next: LoggedInConfig = { ...cur, access_token: r.access_token, token_expires_at: r.expires_at, refresh_token: r.refresh_token };
        saveConfig(next);
        log.debug(`access token refreshed (expires ${r.expires_at})`);
        return next;
      } catch (err) {
        lastErr = err;
        // Rotation race (e.g. a login or an unlocked writer changed the config): re-read, retry once.
        const reread = loadConfig();
        if (isLoggedIn(reread) && reread.refresh_token && reread.refresh_token !== presented) {
          if (!needsRefresh(reread)) return reread;
          cur = reread;
          continue;
        }
        break;
      }
    }
    // Refresh failed. A still-valid (if soon-expiring) token is usable; an expired one is not.
    if (msLeft(cur) > 0 && !(lastErr instanceof ApiRequestError && lastErr.status === 401)) {
      log.warn(`token refresh failed (${(lastErr as Error)?.message}); using the current token until it expires`);
      return cur;
    }
    const why =
      lastErr instanceof ApiRequestError && lastErr.code ? lastErr.code : lastErr instanceof Error ? lastErr.message : "no refresh token";
    throw new LoginRequiredError(`access token expired and refresh failed (${why}) — run \`agentgate login\``);
  } finally {
    release();
  }
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM"; // exists, not ours
  }
}

/**
 * Atomically take a stale lock out of the way. rename() moves whatever is at `path`
 * right now; if that turns out not to be the stale lock we inspected (another process
 * reclaimed it and took a fresh lock in between), put it back with link() (fails if a
 * new lock already exists — then the new owner keeps it) and report failure.
 */
function reclaim(path: string, staleContent: string): boolean {
  const aside = `${path}.stale.${process.pid}.${Math.random().toString(36).slice(2)}`;
  try {
    renameSync(path, aside);
  } catch {
    return false;
  }
  let moved = "";
  try {
    moved = readFileSync(aside, "utf8");
  } catch {
    /* ignore */
  }
  if (moved !== staleContent) {
    try {
      linkSync(aside, path);
    } catch {
      /* someone holds a newer lock; theirs wins */
    }
    try {
      unlinkSync(aside);
    } catch {
      /* ignore */
    }
    return false;
  }
  try {
    unlinkSync(aside);
  } catch {
    /* ignore */
  }
  return true;
}

/** O_EXCL lock file with stale-lock recovery. Returns a release function. */
export async function acquireLock(path: string, timeoutMs = LOCK_TIMEOUT_MS): Promise<() => void> {
  mkdirSync(agentgateHome(), { recursive: true, mode: 0o700 });
  const token = `${process.pid}:${Date.now()}:${Math.random()}`;
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const fd = openSync(path, "wx", 0o600);
      writeSync(fd, token);
      closeSync(fd);
      return () => {
        try {
          if (readFileSync(path, "utf8") === token) unlinkSync(path);
        } catch {
          /* already gone */
        }
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      let content = "";
      let ageMs = 0;
      try {
        content = readFileSync(path, "utf8");
        ageMs = Date.now() - statSync(path).mtimeMs;
      } catch {
        continue; // vanished between checks
      }
      const owner = Number(content.split(":")[0]);
      const ownerDead = content !== "" && Number.isInteger(owner) && owner > 0 && !pidAlive(owner);
      // An empty lock may be mid-write by a live owner; only reclaim it once old.
      if ((ownerDead || ageMs > LOCK_STALE_MS || (content === "" && ageMs > 2_000)) && reclaim(path, content)) continue;
      if (Date.now() > deadline) throw new Error(`timed out waiting for ${path}`);
      await new Promise((r) => setTimeout(r, 25 + Math.random() * 50));
    }
  }
}

/**
 * Read-modify-write of config.json under the config lock. Every writer other than the
 * refresher must use this, or it could overwrite a freshly rotated refresh token with a
 * stale one (the next refresh would then look like token reuse and revoke the family).
 */
export async function updateConfig(mutate: (c: LoggedInConfig) => LoggedInConfig): Promise<LoggedInConfig> {
  const release = await acquireLock(paths.configLock());
  try {
    const cur = loadConfig();
    if (!isLoggedIn(cur)) throw new LoginRequiredError("not logged in — run `agentgate login` first");
    const next = mutate(cur);
    saveConfig(next);
    return next;
  } finally {
    release();
  }
}
