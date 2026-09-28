import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { acquireLock, updateConfig } from "./auth-session.ts";
import type { AgentGateClient } from "./client/index.ts";
import { paths, type LoggedInConfig } from "./config.ts";
import { log } from "./output.ts";

/**
 * Hook-managed sessions: when Claude Code runs without `agentgate run` (installed hook:
 * desktop app, IDE, plain `claude`), each Claude `session_id` is mapped to an AgentGate
 * session, created on first use and persisted at $AGENTGATE_HOME/sessions/<id>.json (0600).
 *
 * Parallel hooks of one Claude session race to create it; creation is serialized with an
 * O_EXCL lock file per Claude session and the mapping is re-read after taking the lock,
 * so exactly one AgentGate session is created. A mapping is only reused if it belongs to
 * the same server + user; if the server says the session is gone/ended, the caller asks
 * for a replacement (compare-and-swap on the stale id, again under the lock).
 */

const Mapping = z.object({
  v: z.literal(1),
  claude_session_id: z.string(),
  session_id: z.string(),
  agent_id: z.string(),
  server: z.string(),
  user_id: z.string().optional(),
  created_at: z.string(),
});
type Mapping = z.infer<typeof Mapping>;

function fileStem(claudeSessionId: string): string {
  return /^[A-Za-z0-9_-]{1,128}$/.test(claudeSessionId)
    ? claudeSessionId
    : `h_${createHash("sha256").update(claudeSessionId).digest("hex").slice(0, 40)}`;
}
const mappingPath = (cs: string) => join(paths.sessions(), `${fileStem(cs)}.json`);
const lockPath = (cs: string) => join(paths.sessions(), `${fileStem(cs)}.lock`);

export function readMapping(claudeSessionId: string): Mapping | null {
  try {
    return Mapping.parse(JSON.parse(readFileSync(mappingPath(claudeSessionId), "utf8")));
  } catch {
    return null;
  }
}

function usable(m: Mapping | null, config: LoggedInConfig): m is Mapping {
  return Boolean(m && m.server === config.server && (!m.user_id || !config.user_id || m.user_id === config.user_id));
}

function writeMapping(m: Mapping) {
  mkdirSync(paths.sessions(), { recursive: true, mode: 0o700 });
  const target = mappingPath(m.claude_session_id);
  const tmp = `${target}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(tmp, JSON.stringify(m), { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, target);
}

/** The "claude-code" agent id, registering (idempotently) and caching it on first use. */
export async function claudeAgentId(client: AgentGateClient, config: LoggedInConfig): Promise<string> {
  if (config.claude_agent_id) return config.claude_agent_id;
  const agent = await client.registerAgent({ name: hostname(), type: "claude-code", machine_id: config.machine_id });
  await updateConfig((c) => ({ ...c, claude_agent_id: agent.id }));
  return agent.id;
}

async function createMapped(client: AgentGateClient, config: LoggedInConfig, claudeSessionId: string): Promise<Mapping> {
  const agentId = await claudeAgentId(client, config);
  const session = await client.createSession(agentId);
  const m: Mapping = {
    v: 1,
    claude_session_id: claudeSessionId,
    session_id: session.id,
    agent_id: agentId,
    server: config.server,
    ...(config.user_id ? { user_id: config.user_id } : {}),
    created_at: new Date().toISOString(),
  };
  writeMapping(m);
  log.step(`hook session: Claude ${claudeSessionId} → AgentGate ${session.id}`);
  return m;
}

async function withLock<T>(claudeSessionId: string, fn: () => Promise<T>): Promise<T> {
  mkdirSync(paths.sessions(), { recursive: true, mode: 0o700 });
  const release = await acquireLock(lockPath(claudeSessionId), 20_000);
  try {
    return await fn();
  } finally {
    release();
  }
}

/** AgentGate session for a Claude session; created exactly once even under parallel hooks. */
export async function resolveHookSession(client: AgentGateClient, config: LoggedInConfig, claudeSessionId: string): Promise<string> {
  const fast = readMapping(claudeSessionId);
  if (usable(fast, config)) return fast.session_id;
  return withLock(claudeSessionId, async () => {
    const again = readMapping(claudeSessionId); // re-read: another hook may have just created it
    if (usable(again, config)) return again.session_id;
    return (await createMapped(client, config, claudeSessionId)).session_id;
  });
}

/** Replace a mapping whose session the server reported as ended/unknown (CAS on the stale id). */
export async function replaceHookSession(
  client: AgentGateClient,
  config: LoggedInConfig,
  claudeSessionId: string,
  staleSessionId: string,
): Promise<string> {
  return withLock(claudeSessionId, async () => {
    const cur = readMapping(claudeSessionId);
    if (usable(cur, config) && cur.session_id !== staleSessionId) return cur.session_id; // already replaced
    return (await createMapped(client, config, claudeSessionId)).session_id;
  });
}

/** Removes and returns the mapping (SessionEnd). */
export function forgetHookSession(claudeSessionId: string): Mapping | null {
  const m = readMapping(claudeSessionId);
  try {
    unlinkSync(mappingPath(claudeSessionId));
  } catch {
    /* gone */
  }
  return m;
}
