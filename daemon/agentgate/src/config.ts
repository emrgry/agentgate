import { randomUUID, createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { z } from "zod";

/** ~/.agentgate, or $AGENTGATE_HOME when set (tests, demos, multiple identities). */
export function agentgateHome(): string {
  const override = process.env.AGENTGATE_HOME;
  return override && override.trim() ? override : join(homedir(), ".agentgate");
}

export const paths = {
  config: () => join(agentgateHome(), "config.json"),
  policy: () => join(agentgateHome(), "policy.yaml"),
  nonces: () => join(agentgateHome(), "nonces"),
  approvals: () => join(agentgateHome(), "approvals"),
  configLock: () => join(agentgateHome(), "config.lock"),
  sessions: () => join(agentgateHome(), "sessions"),
  installs: () => join(agentgateHome(), "installs.json"),
  hookLog: () => join(agentgateHome(), "hook.log"),
};

export const DEFAULT_SERVER = "http://localhost:8787";
export const DEFAULT_EMAIL = "dev@agentgate.local";

export const Config = z.object({
  version: z.literal(1).default(1),
  server: z.string().url(),
  /** Stable per-installation id; survives logout so agent registration stays idempotent. */
  machine_id: z.string().min(1),
  email: z.string().optional(),
  user_id: z.string().optional(),
  access_token: z.string().optional(),
  token_expires_at: z.string().optional(),
  /** Rotating, single-use refresh token (POST /v1/auth/refresh). Secret — 0600 file. */
  refresh_token: z.string().optional(),
  /** Set by `agentgate setup`: accept only phone-signed (v2) approvals. */
  require_device_signatures: z.boolean().optional(),
  /** URL phones/other computers should use (put into `agentgate pair` QR codes). */
  public_url: z.string().url().optional(),
  /** Agent registered as type "claude-code" (installed hooks / run). */
  claude_agent_id: z.string().optional(),
  agent_id: z.string().optional(),
  agent_name: z.string().optional(),
  /**
   * Server approval-signing key, pinned at login (trust on first use). Approval
   * tokens are verified ONLY against this key, never against a freshly fetched one.
   */
  signing_key: z
    .object({
      kid: z.string(),
      alg: z.literal("Ed25519"),
      pem: z.string(),
      pinned_at: z.string(),
    })
    .optional(),
});
export type Config = z.infer<typeof Config>;

export function newMachineId(): string {
  return `mch_${randomUUID()}`;
}

/** Returns null when no config exists. Throws on a corrupt config (callers fail closed). */
export function loadConfig(): Config | null {
  const p = paths.config();
  if (!existsSync(p)) return null;
  const raw = readFileSync(p, "utf8");
  return Config.parse(JSON.parse(raw));
}

/** Atomic write (tmp + rename), directory 0700, file 0600. */
export function saveConfig(config: Config): void {
  const dir = agentgateHome();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const target = paths.config();
  const tmp = `${target}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(Config.parse(config), null, 2)}\n`, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, target);
}

/** Config for display: never prints the bearer token. */
export function redactedConfig(config: Config): Record<string, unknown> {
  return {
    ...config,
    access_token: config.access_token ? `[REDACTED …${config.access_token.slice(-4)}]` : undefined,
    refresh_token: config.refresh_token ? "[REDACTED]" : undefined,
    signing_key: config.signing_key
      ? { kid: config.signing_key.kid, alg: config.signing_key.alg, fingerprint: keyFingerprint(config.signing_key.pem), pinned_at: config.signing_key.pinned_at }
      : undefined,
  };
}

/** Short SHA-256 fingerprint of a PEM key, for humans. */
export function keyFingerprint(pem: string): string {
  const hex = createHash("sha256").update(pem.trim()).digest("hex");
  return `SHA256:${hex.slice(0, 16)}`;
}

export interface LoggedInConfig extends Config {
  access_token: string;
  agent_id: string;
  signing_key: NonNullable<Config["signing_key"]>;
}

export function isLoggedIn(c: Config | null): c is LoggedInConfig {
  return Boolean(c && c.access_token && c.agent_id && c.signing_key);
}

export function tokenExpired(c: Config, now = new Date()): boolean {
  if (!c.token_expires_at) return false;
  const t = Date.parse(c.token_expires_at);
  return Number.isFinite(t) && t <= now.getTime();
}
