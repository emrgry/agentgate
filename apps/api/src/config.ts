import { randomBytes } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { DatabaseTarget } from "./db/client.ts";

export interface Config {
  port: number;
  host: string;
  dataDir: string;
  database: DatabaseTarget;
  authSecret: string;
  /** Ed25519 private key (PKCS#8 PEM) from env, or null → load/generate under dataDir. */
  signingKeyPem: string | null;
  expoAccessToken: string | null;
  logLevel: string;
  sweepIntervalMs: number;
  /** CORS_ORIGINS, comma-separated. Unset → CORS disabled. */
  corsOrigins: string[];
  /** Where auth-secret + approval-signing-key.pem live (outside the repo, 0700). */
  secretsDir: string;
  /** AGENTGATE_ALLOW_REMOTE_AGENT_LOGIN=1: allow agent login from non-loopback addresses. */
  allowRemoteAgentLogin: boolean;
  /** AGENTGATE_DEV_OPEN_DEVICE_LOGIN=1: device login without a pairing code (tests only). */
  openDeviceLogin: boolean;
  /** PUBLIC_URL (or AGENTGATE_PUBLIC_URL): the URL phones/computers use (advertised to `agentgate pair`). */
  publicUrl: string | null;
  /** TRUSTED_PROXIES: comma-separated CIDRs whose X-Forwarded-For is trusted. Default none. */
  trustedProxies: string[];
  /** AGENTGATE_MODE=local: single owner, email-less login (M7 local-first). */
  mode: "dev" | "local";
  /** AGENTGATE_REQUIRE_DEVICE_SIGNATURES=1: approvals must be signed by a device key (v2). */
  requireDeviceSignatures: boolean;
  /** Local mode: owner display name / machine name shown on the phone. */
  ownerName: string | null;
  machineName: string | null;
}

/** ~/Library/Application Support/agentgate-api (macOS) or $XDG_CONFIG_HOME/agentgate-api. */
export function defaultSecretsDir(env: NodeJS.ProcessEnv = process.env): string {
  if (platform() === "darwin") return join(homedir(), "Library", "Application Support", "agentgate-api");
  return join(env.XDG_CONFIG_HOME || join(homedir(), ".config"), "agentgate-api");
}

const DEFAULT_DATA_DIR = resolve(fileURLToPath(new URL("../.data", import.meta.url)));

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  // All authentication here is the development flow (email login + pairing codes).
  if (env.NODE_ENV === "production" && env.AGENTGATE_I_UNDERSTAND_DEV_AUTH !== "1") {
    throw new Error("refusing to start: dev authentication is not allowed with NODE_ENV=production");
  }
  const dataDir = resolve(env.DATA_DIR ?? DEFAULT_DATA_DIR);
  const secretsDir = resolve(env.SECRETS_DIR ?? defaultSecretsDir(env));
  prepareDirs(dataDir, secretsDir);
  const port = Number(env.PORT ?? 8787);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`invalid PORT: ${env.PORT}`);
  return {
    port,
    host: env.HOST ?? "0.0.0.0",
    dataDir,
    database: env.DATABASE_URL
      ? { kind: "postgres", url: env.DATABASE_URL }
      : { kind: "pglite", dataDir: join(dataDir, "pglite") },
    authSecret: env.AUTH_SECRET ?? loadOrCreateSecret(secretsDir),
    signingKeyPem: env.APPROVAL_SIGNING_KEY_PEM ? env.APPROVAL_SIGNING_KEY_PEM.replace(/\\n/g, "\n") : null,
    expoAccessToken: env.EXPO_ACCESS_TOKEN ?? null,
    logLevel: env.LOG_LEVEL ?? "info",
    sweepIntervalMs: Number(env.SWEEP_INTERVAL_MS ?? 2000),
    corsOrigins: (env.CORS_ORIGINS ?? "").split(",").map((o) => o.trim()).filter(Boolean),
    secretsDir,
    allowRemoteAgentLogin: env.AGENTGATE_ALLOW_REMOTE_AGENT_LOGIN === "1",
    openDeviceLogin: env.AGENTGATE_DEV_OPEN_DEVICE_LOGIN === "1",
    publicUrl: (env.PUBLIC_URL || env.AGENTGATE_PUBLIC_URL)?.replace(/\/+$/, "") || null,
    trustedProxies: (env.TRUSTED_PROXIES ?? "").split(",").map((s) => s.trim()).filter(Boolean),
    mode: env.AGENTGATE_MODE === "local" ? "local" : "dev",
    requireDeviceSignatures: env.AGENTGATE_REQUIRE_DEVICE_SIGNATURES === "1",
    ownerName: env.AGENTGATE_OWNER_NAME?.trim() || null,
    machineName: env.AGENTGATE_MACHINE_NAME?.trim() || null,
  };
}

export const SECRET_FILES = ["auth-secret", "approval-signing-key.pem"] as const;

/**
 * 0700 data + secrets dirs, and a one-time move of secrets that older versions kept in
 * the repo tree (DATA_DIR) into SECRETS_DIR. Moving (not regenerating) keeps issued tokens
 * valid and daemons' pinned signing key unchanged.
 */
export function prepareDirs(dataDir: string, secretsDir: string): string[] {
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
  for (const d of [dataDir, secretsDir, join(dataDir, "pglite")]) {
    try {
      if (existsSync(d)) chmodSync(d, 0o700);
    } catch {
      /* best effort */
    }
  }
  const migrated: string[] = [];
  if (resolve(dataDir) === resolve(secretsDir)) return migrated;
  for (const name of SECRET_FILES) {
    const from = join(dataDir, name);
    const to = join(secretsDir, name);
    if (existsSync(from) && !existsSync(to)) {
      copyFileSync(from, to);
      chmodSync(to, 0o600);
      unlinkSync(from);
      migrated.push(name);
    }
  }
  return migrated;
}

/** Dev convenience: a random AUTH_SECRET persisted under SECRETS_DIR so tokens survive restarts. */
function loadOrCreateSecret(secretsDir: string): string {
  const file = join(secretsDir, "auth-secret");
  if (existsSync(file)) return readFileSync(file, "utf8").trim();
  const secret = randomBytes(32).toString("base64url");
  writeFileSync(file, secret, { mode: 0o600 });
  return secret;
}
