import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { describeError } from "../authorize.ts";
import { AgentGateClient } from "../client/index.ts";
import { EXIT } from "../exit-codes.ts";
import { layout, RELEASE, type Layout } from "../install-layout.ts";
import { c, log, out } from "../output.ts";
import { isPlaceholderReleaseKey, RELEASE_PUBLIC_KEY } from "../release-key.ts";
import { requireLogin } from "../runtime.ts";
import { CLI_VERSION } from "../version.ts";
import {
  compareVersions,
  DEFAULT_RELEASE_BASE_URL,
  defaultFetcher,
  KEEP_OLD_VERSIONS,
  ReleaseStore,
  resolveRelease,
  UpdateError,
  type Extractor,
  type Fetcher,
} from "../updater.ts";
import { isLaunchdPlatform, plistPath, readServerConfig, waitHealthy } from "./setup.ts";

/**
 * `agentgate update [--check] [--version X] [--rollback] [--restart] [--prune]`
 *
 * Installed releases only. Downloads SHA256SUMS + SHA256SUMS.sig, REQUIRES a valid
 * signature by the pinned release key, downloads the tarball, checks it against the signed
 * checksum, extracts it into versions/<v>, flips `current` atomically (the old one becomes
 * `previous`) and keeps at most 2 old versions. The launchd server is restarted only when no
 * agent session is running; otherwise the user is told to restart later.
 */

export interface UpdateOptions {
  check: boolean;
  version?: string;
  rollback: boolean;
  restart: boolean;
  prune: boolean;
}

export type SessionProbe = { kind: "down" } | { kind: "idle" } | { kind: "busy"; count: number } | { kind: "unknown"; reason: string };

export interface UpdateEnv {
  layout: Layout;
  runningVersion: string;
  target: string;
  baseUrl: string;
  publicKey: string;
  fetch: Fetcher;
  extract?: Extractor;
  /** Is the launchd server installed on this machine? */
  serverInstalled: () => boolean;
  probeSessions: () => Promise<SessionProbe>;
  /** Restart via the (new) current version: `current/bin/agentgate restart`. */
  restart: () => number;
}

export function defaultUpdateEnv(): UpdateEnv {
  const l = layout();
  return {
    layout: l,
    runningVersion: RELEASE?.version ?? CLI_VERSION,
    target: RELEASE?.target ?? `${process.platform}-${process.arch}`,
    baseUrl: process.env.AGENTGATE_RELEASE_BASE_URL || DEFAULT_RELEASE_BASE_URL,
    publicKey: RELEASE_PUBLIC_KEY,
    fetch: defaultFetcher,
    serverInstalled: () => isLaunchdPlatform() && existsSync(plistPath()),
    probeSessions,
    restart: () => {
      const bin = join(l.installHome ?? l.stable, "current", "bin", "agentgate");
      const r = spawnSync(bin, ["restart"], { stdio: "inherit" });
      return r.status ?? EXIT.ERROR;
    },
  };
}

/** Are agent sessions running on the local server? Unknown → callers must not restart. */
export async function probeSessions(): Promise<SessionProbe> {
  const cfg = readServerConfig();
  if (!cfg) return { kind: "down" };
  if (!(await waitHealthy(cfg.port, 1_500))) return { kind: "down" };
  try {
    const config = await requireLogin();
    const client = new AgentGateClient({ server: config.server, accessToken: config.access_token, timeoutMs: 5_000 });
    const r = await client.agentSessions("active");
    const n = r.items.length;
    return n > 0 ? { kind: "busy", count: n } : { kind: "idle" };
  } catch (err) {
    return { kind: "unknown", reason: describeError(err) };
  }
}

export async function updateCommand(o: UpdateOptions, env: UpdateEnv = defaultUpdateEnv()): Promise<number> {
  const l = env.layout;
  if (l.kind !== "release" || !l.installHome) {
    log.fail(
      l.kind === "dev"
        ? "this is a development checkout — update it with `git pull && npm ci` (agentgate update manages installed releases)"
        : `this release is not installed under an AgentGate install directory (${l.root}) — reinstall with the one-line installer`,
    );
    return EXIT.ERROR;
  }
  const store = new ReleaseStore(l.installHome, env.extract);
  let unlock: (() => void) | null = null;
  try {
    unlock = store.lock();
    if (o.restart) return await maybeRestart(env, true);
    if (o.prune) {
      const removed = store.prune(KEEP_OLD_VERSIONS, [env.runningVersion]);
      log.ok(removed.length ? `removed old version(s): ${removed.join(", ")}` : "nothing to prune");
      return EXIT.OK;
    }
    if (o.rollback) {
      const r = store.rollback();
      log.ok(`rolled back ${c.bold(r.from)} → ${c.bold(r.to)}`);
      return await maybeRestart(env, false);
    }

    if (isPlaceholderReleaseKey(env.publicKey)) {
      log.fail("this build has no release signing key (development placeholder) — updates are disabled; reinstall with the one-line installer");
      return EXIT.BLOCKED;
    }
    const current = store.state().current ?? env.runningVersion;
    log.step(`checking ${o.version ? `release ${o.version}` : "the latest release"} for ${env.target}…`);
    const rel = await resolveRelease({ baseUrl: env.baseUrl, version: o.version, target: env.target, publicKey: env.publicKey, fetch: env.fetch });
    const cmp = compareVersions(rel.version, current);
    log.ok(`release ${c.bold(rel.version)} — signature verified`);

    if (o.check) {
      if (cmp > 0) out(`update available: ${current} → ${rel.version}   (run: agentgate update)`);
      else out(`up to date (${current})`);
      return EXIT.OK;
    }
    if (cmp === 0 && store.isComplete(rel.version)) {
      log.ok(`already on ${rel.version}`);
      return EXIT.OK;
    }
    if (cmp < 0 && !o.version) {
      log.ok(`installed ${current} is newer than the latest release (${rel.version}) — nothing to do`);
      return EXIT.OK;
    }
    if (cmp < 0) log.warn(`downgrading ${current} → ${rel.version} (explicit --version)`);

    log.step(`downloading ${rel.fileName}…`);
    const tarball = await env.fetch(`${rel.dir}/${rel.fileName}`);
    store.install(rel.version, tarball, rel.sha256);
    log.ok(`checksum verified; installed ${store.dirOf(rel.version)}`);
    const a = store.activate(rel.version);
    log.ok(`${c.bold("current")} → ${a.to}${a.from ? c.dim(` (previous: ${a.from}; undo with \`agentgate update --rollback\`)`) : ""}`);
    const removed = store.prune(KEEP_OLD_VERSIONS, [env.runningVersion]);
    if (removed.length) log.step(c.dim(`removed old version(s): ${removed.join(", ")}`));
    return await maybeRestart(env, false);
  } catch (err) {
    if (err instanceof UpdateError) {
      log.fail(err.message);
      return err.code === "signature" || err.code === "checksum" ? EXIT.BLOCKED : EXIT.ERROR;
    }
    throw err;
  } finally {
    unlock?.();
  }
}

async function maybeRestart(env: UpdateEnv, explicit: boolean): Promise<number> {
  if (!env.serverInstalled()) {
    if (explicit) log.step("the local server is not installed (agentgate setup) — nothing to restart");
    return EXIT.OK;
  }
  const p = await env.probeSessions();
  if (p.kind === "busy" || p.kind === "unknown") {
    const why = p.kind === "busy" ? `${p.count} agent session${p.count === 1 ? " is" : "s are"} running` : `cannot tell whether agent sessions are running (${p.reason})`;
    log.warn(`${why} — not restarting the server now; the new version is used by new hook calls immediately.`);
    log.step(`When they are done run ${c.bold("agentgate update --restart")} (or ${c.bold("agentgate restart")} to restart anyway).`);
    return EXIT.OK;
  }
  log.step("restarting the local server…");
  return env.restart();
}
