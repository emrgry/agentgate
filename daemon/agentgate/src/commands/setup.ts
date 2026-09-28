import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, hostname, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { z } from "zod";
import { updateConfig } from "../auth-session.ts";
import { agentgateHome } from "../config.ts";
import { EXIT } from "../exit-codes.ts";
import { c, log, out } from "../output.ts";
import { loginCommand } from "./login.ts";
import { buildInstalledHookCommand, ourGroups } from "../claude-settings.ts";
import { hookShimPath } from "./run.ts";
import { pairCommand } from "./pair.ts";
import { layout } from "../install-layout.ts";

/**
 * M7 local-first: `agentgate setup` installs and starts the local AgentGate server
 * (API + PGlite under ~/.agentgate/server) as a launchd user agent, logs this machine's
 * agent in over loopback (no email), and prints the pairing QR. Idempotent.
 *
 * launchctl is behind an injectable runner (AGENTGATE_LAUNCHCTL) so tests never touch
 * the real launchd.
 *
 * Paths come from install-layout.ts: a dev checkout runs `node …/bin/agentgate.mjs serve`;
 * an installed release runs the stable `~/.agentgate/current/bin/agentgate serve`, so an
 * update only has to flip `current` and restart the agent.
 */

export const LABEL = "dev.agentgate.server";

export const serverDir = () => join(agentgateHome(), "server");
const serverJsonPath = () => join(serverDir(), "server.json");
export const logPath = () => join(serverDir(), "logs", "server.log");
export const plistPath = () => join(homedir(), "Library", "LaunchAgents", `${LABEL}.plist`);

/** PreToolUse (gating) + PostToolUse (reporting) for supervisor-run turns. */
export function managedHookSettings() {
  const command = buildInstalledHookCommand({ shimPath: hookShimPath(), nodePath: layout().node, home: agentgateHome() });
  const g = ourGroups(command);
  return { hooks: { PreToolUse: [g.PreToolUse], PostToolUse: [g.PostToolUse] } };
}

const ServerConfig = z.object({
  v: z.literal(1),
  port: z.number().int().min(1).max(65535),
  host: z.string(),
  owner_name: z.string(),
  machine_name: z.string(),
  require_device_signatures: z.boolean(),
  created_at: z.string(),
  /** The owner's shell PATH at setup time: managed turns run with it (launchd's PATH is minimal). */
  turn_path: z.string().optional(),
});
type ServerConfig = z.infer<typeof ServerConfig>;

export function readServerConfig(): ServerConfig | null {
  try {
    return ServerConfig.parse(JSON.parse(readFileSync(serverJsonPath(), "utf8")));
  } catch {
    return null;
  }
}

function ownerFullName(): string {
  if (process.platform === "darwin") {
    try {
      const n = execFileSync("id", ["-F"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 2000 }).trim();
      if (n) return n;
    } catch {
      /* fall through */
    }
  }
  return process.env.USER || userInfo().username || "Owner";
}

export function isLaunchdPlatform(): boolean {
  return (process.env.AGENTGATE_SETUP_PLATFORM ?? process.platform) === "darwin";
}

export function launchctl(args: string[]): { status: number; out: string } {
  const bin = process.env.AGENTGATE_LAUNCHCTL || "/bin/launchctl";
  const r = spawnSync(bin, args, { encoding: "utf8", timeout: 20_000 });
  return { status: r.status ?? 1, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}
export const domain = () => `gui/${process.getuid?.() ?? 501}`;
export const loaded = () => launchctl(["print", `${domain()}/${LABEL}`]).status === 0;

function xml(s: string) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function renderPlist(): string {
  const env: Record<string, string> = {
    AGENTGATE_HOME: agentgateHome(),
    PATH: `${dirname(layout().node)}:/usr/bin:/bin:/usr/sbin:/sbin`,
  };
  const args = layout().serveArgs;
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${args.map((a) => `    <string>${xml(a)}</string>`).join("\n")}
  </array>
  <key>EnvironmentVariables</key>
  <dict>
${Object.entries(env)
  .map(([k, v]) => `    <key>${k}</key><string>${xml(v)}</string>`)
  .join("\n")}
  </dict>
  <key>WorkingDirectory</key><string>${xml(serverDir())}</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Standard</string>
  <key>StandardOutPath</key><string>${xml(logPath())}</string>
  <key>StandardErrorPath</key><string>${xml(logPath())}</string>
</dict>
</plist>
`;
}

// First start compiles TypeScript (tsx) and initialises PGlite; allow a slow machine.
export async function waitHealthy(port: number, ms = 90_000): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/healthz`, { signal: AbortSignal.timeout(1_000) });
      if (r.ok) return true;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

export interface SetupOptions {
  port?: number;
  host?: string;
  start: boolean;
  pair: boolean;
}

export async function setupCommand(o: SetupOptions): Promise<number> {
  // 1. Server home (0700): data (PGlite), secrets (identity key, auth secret), logs.
  for (const d of [agentgateHome(), serverDir(), join(serverDir(), "data"), join(serverDir(), "secrets"), join(serverDir(), "logs")]) {
    mkdirSync(d, { recursive: true, mode: 0o700 });
    chmodSync(d, 0o700);
  }
  // 2. Server config: created once; flags may change port/host later.
  const prev = readServerConfig();
  const cfg: ServerConfig = {
    v: 1,
    port: o.port ?? prev?.port ?? 8787,
    host: o.host ?? prev?.host ?? "0.0.0.0",
    owner_name: prev?.owner_name ?? ownerFullName(),
    machine_name: prev?.machine_name ?? hostname().replace(/\.local$/, ""),
    // New installs accept only phone-signed approvals; an existing install keeps its choice.
    require_device_signatures: prev?.require_device_signatures ?? true,
    created_at: prev?.created_at ?? new Date().toISOString(),
    turn_path: process.env.PATH ?? prev?.turn_path,
  };
  writeFileSync(serverJsonPath(), `${JSON.stringify(cfg, null, 2)}\n`, { mode: 0o600 });
  log.ok(`${prev ? "server config kept" : "created"} ${serverDir()} ${c.dim(`(owner: ${cfg.owner_name}, port ${cfg.port})`)}`);

  // 3. Background service.
  if (!isLaunchdPlatform()) {
    log.warn("automatic background start is only implemented for macOS (launchd).");
    log.step(`Run the server yourself (e.g. in a systemd user service or tmux): ${c.bold(layout().serveArgs.join(" "))}`);
  } else {
    const plist = renderPlist();
    const path = plistPath();
    const changed = !existsSync(path) || readFileSync(path, "utf8") !== plist;
    mkdirSync(dirname(path), { recursive: true });
    if (!o.start) {
      if (changed) writeFileSync(path, plist, { mode: 0o644 });
      log.step(`launchd agent written (${path}); not started (--no-start)`);
    } else {
      const isLoaded = loaded();
      if (changed || !isLoaded) {
        if (isLoaded) launchctl(["bootout", `${domain()}/${LABEL}`]);
        writeFileSync(path, plist, { mode: 0o644 });
        const r = launchctl(["bootstrap", domain(), path]);
        if (r.status !== 0) {
          log.fail(`launchctl bootstrap failed: ${r.out.trim()}`);
          return EXIT.ERROR;
        }
        log.ok(`started launchd agent ${LABEL}`);
      } else {
        log.ok(`launchd agent ${LABEL} already running`);
      }
    }
  }
  if (!o.start) return EXIT.OK;

  // 4. Wait for the API, then log this machine's agent in over loopback (no email).
  const url = `http://127.0.0.1:${cfg.port}`;
  if (!(await waitHealthy(cfg.port))) {
    log.fail(`server did not become healthy on ${url} — see ${logPath()} (agentgate server logs)`);
    return EXIT.ERROR;
  }
  log.ok(`server healthy at ${url}`);
  const code = await loginCommand({ server: url, localFirst: true });
  if (code !== EXIT.OK) return code;
  if (cfg.require_device_signatures) {
    await updateConfig((c0) => ({ ...c0, require_device_signatures: true }));
  }

  // 5. Pairing QR (v2).
  if (!o.pair) return EXIT.OK;
  out("");
  return pairCommand({ qr: true });
}

/** `agentgate serve`: run the local-first API in the foreground (launchd runs this). */
export async function serveCommand(o: { port?: number; host?: string }): Promise<number> {
  const cfg = readServerConfig();
  if (!cfg) {
    log.fail("no local server configured — run `agentgate setup` first");
    return EXIT.ERROR;
  }
  const env: Record<string, string> = {
    AGENTGATE_MODE: "local",
    DATA_DIR: join(serverDir(), "data"),
    SECRETS_DIR: join(serverDir(), "secrets"),
    PORT: String(o.port ?? cfg.port),
    HOST: o.host ?? cfg.host,
    AGENTGATE_OWNER_NAME: cfg.owner_name,
    AGENTGATE_MACHINE_NAME: cfg.machine_name,
  };
  if (cfg.require_device_signatures) env.AGENTGATE_REQUIRE_DEVICE_SIGNATURES = "1";
  // Control Center: hook settings for managed turns (every tool call still goes through
  // the AgentGate PreToolUse hook → phone approvals) and the owner's PATH for `claude`.
  const hooksFile = join(serverDir(), "managed-hooks.json");
  writeFileSync(hooksFile, `${JSON.stringify(managedHookSettings(), null, 2)}\n`, { mode: 0o600 });
  env.AGENTGATE_MANAGED_HOOK_SETTINGS = hooksFile;
  if (cfg.turn_path) env.AGENTGATE_TURN_PATH = cfg.turn_path;
  for (const [k, v] of Object.entries(env)) process.env[k] ??= v;
  // The API owns its process from here (listen, signals, shutdown → process.exit).
  await import(pathToFileURL(layout().apiMain).href);
  return new Promise<number>(() => {});
}

export async function serverCommand(action: string | undefined, o: { follow: boolean }): Promise<number> {
  const cfg = readServerConfig();
  switch (action) {
    case "status": {
      out(`config      ${cfg ? serverJsonPath() : c.yellow("not set up (agentgate setup)")}`);
      if (isLaunchdPlatform()) out(`launchd     ${loaded() ? c.green(`${LABEL} loaded`) : c.yellow("not loaded")}`);
      if (cfg) {
        const ok = await waitHealthy(cfg.port, 1_500);
        out(`api         http://127.0.0.1:${cfg.port} ${ok ? c.green("healthy") : c.red("not responding")}`);
        out(`signatures  ${cfg.require_device_signatures ? "phone-signed approvals required" : "legacy server-signed approvals allowed"}`);
      }
      return EXIT.OK;
    }
    case "start": {
      if (!existsSync(plistPath())) {
        log.fail("not installed — run `agentgate setup`");
        return EXIT.ERROR;
      }
      const r = loaded() ? launchctl(["kickstart", "-k", `${domain()}/${LABEL}`]) : launchctl(["bootstrap", domain(), plistPath()]);
      if (r.status !== 0) log.fail(r.out.trim());
      else log.ok("server started");
      return r.status === 0 ? EXIT.OK : EXIT.ERROR;
    }
    case "stop": {
      const r = launchctl(["bootout", `${domain()}/${LABEL}`]);
      log.step(r.status === 0 ? "server stopped" : "server was not running");
      return EXIT.OK;
    }
    case "logs": {
      if (!existsSync(logPath())) {
        log.step("no log yet");
        return EXIT.OK;
      }
      const t = spawnSync("tail", o.follow ? ["-n", "100", "-f", logPath()] : ["-n", "100", logPath()], { stdio: "inherit" });
      return t.status ?? EXIT.OK;
    }
    default:
      log.fail("usage: agentgate server <start|stop|status|logs [-f]>");
      return EXIT.USAGE;
  }
}

/**
 * `agentgate restart`: (re)write the launchd plist for THIS installation and restart the
 * server. Used after `agentgate update` (run by the new version so its plist is current).
 */
export async function restartCommand(): Promise<number> {
  if (!isLaunchdPlatform()) {
    log.fail("restart is only implemented for macOS (launchd); restart `agentgate serve` yourself");
    return EXIT.ERROR;
  }
  const path = plistPath();
  if (!existsSync(path)) {
    log.fail("the local server is not installed — run `agentgate setup`");
    return EXIT.ERROR;
  }
  const plist = renderPlist();
  const changed = readFileSync(path, "utf8") !== plist;
  if (changed) writeFileSync(path, plist, { mode: 0o644 });
  let r;
  if (loaded() && !changed) r = launchctl(["kickstart", "-k", `${domain()}/${LABEL}`]);
  else {
    if (loaded()) launchctl(["bootout", `${domain()}/${LABEL}`]);
    r = launchctl(["bootstrap", domain(), path]);
  }
  if (r.status !== 0) {
    log.fail(`launchctl failed: ${r.out.trim()}`);
    return EXIT.ERROR;
  }
  const cfg = readServerConfig();
  if (cfg && !(await waitHealthy(cfg.port, 60_000))) {
    log.fail(`server did not become healthy — see ${logPath()} (agentgate server logs)`);
    return EXIT.ERROR;
  }
  log.ok(`server restarted${changed ? " (launchd agent updated)" : ""}`);
  return EXIT.OK;
}

export function uninstallServerCommand(o: { purge: boolean }): number {
  if (isLaunchdPlatform()) launchctl(["bootout", `${domain()}/${LABEL}`]);
  rmSync(plistPath(), { force: true });
  log.ok("launchd agent removed");
  if (o.purge) {
    rmSync(serverDir(), { recursive: true, force: true });
    log.ok(`deleted ${serverDir()} (data, identity key, secrets)`);
  } else {
    log.step(`data kept in ${serverDir()} (use --purge to delete it)`);
  }
  return EXIT.OK;
}
