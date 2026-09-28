import { existsSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { claudeCodeProvider } from "@agentgate/adapter-claude-code";
import { codexProvider } from "@agentgate/adapter-codex";
import { BUILTIN_PROFILES_DIR, genericProvider, loadProfiles, prepareGenericHome } from "@agentgate/adapter-generic";
import type { AgentProvider } from "@agentgate/adapters";
import { managedHookCommand, prepareCodexHome } from "./control/provider-homes.ts";
import type { SupervisorOptions } from "./control/supervisor.ts";
import { buildApp } from "./app.ts";
import { loadConfig } from "./config.ts";
import { openDatabase } from "./db/client.ts";
import { loadSigner } from "./keys.ts";
import { ExpoPushSender } from "./push/expo.ts";

const config = loadConfig();
const database = await openDatabase(config.database);
const signer = loadSigner({ envPem: config.signingKeyPem, dataDir: config.secretsDir });

// Control Center (local-first only): managed Claude Code sessions run by the supervisor.
// Refuse to enable it without the AgentGate hook settings — managed turns must stay gated.
let control: SupervisorOptions | undefined;
if (config.mode === "local") {
  const hooks = process.env.AGENTGATE_MANAGED_HOOK_SETTINGS;
  if (hooks && existsSync(hooks)) {
    const home = homedir();
    const claudeBin =
      process.env.AGENTGATE_CLAUDE_BIN || [join(home, ".local", "bin", "claude"), "/opt/homebrew/bin/claude", "/usr/local/bin/claude"].find((p) => existsSync(p)) || "claude";
    const turnPath = [process.env.AGENTGATE_TURN_PATH, join(home, ".local", "bin"), dirname(process.execPath), "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
      .filter(Boolean)
      .join(":");
    const split = (v: string | undefined) => (v ?? "").split(/\s+/).filter(Boolean);
    // Per-session provider homes (CODEX_HOME / HERMES_HOME copies with the AgentGate hook).
    const homesDir = join(dirname(hooks), "provider-homes");
    const providers: Record<string, AgentProvider> = {
      // AGENTGATE_CLAUDE_ARGS: extra args (e.g. "--model sonnet"); permission-bypass flags are dropped by the provider.
      "claude-code": claudeCodeProvider({ binary: claudeBin, extraArgs: split(process.env.AGENTGATE_CLAUDE_ARGS) }),
      // Codex: gated by a PreToolUse hook in a per-session CODEX_HOME + the supervisor tripwire.
      codex: codexProvider({
        binary: process.env.AGENTGATE_CODEX_BIN || "codex",
        extraArgs: split(process.env.AGENTGATE_CODEX_ARGS),
        minVersion: process.env.AGENTGATE_CODEX_MIN_VERSION || "0.40.0",
        codexHome: (sessionId) =>
          prepareCodexHome({ baseDir: homesDir, sessionId, ownerCodexHome: process.env.CODEX_HOME || join(home, ".codex"), hookCommand: managedHookCommand(hooks) }),
      }),
    };
    // providers.yaml: built-in profiles (Hermes) + ~/.agentgate/providers/*.yaml (user overrides by id).
    const agHome = process.env.AGENTGATE_HOME || join(home, ".agentgate");
    const loaded = loadProfiles([BUILTIN_PROFILES_DIR, join(agHome, "providers")]);
    for (const e of loaded.errors) console.warn(`provider profile ignored: ${e.error}`);
    for (const p of loaded.profiles) {
      if (p.id in providers) {
        console.warn(`provider profile '${p.id}' ignored: the id is reserved`);
        continue;
      }
      providers[p.id] = genericProvider(p, {
        prepareHome: (profile, sessionId) =>
          prepareGenericHome(profile, {
            baseDir: homesDir,
            sessionId,
            // prepareGenericHome pins AGENTGATE_GATE_RECEIPTS in front of this command.
            hookCommand: `AGENTGATE_CONTROL_SESSION=${sessionId} ${managedHookCommand(hooks)} --agentgate-provider=${profile.id}`,
          }),
      });
    }
    control = {
      providers,
      hookSettingsPath: () => hooks,
      // Verified: Claude Code's credential lookup fails ("Not logged in") without USER/LOGNAME,
      // which a launchd user agent may not provide.
      maxConcurrentTurns: Math.max(1, Number(process.env.AGENTGATE_MAX_CONCURRENT_TURNS) || 4),
      // Phase 3/4: "stuck" after N minutes without events; open_pr uses the owner's policy too.
      autoContinueBackground: process.env.AGENTGATE_AUTO_CONTINUE_BACKGROUND !== "0",
      stuckAfterMs: Math.max(1, Number(process.env.AGENTGATE_STUCK_MINUTES) || 10) * 60_000,
      policyPath: () => join(agHome, "policy.yaml"),
      turnEnv: () => {
        const u = userInfo();
        return { ...process.env, HOME: home, PATH: turnPath, USER: process.env.USER || u.username, LOGNAME: process.env.LOGNAME || u.username, SHELL: process.env.SHELL || u.shell || "/bin/zsh" };
      },
    };
  } else {
    console.warn("Control Center disabled: AGENTGATE_MANAGED_HOOK_SETTINGS missing (start the server with `agentgate serve`)");
  }
}

const { app, startBackgroundJobs } = await buildApp({
  db: database.db,
  signer,
  authSecret: config.authSecret,
  logLevel: config.logLevel,
  sweepIntervalMs: config.sweepIntervalMs,
  corsOrigins: config.corsOrigins,
  auth: { allowRemoteAgentLogin: config.allowRemoteAgentLogin, openDeviceLogin: config.openDeviceLogin },
  publicUrl: config.publicUrl,
  trustedProxies: config.trustedProxies,
  ...(control ? { control } : {}),
  mode: config.mode,
  requireDeviceSignatures: config.requireDeviceSignatures,
  ...(config.ownerName ? { ownerName: config.ownerName } : {}),
  ...(config.machineName ? { machineName: config.machineName } : {}),
  push: (logger) => new ExpoPushSender(logger, config.expoAccessToken),
});

startBackgroundJobs();
await app.listen({ port: config.port, host: config.host });
app.log.info(
  {
    driver: database.driver,
    dataDir: database.driver === "pglite" ? config.dataDir : undefined,
    kid: signer.kid,
  },
  "agentgate api ready",
);
if (config.host === "0.0.0.0" || config.host === "::") {
  app.log.warn(
    { host: config.host },
    "listening on ALL interfaces (needed for a phone on the LAN). Anyone on this network can reach the API; agent login is loopback-only and device login requires a pairing code. Set HOST=127.0.0.1 if you don't need LAN access.",
  );
}
if (config.openDeviceLogin) app.log.warn("AGENTGATE_DEV_OPEN_DEVICE_LOGIN=1: devices can log in WITHOUT pairing — tests only");
if (config.allowRemoteAgentLogin) app.log.warn("AGENTGATE_ALLOW_REMOTE_AGENT_LOGIN=1: agent login accepted from non-loopback addresses");

let shuttingDown = false;
for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => {
    if (shuttingDown) return;
    shuttingDown = true;
    app.log.info({ sig }, "shutting down");
    app
      .close()
      .then(() => database.close())
      .then(() => process.exit(0))
      .catch((err: unknown) => {
        app.log.error({ err }, "shutdown failed");
        process.exit(1);
      });
  });
}
