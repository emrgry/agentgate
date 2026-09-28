import { existsSync, lstatSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline/promises";
import { findOurCommands } from "../claude-settings.ts";
import { agentgateHome } from "../config.ts";
import { EXIT } from "../exit-codes.ts";
import { layout, type Layout } from "../install-layout.ts";
import { mcpInstalledFiles, mcpUninstallFile } from "../mcp/install.ts";
import { c, log, out } from "../output.ts";
import { claudeInstalls, uninstallCommand, userSettingsPath } from "./install.ts";
import { cursorInstalls, hasOurCursorHook, uninstallCursorCommand, userCursorHooksPath } from "./install-cursor.ts";
import { codexInstalls, hasOurCodexHook, uninstallCodexCommand, userCodexHooksPath } from "./install-codex.ts";
import { isLaunchdPlatform, plistPath, serverDir, uninstallServerCommand } from "./setup.ts";

/**
 * `agentgate uninstall [--purge] [--yes] [--dry-run]` — remove AgentGate from this machine:
 *   1. Claude Code hooks from every settings file `agentgate install` wrote (+ the user file),
 *      and Cursor hooks from every hooks.json `agentgate install cursor` wrote (+ the user file),
 *      and Codex hooks + trust entries from every hooks.json `agentgate install codex` wrote (+ the user file),
 *   2. MCP servers wrapped by `agentgate mcp install` (originals restored),
 *   3. the launchd agent (bootout + plist),
 *   4. installed release files: versions/, current, previous, ~/.local/bin/agentgate.
 * Server data + config stay unless --purge. Hooks go first so no integration is left
 * pointing at a missing shim. Agents cannot run this (self-management guard).
 */

export const PATH_SHIM_MARKER = "# agentgate-path-shim";

export interface UninstallAllOptions {
  purge: boolean;
  yes: boolean;
  dryRun: boolean;
}

interface Step {
  label: string;
  run: () => void | number;
}

function userSettingsHasOurHooks(): boolean {
  try {
    return findOurCommands(JSON.parse(readFileSync(userSettingsPath(), "utf8"))).length > 0;
  } catch {
    return false;
  }
}

const lexists = (p: string) => {
  try {
    lstatSync(p);
    return true;
  } catch {
    return false;
  }
};

export function isOurPathShim(p: string): boolean {
  try {
    return lstatSync(p).isFile() && readFileSync(p, "utf8").includes(PATH_SHIM_MARKER);
  } catch {
    return false;
  }
}

export function planUninstall(o: UninstallAllOptions, l: Layout = layout()): Step[] {
  const steps: Step[] = [];
  const claude = claudeInstalls();
  let userDone = false;
  for (const i of claude) {
    if (i.scope === "user") {
      userDone = true;
      steps.push({ label: `remove Claude Code hooks from ${i.file}`, run: () => uninstallCommand({ agent: "claude-code", user: true }) });
    } else {
      const project = dirname(dirname(i.file));
      if (!existsSync(project)) {
        steps.push({ label: `skip ${i.file} (project directory no longer exists)`, run: () => undefined });
        continue;
      }
      steps.push({ label: `remove Claude Code hooks from ${i.file}`, run: () => uninstallCommand({ agent: "claude-code", project, user: false }) });
    }
  }
  if (!userDone && userSettingsHasOurHooks()) {
    steps.push({ label: `remove Claude Code hooks from ${userSettingsPath()}`, run: () => uninstallCommand({ agent: "claude-code", user: true }) });
  }
  let cursorUserDone = false;
  for (const i of cursorInstalls()) {
    if (i.scope === "user") {
      cursorUserDone = true;
      steps.push({ label: `remove Cursor hooks from ${i.file}`, run: () => uninstallCursorCommand({ user: true }) });
    } else if (!i.projectDir || !existsSync(i.projectDir)) {
      steps.push({ label: `skip ${i.file} (project directory no longer exists)`, run: () => undefined });
    } else {
      const project = i.projectDir;
      steps.push({ label: `remove Cursor hooks from ${i.file}`, run: () => uninstallCursorCommand({ project, user: false }) });
    }
  }
  if (!cursorUserDone && hasOurCursorHook(userCursorHooksPath())) {
    steps.push({ label: `remove Cursor hooks from ${userCursorHooksPath()}`, run: () => uninstallCursorCommand({ user: true }) });
  }
  let codexUserDone = false;
  for (const i of codexInstalls()) {
    if (i.scope === "user") {
      codexUserDone = true;
      steps.push({ label: `remove Codex hooks from ${i.file}`, run: () => uninstallCodexCommand({ user: true }) });
    } else if (!i.projectDir || !existsSync(i.projectDir)) {
      steps.push({ label: `skip ${i.file} (project directory no longer exists)`, run: () => undefined });
    } else {
      const project = i.projectDir;
      steps.push({ label: `remove Codex hooks from ${i.file}`, run: () => uninstallCodexCommand({ project, user: false }) });
    }
  }
  if (!codexUserDone && hasOurCodexHook(userCodexHooksPath())) {
    steps.push({ label: `remove Codex hooks from ${userCodexHooksPath()}`, run: () => uninstallCodexCommand({ user: true }) });
  }
  for (const m of mcpInstalledFiles()) {
    steps.push({ label: `restore MCP server(s) ${m.servers.join(", ") || "(none)"} in ${m.file} (${m.client})`, run: () => mcpUninstallFile(m.client, m.file) });
  }
  if (isLaunchdPlatform() && existsSync(plistPath())) {
    steps.push({ label: `stop and remove the launchd agent (${plistPath()})`, run: () => uninstallServerCommand({ purge: false }) });
  }
  if (l.kind === "release" && l.installHome) {
    const home = l.installHome;
    const shim = l.pathShim;
    if (isOurPathShim(shim)) steps.push({ label: `remove ${shim}`, run: () => rmSync(shim, { force: true }) });
    for (const n of ["current", "previous", "update.lock"]) {
      const p = join(home, n);
      if (lexists(p)) steps.push({ label: `remove ${p}`, run: () => rmSync(p, { force: true }) });
    }
    const versions = join(home, "versions");
    if (existsSync(versions)) steps.push({ label: `remove ${versions}`, run: () => rmSync(versions, { recursive: true, force: true }) });
  }
  if (o.purge) {
    const targets = [...new Set([agentgateHome(), ...(l.installHome ? [l.installHome] : [])])];
    for (const t of targets) {
      if (existsSync(t)) steps.push({ label: `DELETE ${t} (config, tokens, server data, identity key, audit log)`, run: () => rmSync(t, { recursive: true, force: true }) });
    }
  }
  return steps;
}

async function confirm(question: string): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    return /^y(es)?$/i.test((await rl.question(question)).trim());
  } finally {
    rl.close();
  }
}

export async function uninstallAllCommand(o: UninstallAllOptions): Promise<number> {
  const steps = planUninstall(o);
  out(c.bold(o.dryRun ? "agentgate uninstall would:" : "agentgate uninstall will:"));
  if (steps.length === 0) out("  (nothing to do)");
  for (const s of steps) out(`  - ${s.label}`);
  const l = layout();
  if (l.kind === "dev") out(c.dim(`  leave the development checkout ${l.root} in place (delete it yourself)`));
  if (!o.purge) out(c.dim(`  keep ${serverDir()} (data, identity key) and ${agentgateHome()} config — use --purge to delete them`));
  if (o.dryRun || steps.length === 0) return EXIT.OK;
  if (!o.yes) {
    if (!process.stdin.isTTY) {
      log.fail("refusing to uninstall without confirmation — re-run with --yes");
      return EXIT.USAGE;
    }
    if (!(await confirm("Proceed? [y/N] "))) {
      log.step("cancelled");
      return EXIT.OK;
    }
  }
  let failed = 0;
  for (const s of steps) {
    try {
      const r = s.run();
      if (typeof r === "number" && r !== EXIT.OK) failed++;
    } catch (err) {
      failed++;
      log.fail(`${s.label}: ${(err as Error).message}`);
    }
  }
  if (failed) {
    log.warn(`${failed} step(s) failed — see above`);
    return EXIT.ERROR;
  }
  log.ok("AgentGate was uninstalled");
  return EXIT.OK;
}
