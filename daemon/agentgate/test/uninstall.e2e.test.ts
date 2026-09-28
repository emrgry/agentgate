/**
 * `agentgate uninstall` (full) in a temp HOME: removes Claude Code hooks (project + user),
 * restores MCP wraps and removes the launchd agent (fake launchctl), keeps server data
 * unless --purge. --dry-run changes nothing; no --yes without a TTY refuses.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { FakeServer } from "./fake-server.ts";
import { makeEnv, runCli } from "./helpers.ts";

const FAKE_LAUNCHCTL = join(dirname(fileURLToPath(import.meta.url)), "fake-launchctl.mjs");
const MARKER = "--agentgate-install=claude-code/v1";

let server: FakeServer | null = null;
afterEach(async () => {
  await server?.stop();
  server = null;
});

async function prepared() {
  server = await new FakeServer({}).start();
  const e = makeEnv({ server: server.url, token: server.token, publicKeyPem: server.keys.publicKeyPem });
  const root = dirname(e.home);
  const userHome = join(root, "userhome");
  const project = join(root, "project");
  mkdirSync(userHome, { recursive: true });
  mkdirSync(project, { recursive: true });
  const env = {
    HOME: userHome,
    AGENTGATE_LAUNCHCTL: FAKE_LAUNCHCTL,
    AGENTGATE_SETUP_PLATFORM: "darwin",
    FAKE_LAUNCHD_DIR: join(root, "launchd"),
  };
  const cli = (args: string[], cwd = project) => runCli(args, { home: e.home, cwd, env });

  // Claude Code: one project install + one user install.
  expect((await cli(["install", "claude-code", "--project", project])).code).toBe(0);
  const otherProject = join(root, "other");
  mkdirSync(otherProject);
  // (a second scope is refused while a project install exists, so install user-level from elsewhere)
  expect((await cli(["install", "claude-code", "--user", "--yes"], otherProject)).code).toBe(0);
  // MCP: wrap a stdio server in the project's .mcp.json.
  const mcpOriginal = `${JSON.stringify({ mcpServers: { demo: { command: "npx", args: ["-y", "demo-mcp"] } } }, null, 2)}\n`;
  writeFileSync(join(project, ".mcp.json"), mcpOriginal);
  expect((await cli(["mcp", "install", "--client", "claude-code", "--project", project, "--all"])).code).toBe(0);
  // launchd agent + server config (not started).
  expect((await cli(["setup", "--no-start"])).code).toBe(0);
  const plist = join(userHome, "Library", "LaunchAgents", "dev.agentgate.server.plist");
  expect(existsSync(plist)).toBe(true);
  return { e, root, userHome, project, cli, plist, mcpOriginal };
}

const hasOurHooks = (file: string) => existsSync(file) && readFileSync(file, "utf8").includes(MARKER);

describe("agentgate uninstall", () => {
  it("--dry-run lists every step and changes nothing", async () => {
    const t = await prepared();
    const r = await t.cli(["uninstall", "--dry-run"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("agentgate uninstall would:");
    expect(r.stdout).toContain(join(t.project, ".claude", "settings.local.json"));
    expect(r.stdout).toContain(join(t.userHome, ".claude", "settings.json"));
    expect(r.stdout).toContain(`restore MCP server(s) demo in ${join(t.project, ".mcp.json")}`);
    expect(r.stdout).toContain("stop and remove the launchd agent");
    expect(r.stdout).toContain("leave the development checkout");
    expect(hasOurHooks(join(t.project, ".claude", "settings.local.json"))).toBe(true);
    expect(hasOurHooks(join(t.userHome, ".claude", "settings.json"))).toBe(true);
    expect(readFileSync(join(t.project, ".mcp.json"), "utf8")).toContain("AGENTGATE_MCP_WRAPPED");
    expect(existsSync(t.plist)).toBe(true);
  });

  it("refuses without --yes when not interactive", async () => {
    const t = await prepared();
    const r = await t.cli(["uninstall"]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/--yes/);
    expect(existsSync(t.plist)).toBe(true);
  });

  it("--yes removes hooks, MCP wraps and the launchd agent; keeps data", async () => {
    const t = await prepared();
    const r = await t.cli(["uninstall", "--yes"]);
    expect(r.code, r.stderr).toBe(0);
    expect(hasOurHooks(join(t.project, ".claude", "settings.local.json"))).toBe(false);
    expect(hasOurHooks(join(t.userHome, ".claude", "settings.json"))).toBe(false);
    expect(readFileSync(join(t.project, ".mcp.json"), "utf8")).toBe(t.mcpOriginal);
    expect(existsSync(t.plist)).toBe(false);
    expect(readFileSync(join(t.root, "launchd", "calls.log"), "utf8")).toMatch(/^bootout gui\/\d+\/dev\.agentgate\.server$/m);
    expect(existsSync(join(t.e.home, "server", "server.json"))).toBe(true);
    expect(existsSync(join(t.e.home, "config.json"))).toBe(true);
    // Idempotent.
    const again = await t.cli(["uninstall", "--yes"]);
    expect(again.code).toBe(0);
    expect(again.stdout).toContain("(nothing to do)");
  });

  it("--purge also deletes AGENTGATE_HOME", async () => {
    const t = await prepared();
    expect((await t.cli(["uninstall", "--purge", "--yes"])).code).toBe(0);
    expect(existsSync(t.e.home)).toBe(false);
  });

  it("integration-specific uninstall still works and rejects full-uninstall flags", async () => {
    const t = await prepared();
    expect((await t.cli(["uninstall", "claude-code", "--project", t.project])).code).toBe(0);
    expect(hasOurHooks(join(t.project, ".claude", "settings.local.json"))).toBe(false);
    expect((await t.cli(["uninstall", "claude-code", "--yes"])).code).toBe(2);
    expect((await t.cli(["uninstall", "--user"])).code).toBe(2);
  });
});
