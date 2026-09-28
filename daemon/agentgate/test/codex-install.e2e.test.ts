import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { codexTrustEntries, TRUST_BEGIN, TRUST_END } from "../src/codex-hooks.ts";
import { FakeServer } from "./fake-server.ts";
import { makeEnv, runCli } from "./helpers.ts";

/**
 * `agentgate install codex` / `uninstall codex` / full `uninstall` in a temp HOME with a fake
 * ~/.codex — never the real one. Byte-exact restore, idempotency, trust entries, refusals.
 */

const T = 30_000;
const MARKER = "--agentgate-install=codex/v1";

let server: FakeServer | null = null;
afterEach(async () => {
  await server?.stop();
  server = null;
});

async function setup() {
  server = await new FakeServer({}).start();
  const e = makeEnv({ server: server.url, token: server.token, publicKeyPem: server.keys.publicKeyPem });
  const root = dirname(e.home);
  const userHome = join(root, "userhome");
  const codex = join(userHome, ".codex");
  const project = join(root, "project");
  mkdirSync(codex, { recursive: true });
  mkdirSync(project, { recursive: true });
  const env = { HOME: userHome, CODEX_HOME: "", AGENTGATE_CODEX_BIN: "/nonexistent/codex" };
  const cli = (args: string[], o: { cwd?: string; env?: Record<string, string> } = {}) => runCli(args, { home: e.home, cwd: o.cwd ?? project, env: { ...env, ...o.env } });
  return { ...e, root, userHome, codex, project, cli, hooks: join(codex, "hooks.json"), config: join(codex, "config.toml") };
}

const read = (p: string) => readFileSync(p, "utf8");
const json = (p: string) => JSON.parse(read(p));
const ours = (doc: any): string[] =>
  Object.values(doc.hooks ?? {}).flatMap((groups: any) => groups.flatMap((g: any) => (g.hooks ?? []).map((h: any) => h.command)).filter((c: string) => c.includes(MARKER)));

const USER_HOOKS = `{
    "description": "my hooks",
    "hooks": {
        "PreToolUse": [
            { "matcher": "Bash", "hooks": [ { "type": "command", "command": "python3 ~/.codex/hooks/check.py" } ] }
        ]
    }
}
`;
const USER_CONFIG = `model = "gpt-5.5"
approval_policy = "on-request"

[mcp_servers.docs]
command = "npx"
args = ["-y", "docs-mcp"]
`;

describe("agentgate install codex --user", () => {
  it("refuses without --yes and touches nothing", async () => {
    const t = await setup();
    const r = await t.cli(["install", "codex", "--user"]);
    expect(r.code).toBe(2); // EXIT.USAGE
    expect(r.stderr).toMatch(/refusing without --yes/);
    expect(existsSync(t.hooks)).toBe(false);
    expect(existsSync(t.config)).toBe(false);
  }, T);

  it("merges into existing hooks.json + config.toml, backs up, is idempotent, uninstall restores both byte-exact", async () => {
    const t = await setup();
    writeFileSync(t.hooks, USER_HOOKS);
    writeFileSync(t.config, USER_CONFIG);

    const r = await t.cli(["install", "codex", "--user", "--yes"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stderr).toMatch(/hook trusted for Codex/);
    expect(r.stderr).toMatch(/1 other PreToolUse hook/);
    const doc = json(t.hooks);
    expect(doc.description).toBe("my hooks");
    expect(doc.hooks.PreToolUse[0]).toEqual({ matcher: "Bash", hooks: [{ type: "command", command: "python3 ~/.codex/hooks/check.py" }] });
    expect(doc.hooks.PreToolUse[1].matcher).toBeUndefined(); // every tool
    expect(doc.hooks.PreToolUse[1].hooks[0]).toMatchObject({ type: "command", timeout: 600 });
    expect(doc.hooks.SessionEnd[0].hooks[0]).toMatchObject({ type: "command", timeout: 3 });
    const cmd: string = doc.hooks.PreToolUse[1].hooks[0].command;
    expect(cmd).toContain(`AGENTGATE_HOME=${t.home}`);
    expect(cmd).toContain("AGENTGATE_HOOK_TIMEOUT_S=600");
    expect(cmd).toContain("AGENTGATE_CODEX_INSTALL=user");
    expect(cmd).toMatch(/agentgate-hook\.sh --agentgate-provider=codex --agentgate-install=codex\/v1$/);
    expect(cmd).not.toMatch(/token|test-access/);
    expect(read(t.hooks)).toMatch(/\n {4}"hooks"/); // original 4-space indent kept

    // Trust: our block appended verbatim after the user's config; keys/hashes for our handlers.
    const cfg = read(t.config);
    expect(cfg.startsWith(USER_CONFIG)).toBe(true);
    expect(cfg).toContain(TRUST_BEGIN);
    for (const e of codexTrustEntries(doc, t.hooks)) {
      expect(cfg).toContain(`[hooks.state."${e.key}"]\ntrusted_hash = "${e.hash}"`);
    }
    expect(cfg).toContain(`${t.hooks}:pre_tool_use:1:0`);
    expect(cfg).toContain(`${t.hooks}:session_end:0:0`);
    expect(readdirSync(t.codex).filter((n) => n.includes(".agentgate-backup-"))).toHaveLength(2);
    expect(statSync(join(t.home, "codex-installs.json")).mode & 0o777).toBe(0o600);

    // Idempotent.
    const hooksAfter = read(t.hooks);
    const r2 = await t.cli(["install", "codex", "--user", "--yes"]);
    expect(r2.code).toBe(0);
    expect(r2.stderr).toMatch(/unchanged, trusted/);
    expect(read(t.hooks)).toBe(hooksAfter);
    expect(read(t.config)).toBe(cfg);

    // Status reports it.
    const st = await t.cli(["status"]);
    expect(st.stdout).toMatch(/codex\s+hook installed \+ trusted \(user\)/);
    expect(st.stdout).toMatch(/hook has not run yet/);

    const u = await t.cli(["uninstall", "codex", "--user"]);
    expect(u.code, u.stderr).toBe(0);
    expect(read(t.hooks)).toBe(USER_HOOKS);
    expect(read(t.config)).toBe(USER_CONFIG);
    expect(existsSync(join(t.home, "codex-installs.json")) ? Object.keys(json(join(t.home, "codex-installs.json"))) : []).toEqual([]);
  }, T);

  it("fresh machine: creates hooks.json + config.toml, uninstall deletes both", async () => {
    const t = await setup();
    const r = await t.cli(["install", "codex", "--user", "--yes"]);
    expect(r.code, r.stderr).toBe(0);
    expect(ours(json(t.hooks))).toHaveLength(2);
    expect(statSync(t.hooks).mode & 0o777).toBe(0o600);
    expect(read(t.config).startsWith(TRUST_BEGIN)).toBe(true);
    const u = await t.cli(["uninstall", "codex", "--user"]);
    expect(u.code).toBe(0);
    expect(existsSync(t.hooks)).toBe(false);
    expect(existsSync(t.config)).toBe(false);
  }, T);

  it("edits after install survive uninstall: only our entries and our trust block are removed", async () => {
    const t = await setup();
    writeFileSync(t.config, USER_CONFIG);
    expect((await t.cli(["install", "codex", "--user", "--yes"])).code).toBe(0);
    const doc = json(t.hooks);
    doc.hooks.Stop = [{ hooks: [{ type: "command", command: "echo later" }] }];
    writeFileSync(t.hooks, JSON.stringify(doc, null, 2));
    writeFileSync(t.config, `${read(t.config)}\n[profiles.fast]\nmodel = "gpt-5.5-mini"\n`);

    const u = await t.cli(["uninstall", "codex", "--user"]);
    expect(u.code, u.stderr).toBe(0);
    const after = json(t.hooks);
    expect(ours(after)).toEqual([]);
    expect(after.hooks.Stop).toEqual([{ hooks: [{ type: "command", command: "echo later" }] }]);
    expect(read(t.config)).toBe(`${USER_CONFIG}\n[profiles.fast]\nmodel = "gpt-5.5-mini"\n`);
  }, T);

  it("Codex inserting its own table inside our block (it does: project trust) → uninstall keeps Codex's table", async () => {
    const t = await setup();
    writeFileSync(t.config, USER_CONFIG);
    expect((await t.cli(["install", "codex", "--user", "--yes"])).code).toBe(0);
    const project = `[projects."${t.project}"]\ntrust_level = "trusted"\n`;
    writeFileSync(t.config, read(t.config).replace(`${TRUST_END}\n`, `\n${project}${TRUST_END}\n`));
    const u = await t.cli(["uninstall", "codex", "--user"]);
    expect(u.code, u.stderr).toBe(0);
    expect(read(t.config)).toBe(`${USER_CONFIG}\n${project}`);
  }, T);

  it("CODEX_HOME is honored (canonical path in the trust keys)", async () => {
    const t = await setup();
    const alt = join(t.root, "alt-codex");
    mkdirSync(alt);
    const r = await t.cli(["install", "codex", "--user", "--yes"], { env: { CODEX_HOME: alt } });
    expect(r.code, r.stderr).toBe(0);
    expect(existsSync(join(alt, "hooks.json"))).toBe(true);
    expect(existsSync(t.hooks)).toBe(false);
    expect(read(join(alt, "config.toml"))).toContain(`${join(alt, "hooks.json")}:pre_tool_use:0:0`);
    expect((await t.cli(["uninstall", "codex", "--user"], { env: { CODEX_HOME: alt } })).code).toBe(0);
    expect(existsSync(join(alt, "hooks.json"))).toBe(false);
  }, T);

  it.each([
    ["invalid JSON", "{ nope"],
    ["unknown top-level key", JSON.stringify({ version: 1, hooks: {} })],
    ["hooks not an object", JSON.stringify({ hooks: [] })],
  ])("%s in hooks.json → refused, nothing written", async (_n, content) => {
    const t = await setup();
    writeFileSync(t.hooks, content);
    const r = await t.cli(["install", "codex", "--user", "--yes"]);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/not modifying it/);
    expect(read(t.hooks)).toBe(content);
    expect(existsSync(t.config)).toBe(false);
  }, T);

  it("config.toml that can't take our tables → hook installed, trust NOT written, loud warning", async () => {
    const t = await setup();
    const cfg = 'model = "o3"\nhooks = { state = {} }\n';
    writeFileSync(t.config, cfg);
    const r = await t.cli(["install", "codex", "--user", "--yes"]);
    expect(r.code).toBe(0);
    expect(r.stderr).toMatch(/NOT trusted yet/);
    expect(r.stderr).toMatch(/\/hooks/);
    expect(read(t.config)).toBe(cfg);
    const st = await t.cli(["status"]);
    expect(st.stdout).toMatch(/NOT GATING \(user\).*not trusted/);
  }, T);

  it("not logged in → refused", async () => {
    const t = await setup();
    writeFileSync(join(t.home, "config.json"), JSON.stringify({ version: 1, server: "http://127.0.0.1:1", machine_id: "m" }));
    const r = await t.cli(["install", "codex", "--user", "--yes"]);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/not logged in/);
    expect(existsSync(t.hooks)).toBe(false);
  }, T);
});

describe("agentgate install codex --project", () => {
  it("writes <project>/.codex/hooks.json + trust in the USER config.toml, git-excludes it, uninstall cleans up", async () => {
    const t = await setup();
    execFileSync("git", ["init", "-q", "-b", "main"], { cwd: t.project });
    writeFileSync(t.config, USER_CONFIG);
    const r = await t.cli(["install", "codex", "--project", t.project], { cwd: t.root });
    expect(r.code, r.stderr).toBe(0);
    const file = join(t.project, ".codex", "hooks.json");
    expect(ours(json(file))[0]).toContain("AGENTGATE_CODEX_INSTALL=project");
    expect(read(t.config)).toContain(`${file}:pre_tool_use:0:0`);
    expect(read(join(t.project, ".git", "info", "exclude"))).toContain("/.codex/hooks.json");
    expect(execFileSync("git", ["status", "--porcelain"], { cwd: t.project, encoding: "utf8" })).toBe("");

    // A second scope would ask twice per action.
    const u2 = await t.cli(["install", "codex", "--user", "--yes"]);
    expect(u2.code).toBe(1);
    expect(u2.stderr).toMatch(/already installed for project/);

    const u = await t.cli(["uninstall", "codex", "--project", t.project], { cwd: t.root });
    expect(u.code, u.stderr).toBe(0);
    expect(existsSync(join(t.project, ".codex"))).toBe(false);
    expect(read(t.config)).toBe(USER_CONFIG);
    expect(read(join(t.project, ".git", "info", "exclude"))).not.toContain(".codex/hooks.json");
  }, T);

  it("project install is refused while a user install exists", async () => {
    const t = await setup();
    expect((await t.cli(["install", "codex", "--user", "--yes"])).code).toBe(0);
    const r = await t.cli(["install", "codex", "--project", t.project]);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/already installed for the user/);
  }, T);
});

describe("full `agentgate uninstall` removes the Codex install", () => {
  it("--dry-run lists it; --yes restores ~/.codex byte-exact", async () => {
    const t = await setup();
    writeFileSync(t.hooks, USER_HOOKS);
    writeFileSync(t.config, USER_CONFIG);
    expect((await t.cli(["install", "codex", "--user", "--yes"])).code).toBe(0);
    const env = { AGENTGATE_SETUP_PLATFORM: "linux" };
    const dry = await t.cli(["uninstall", "--dry-run"], { env });
    expect(dry.stdout).toContain(`remove Codex hooks from ${t.hooks}`);
    expect(ours(json(t.hooks))).toHaveLength(2);
    const r = await t.cli(["uninstall", "--yes"], { env });
    expect(r.code, r.stderr).toBe(0);
    expect(read(t.hooks)).toBe(USER_HOOKS);
    expect(read(t.config)).toBe(USER_CONFIG);
  }, T);
});
