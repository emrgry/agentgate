/**
 * Path stability for installed releases: everything AgentGate persists (hook commands,
 * MCP wrap entries, exec rewrites, the launchd plist) must reference the STABLE
 * ~/.agentgate/current/… path, never versions/<v>/, so `agentgate update` can swap versions
 * without breaking hooks. And agents must not be able to touch versions/ or current.
 */
import { mkdirSync, mkdtempSync, realpathSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AGENTGATE_DIR_REF_RE, ClaudeCodeAdapter, SELF_MANAGEMENT_RE, sensitivePathReason } from "@agentgate/adapter-claude-code";
import { buildInstalledHookCommand, commandShim, commandVar } from "../src/claude-settings.ts";
import { computeLayout, layout } from "../src/install-layout.ts";

const home = realpathSync(mkdtempSync(join(tmpdir(), "agentgate-layout-")));
const install = join(home, ".agentgate");
const vdir = join(install, "versions", "1.4.0");
mkdirSync(join(vdir, "lib"), { recursive: true });
symlinkSync("versions/1.4.0", join(install, "current"));

const release = computeLayout({ release: { version: "1.4.0", target: "darwin-arm64", node: "24.21.0" }, moduleDir: join(vdir, "lib"), execPath: join(vdir, "libexec", "node"), home });

describe("install layout", () => {
  it("installed release: persisted paths go through ~/.agentgate/current", () => {
    const cur = join(install, "current");
    expect(release.kind).toBe("release");
    expect(release.root).toBe(vdir);
    expect(release.installHome).toBe(install);
    expect(release.cli).toBe(join(cur, "bin", "agentgate"));
    expect(release.hookShim).toBe(join(cur, "bin", "agentgate-hook.sh"));
    expect(release.node).toBe(join(cur, "libexec", "node"));
    expect(release.serveArgs).toEqual([join(cur, "bin", "agentgate"), "serve"]);
    // The running server imports its OWN version's API bundle.
    expect(release.apiMain).toBe(join(vdir, "lib", "api.mjs"));
  });

  it("installed hook commands reference the stable path only", () => {
    const cmd = buildInstalledHookCommand({ shimPath: release.hookShim, nodePath: release.node, home: install });
    expect(commandShim(cmd)).toBe(join(install, "current", "bin", "agentgate-hook.sh"));
    expect(commandVar(cmd, "AGENTGATE_NODE")).toBe(join(install, "current", "libexec", "node"));
    expect(cmd).not.toContain("versions/");
  });

  it("a release extracted outside an install dir uses its own paths", () => {
    const loose = join(home, "loose");
    mkdirSync(join(loose, "lib"), { recursive: true });
    const l = computeLayout({ release: { version: "1.4.0", target: "darwin-arm64", node: "24.21.0" }, moduleDir: join(loose, "lib"), execPath: "/x", home });
    expect(l.installHome).toBeNull();
    expect(l.cli).toBe(join(loose, "bin", "agentgate"));
  });

  it("dev checkout (this test run) keeps the repository paths", () => {
    const l = layout();
    expect(l.kind).toBe("dev");
    expect(l.cli).toMatch(/daemon\/agentgate\/bin\/agentgate\.sh$/);
    expect(l.hookShim).toMatch(/daemon\/agentgate\/bin\/agentgate-hook\.sh$/);
    expect(l.serveArgs[1]).toMatch(/daemon\/agentgate\/bin\/agentgate\.mjs$/);
    expect(l.node).toBe(process.execPath);
  });
});

describe("guard covers installed releases", () => {
  // AGENTGATE_HOME deliberately elsewhere: versions/ and current must be protected anyway.
  const adapter = new ClaudeCodeAdapter({ homeDir: home, projectRoot: join(home, "proj"), agentgateHome: join(home, "other-ag-home"), protectedDirs: release.protectedDirs });
  const ev = (tool_name: string, tool_input: Record<string, unknown>) => ({ hook_event_name: "PreToolUse", session_id: "s", tool_name, tool_input }) as never;

  it.each([
    join(vdir, "lib", "agentgate.mjs"),
    join(vdir, "bin", "agentgate-hook.sh"),
    join(install, "versions", "9.9.9", "bin", "agentgate"),
    join(install, "current"),
    join(install, "current", "bin", "agentgate"),
    join(install, "previous"),
    join(home, ".local", "bin", "agentgate"),
  ])("Write %s → deny", (file_path) => {
    expect(adapter.guard(ev("Write", { file_path, content: "x" }), join(home, "proj"))?.decision).toBe("deny");
    expect(sensitivePathReason(file_path, { homeDir: home, projectRoot: join(home, "proj"), protectedDirs: release.protectedDirs })).toBeTruthy();
  });

  it("dev layout also protects ~/.agentgate/versions and current", () => {
    const dev = computeLayout({ release: null, moduleDir: join(home, "repo", "daemon", "agentgate", "src"), execPath: "/x", home });
    for (const p of [join(install, "versions", "1.0.0", "lib", "api.mjs"), join(install, "current")]) {
      expect(dev.protectedDirs.some((d) => p === d || p.startsWith(`${d}/`)), p).toBe(true);
    }
  });

  it.each([
    `ln -sfn /tmp/evil ${install}/current`,
    "ln -sfn /tmp/evil ~/.agentgate/current",
    "cd ~ && ln -sfn /tmp/evil .agentgate/current",
    "cd ~ && rm -rf .agentgate",
    `cp /tmp/x ${vdir}/lib/agentgate.mjs`,
  ])("Bash %j → ask", (command) => {
    expect(adapter.guard(ev("Bash", { command }), join(home, "proj"))?.decision).toBe("ask");
  });

  it("the relative-reference pattern does not fire on unrelated names", () => {
    for (const s of ["cat my.agentgate.txt", "echo agentgate", "ls x.agentgate/"]) expect(AGENTGATE_DIR_REF_RE.test(s), s).toBe(false);
  });

  it.each([
    "agentgate update",
    "agentgate update --rollback",
    "~/.local/bin/agentgate update --version 0.0.1",
    `'${install}/current/bin/agentgate' update --restart`,
    `"$HOME/.agentgate/current/bin/agentgate" uninstall --yes`,
    "agentgate uninstall --purge --yes",
    "agentgate uninstall-server --purge",
    "agentgate -v restart",
    "agentgate setup --host 0.0.0.0",
  ])("Bash %j → deny (self-management)", (command) => {
    expect(SELF_MANAGEMENT_RE.test(command), command).toBe(true);
    expect(adapter.guard(ev("Bash", { command }), join(home, "proj"))?.decision).toBe("deny");
  });

  it.each(["agentgate version", "agentgate --version", "agentgate status", "cat agentgate-update.md", "echo update"])("Bash %j → not self-management", (command) => {
    expect(SELF_MANAGEMENT_RE.test(command), command).toBe(false);
  });
});
