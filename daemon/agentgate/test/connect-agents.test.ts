import { describe, expect, it } from "vitest";
import { connectCommandFor, detectAgents, parseAnswer, parseConnectMode, type DetectDeps } from "../src/commands/connect-agents.ts";

function deps(files: Record<string, string | true>, path = "/usr/bin:/bin"): DetectDeps {
  return {
    home: "/Users/u",
    path,
    exists: (p) => p in files,
    read: (p) => (typeof files[p] === "string" ? (files[p] as string) : null),
  };
}

describe("detectAgents", () => {
  it("finds nothing on a bare machine", () => {
    expect(detectAgents(deps({}))).toEqual([]);
  });

  it("finds Claude Code, Codex and Cursor from their usual locations", () => {
    const found = detectAgents(
      deps({
        "/Users/u/.local/bin/claude": true,
        "/opt/homebrew/bin/codex": true,
        "/Applications/Cursor.app": true,
      }),
    );
    expect(found.map((a) => [a.id, a.connected])).toEqual([
      ["claude-code", false],
      ["codex", false],
      ["cursor", false],
    ]);
  });

  it("uses PATH and config dirs too", () => {
    const found = detectAgents(deps({ "/custom/bin/codex": true, "/Users/u/.claude": true, "/Users/u/.cursor": true }, "/custom/bin"));
    expect(found.map((a) => a.id)).toEqual(["claude-code", "codex", "cursor"]);
  });

  it("marks agents whose config already carries AgentGate's hook as connected", () => {
    const found = detectAgents(
      deps({
        "/Users/u/.claude": true,
        "/Users/u/.claude/settings.json": '{"hooks":{"PreToolUse":[{"hooks":[{"command":"x --agentgate-install=claude-code/v1"}]}]}}',
        "/opt/homebrew/bin/codex": true,
        "/Users/u/.codex/hooks.json": '{"hooks":{}}',
        "/Users/u/.cursor": true,
        "/Users/u/.cursor/hooks.json": '{"hooks":{"beforeShellExecution":[{"command":"s --agentgate-provider=cursor --agentgate-install=cursor/v1"}]}}',
      }),
    );
    expect(Object.fromEntries(found.map((a) => [a.id, a.connected]))).toEqual({ "claude-code": true, codex: false, cursor: true });
  });
});

describe("answers and modes", () => {
  it("defaults to yes; accepts English and Turkish", () => {
    for (const a of ["", "y", "Yes", " e ", "evet"]) expect(parseAnswer(a)).toBe(true);
    for (const a of ["n", "NO", "h", "hayır", "hayir"]) expect(parseAnswer(a)).toBe(false);
    expect(parseAnswer("maybe")).toBeNull();
  });

  it("parses --connect / AGENTGATE_CONNECT", () => {
    expect(parseConnectMode(undefined)).toBe("ask");
    expect(parseConnectMode("")).toBe("ask");
    expect(parseConnectMode("all")).toBe("all");
    expect(parseConnectMode("none")).toBe("none");
    expect(parseConnectMode("yes")).toBeNull();
  });

  it("prints the exact install command per agent", () => {
    expect(connectCommandFor("cursor")).toBe("agentgate install cursor --user --yes");
  });
});
