import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { codexProvider, codexReceiptFacts, compareVersions, filterCodexArgs, normalizeCodexHook, parseCodexHookInput, parseCodexLine, patchPaths } from "../src/index.ts";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const events = (f: string) => readFileSync(join(FIX, f), "utf8").split("\n").flatMap(parseCodexLine);

describe("parseCodexLine (documented stream, synthetic fixture)", () => {
  it("maps thread/items/usage and ignores unknown types", () => {
    const ev = events("turn.jsonl");
    expect(ev.map((e) => e.type)).toEqual([
      "provider.session",
      "tool.call",
      "provider.tool_started",
      "tool.result",
      "provider.tool_completed",
      "tool.call",
      "provider.tool_started",
      "tool.result",
      "provider.tool_completed",
      "todo.updated",
      "tool.call",
      "provider.tool_started",
      "tool.result",
      "provider.tool_completed",
      "tool.call",
      "message.assistant",
      "provider.turn_result",
    ]);
    expect(ev[0]!.payload.provider_session_id).toBe("0199a213-81c0-7800-8aa1-bbab2a035a53");
    expect(ev[1]!.payload).toMatchObject({ tool: "Bash", summary: "bash -lc ls", tool_use_id: "item_1" });
    expect(ev[3]!.payload).toMatchObject({ ok: true, summary: "one.txt\ntwo.txt" });
    expect(ev[6]!.payload).toMatchObject({ kind: "file", paths: ["one.txt"] });
    expect(ev[9]!.payload).toEqual({ items: [{ text: "list", completed: true }] });
    expect(ev[12]!.payload).toMatchObject({ ok: false, summary: "rate limited" });
    expect(ev[14]!.payload).toMatchObject({ tool: "web_search", summary: "codex docs" });
    expect(ev.at(-1)!.payload).toMatchObject({ ok: true, usage: { cost_usd: null, input_tokens: 24763, output_tokens: 122 } });
  });
  it("turn.failed / error → failed result", () => {
    const ev = events("failed.jsonl");
    expect(ev.at(-1)!.payload).toMatchObject({ ok: false, error: "stream disconnected before completion" });
  });
  it("garbage tolerant", () => {
    for (const l of ["", "x", "[]", '{"type":"item.completed"}', '{"type":"item.completed","item":{"type":"agent_message"}}']) expect(() => parseCodexLine(l)).not.toThrow();
  });
});

describe("codexProvider.buildTurnCommand", () => {
  const p = codexProvider({ binary: "/usr/local/bin/codex", extraArgs: ["-m", "gpt-5-codex", "--yolo", "--dangerously-bypass-approvals-and-sandbox", "--sandbox", "danger-full-access", "-s", "read-only", "--ephemeral", "--full-auto"], codexHome: (sid) => `/h/${sid}` });
  it("first turn: exec --json -C cwd --sandbox workspace-write, prompt on stdin", () => {
    const c = p.buildTurnCommand({ instruction: "fix it", cwd: "/w", hookSettingsPath: "/x", sessionId: "ags_1" });
    expect(c.args).toEqual(["exec", "--json", "-C", "/w", "--sandbox", "workspace-write", "--skip-git-repo-check", "--dangerously-bypass-hook-trust", "-m", "gpt-5-codex", "-"]);
    expect(c.stdin).toBe("fix it");
    expect(c.env).toEqual({ CODEX_HOME: "/h/ags_1", AGENTGATE_GATE_RECEIPTS: "/h/ags_1/agentgate-receipts.jsonl" });
    expect(c.gateReceipts).toBe("/h/ags_1/agentgate-receipts.jsonl");
  });
  it("resume: exec resume … <thread_id> -", () => {
    const c = p.buildTurnCommand({ instruction: "go on", cwd: "/w", hookSettingsPath: "/x", providerSessionId: "thr_9", sessionId: "ags_1" });
    expect(c.args.slice(0, 2)).toEqual(["exec", "resume"]);
    expect(c.args.slice(-2)).toEqual(["thr_9", "-"]);
    expect(JSON.stringify(c.args)).not.toMatch(/yolo|bypass-approvals|danger-full-access|ephemeral|full-auto|read-only/);
  });
  it("filterCodexArgs", () => {
    expect(filterCodexArgs(["--sandbox=danger-full-access", "-m", "x", "--yolo"])).toEqual(["-m", "x"]);
  });
  it("capabilities", () => {
    expect(p.capabilities).toEqual({ resume: true, pause: "signal", observe: false, cost: false });
  });
  it("preflight: unknown version fails closed; min version enforced", () => {
    expect(codexProvider({ binary: "/nonexistent/codex" }).preflight!(process.env).ok).toBe(false);
    expect(compareVersions("0.44.0", "0.40.1")).toBeGreaterThan(0);
    expect(compareVersions("0.39", "0.40.0")).toBeLessThan(0);
  });
});

describe("codex PreToolUse normalization", () => {
  const ctx = { session_id: "ses_1", homeDir: "/Users/dev", projectRoot: "/w" };
  const inp = (tool_name: string, tool_input: unknown) => parseCodexHookInput({ session_id: "thr", cwd: "/w", hook_event_name: "PreToolUse", tool_name, tool_input, tool_use_id: "call_1", turn_id: "t1" });
  it("Bash (string or argv) → shell.execute", () => {
    expect(normalizeCodexHook(inp("Bash", { command: "git push origin main" }), ctx).action).toMatchObject({ category: "shell", operation: "execute", command: "git push origin main" });
    expect(normalizeCodexHook(inp("Bash", { command: ["bash", "-lc", "ls"] }), ctx).action.command).toBe("bash -lc ls");
  });
  it("apply_patch → filesystem.write with paths from the patch; sensitive → high risk", () => {
    const patch = "*** Begin Patch\n*** Update File: src/a.ts\n@@\n-x\n+y\n*** Add File: .env\n+K=1\n*** End Patch";
    expect(patchPaths(patch)).toEqual(["src/a.ts", ".env"]);
    const d = normalizeCodexHook(inp("apply_patch", { input: patch }), ctx);
    expect(d.action).toMatchObject({ category: "filesystem", operation: "write", arguments: { paths: ["/w/src/a.ts", "/w/.env"] } });
    expect(d.risk?.level).toBe("high");
  });
  it("mcp__server__tool → mcp.invoke; unknown tool → high-risk generic", () => {
    expect(normalizeCodexHook(inp("mcp__github__create_issue", { title: "x" }), ctx).action).toMatchObject({ category: "mcp", arguments: { server: "github", tool: "create_issue" } });
    expect(normalizeCodexHook(inp("view_image", {}), ctx).risk?.level).toBe("high");
  });
  it("receipt facts", () => {
    expect(codexReceiptFacts(inp("Bash", { command: "ls" }))).toEqual({ kind: "shell", text: "ls", paths: [] });
  });
  it("rejects non-PreToolUse input", () => {
    expect(() => parseCodexHookInput({ hook_event_name: "Stop", tool_name: "Bash", cwd: "/" })).toThrow();
  });
});
