import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";
import { BUILTIN_PROFILES_DIR, genericProvider, isGated, loadProfiles, normalizeGenericHook, parseProfile, prepareGenericHome } from "../src/index.ts";

const hermes = () => loadProfiles([BUILTIN_PROFILES_DIR]).profiles.find((p) => p.id === "hermes")!;

function fakeHermes(dir: string, withFormat: boolean): string {
  const bin = join(dir, "hermes");
  writeFileSync(bin, `#!/bin/sh\nif [ "$2" = "--help" ]; then echo "usage: hermes chat ${withFormat ? "--format {text,stream-json}" : ""} -q"; fi\n`);
  chmodSync(bin, 0o755);
  return bin;
}

describe("profiles", () => {
  it("built-in hermes profile loads and is gated (hook mode)", () => {
    const r = loadProfiles([BUILTIN_PROFILES_DIR]);
    expect(r.errors).toEqual([]);
    expect(isGated(hermes())).toBe(true);
  });

  it.each([
    ["not yaml: [", /invalid YAML/],
    ["id: Hermes\n", /id: must be a lowercase id/],
    ["id: x\ndisplay_name: X\nbinary: x\ncommand: {args: [], prompt: {via: stdin}}\noutput: {format: jsonl}\napproval: {mode: none}\n", /output.*jsonl is required/],
    ["id: x\ndisplay_name: X\nbinary: x\ncommand: {args: [], prompt: {via: flag}}\noutput: {format: text}\napproval: {mode: none}\n", /prompt.flag is required/],
    ["id: x\ndisplay_name: X\nbinary: x\ncommand: {args: [], prompt: {via: stdin}}\noutput: {format: text}\napproval: {mode: hook}\n", /approval.hook is required/],
    ["id: x\ndisplay_name: X\nbinary: x\ncommand: {args: [], prompt: {via: stdin}}\nresume: {args: [-r]}\noutput: {format: text}\napproval: {mode: none}\n", /must contain \{session_id\}/],
    ["id: x\ndisplay_name: X\nbinary: x\ncommand: {args: [], prompt: {via: stdin}}\noutput: {format: text}\napproval: {mode: none}\nyolo: true\n", /Unrecognized key/],
  ])("validation error %#", (text, re) => {
    expect(() => parseProfile(text, "p.yaml")).toThrow(re);
  });

  it("loadProfiles collects errors without throwing; user dirs override built-ins by id", () => {
    const d = mkdtempSync(join(tmpdir(), "ag-prof-"));
    writeFileSync(join(d, "bad.yaml"), "id: 1\n");
    writeFileSync(join(d, "h.yml"), readFileSync(join(BUILTIN_PROFILES_DIR, "hermes.yaml"), "utf8").replace("display_name: Hermes", "display_name: My Hermes"));
    const r = loadProfiles([BUILTIN_PROFILES_DIR, d, join(d, "missing")]);
    expect(r.errors).toHaveLength(1);
    expect(r.errors[0]!.file).toContain("bad.yaml");
    expect(r.profiles.find((p) => p.id === "hermes")!.display_name).toBe("My Hermes");
  });

  it("sandbox-only / none profiles are ungated", () => {
    const p = parseProfile("id: aider\ndisplay_name: Aider\nbinary: aider\ncommand: {args: [--message-file, '-'], prompt: {via: stdin}}\noutput: {format: text}\napproval: {mode: none}\n");
    expect(isGated(p)).toBe(false);
    expect(genericProvider(p).gated).toBe(false);
  });
});

describe("hermes stream-json parser table", () => {
  const lines = [
    { type: "system", subtype: "init", session_id: "h-1" },
    { type: "text", text: "Hel" },
    { type: "text", text: "lo" },
    { type: "tool_use", name: "terminal", input: { command: "ls -la" } },
    { type: "tool_result", name: "terminal", output: "total 0", duration_ms: 3, is_error: false },
    { type: "text", text: "Done?" },
    { type: "result", session_id: "h-1", exit_code: 0, text: "Done?", tokens: { input: 10, output: 5 }, duration_ms: 99 },
  ];
  it("maps events", () => {
    const pr = genericProvider(hermes());
    const parser = pr.createParser!();
    const evs = lines.flatMap((l) => parser.line(JSON.stringify(l)));
    evs.push(...parser.end(0));
    expect(evs.map((e) => e.type)).toEqual([
      "provider.session",
      "message.assistant",
      "tool.call",
      "provider.tool_started",
      "tool.result",
      "provider.tool_completed",
      "message.assistant",
      "provider.turn_result",
    ]);
    expect(evs[1]!.payload).toEqual({ text: "Hello" });
    expect((evs[2]!.payload as { summary: string }).summary).toContain("ls -la");
    const res = evs.at(-1)!.payload as { ok: boolean; text: string; usage: { input_tokens: number; output_tokens: number; cost_usd: null } };
    expect(res.ok).toBe(true);
    expect(res.text).toBe("Done?");
    expect(res.usage.input_tokens).toBe(10);
    expect(res.usage.cost_usd).toBeNull();
  });
  it("error in result → failed", () => {
    const p = genericProvider(hermes()).createParser!();
    const evs = p.line(JSON.stringify({ type: "result", exit_code: 1, error: "rate limited" }));
    expect(evs.at(-1)!.payload).toMatchObject({ ok: false, error: "rate limited" });
  });
  it("no result + exit 0 → still success; non-zero → failure", () => {
    expect(genericProvider(hermes()).createParser!().end(0).at(-1)!.payload).toMatchObject({ ok: true });
    expect(genericProvider(hermes()).createParser!().end(3).at(-1)!.payload).toMatchObject({ ok: false });
    expect(genericProvider(hermes()).createParser!().end(null).at(-1)!.payload).toMatchObject({ ok: false });
  });
});

describe("hermes command construction + detection", () => {
  it("stream-json available → primary args with stdin prompt; resume uses -r", () => {
    const d = mkdtempSync(join(tmpdir(), "ag-hb-"));
    const pr = genericProvider(hermes(), { binary: fakeHermes(d, true) });
    expect(pr.preflight!(process.env as Record<string, string>).ok).toBe(true);
    expect(pr.mode()).toBe("primary");
    const c = pr.buildTurnCommand({ cwd: "/w", instruction: "do it", hookSettingsPath: "" });
    expect(c.args).toEqual(["chat", "--oneshot", "-Q", "--format", "stream-json", "--query-file", "-"]);
    expect(c.stdin).toBe("do it");
    const r = pr.buildTurnCommand({ cwd: "/w", instruction: "more", providerSessionId: "h-1", hookSettingsPath: "" });
    expect(r.args).toEqual(["chat", "--oneshot", "-Q", "--format", "stream-json", "-r", "h-1", "--query-file", "-"]);
    expect(pr.capabilities.resume).toBe(true);
  });
  it("no --format in help → text fallback (final text only, no resume)", () => {
    const d = mkdtempSync(join(tmpdir(), "ag-hb-"));
    const pr = genericProvider(hermes(), { binary: fakeHermes(d, false) });
    pr.preflight!(process.env as Record<string, string>);
    expect(pr.mode()).toBe("fallback");
    expect(pr.capabilities.resume).toBe(false);
    const c = pr.buildTurnCommand({ cwd: "/w", instruction: "hi", providerSessionId: "h-1", hookSettingsPath: "" });
    expect(c.args).toEqual(["chat", "--oneshot", "-z", "--query-file", "-"]);
    const p = pr.createParser!();
    p.line("line one");
    p.line("line two");
    const evs = p.end(0);
    expect(evs.map((e) => e.type)).toEqual(["message.assistant", "provider.turn_result"]);
    expect(evs[0]!.payload).toEqual({ text: "line one\nline two" });
  });
  it("prepareGenericHome copies the user home and patches config.yaml with the hook", () => {
    const base = mkdtempSync(join(tmpdir(), "ag-hh-"));
    const src = join(base, "src");
    mkdirSync(src);
    writeFileSync(join(src, "config.yaml"), "model: x\n");
    writeFileSync(join(src, ".env"), "KEY=1\n");
    const prof = { ...hermes(), approval: { ...hermes().approval, hook: { ...hermes().approval.hook!, copy_from: src } } };
    const r = prepareGenericHome(prof, { baseDir: join(base, "homes"), sessionId: "s/1", hookCommand: "/x/shim --agentgate-provider=hermes" });
    const home = r.env.HERMES_HOME!;
    expect(readFileSync(join(home, ".env"), "utf8")).toBe("KEY=1\n");
    const cfg = parseYaml(readFileSync(join(home, "config.yaml"), "utf8"));
    expect(cfg.model).toBe("x");
    expect(cfg.hooks.PreToolUse[0].hooks[0].command).toContain("--agentgate-provider=hermes");
    expect(r.gateReceipts).toContain(home);
  });
});

describe("normalizeGenericHook", () => {
  const ctx = { session_id: "s", cwd: "/w" };
  it("shell / write / unknown", () => {
    expect(normalizeGenericHook("hermes", { tool_name: "terminal", tool_input: { command: "rm -rf x" } }, ctx).action).toMatchObject({ category: "shell", command: "rm -rf x" });
    expect(normalizeGenericHook("hermes", { tool_name: "write_file", tool_input: { path: "a.txt" } }, ctx).resource).toMatchObject({ name: "/w/a.txt" });
    const u = normalizeGenericHook("hermes", { tool_name: "browser_click", tool_input: { x: 1 } }, ctx);
    expect(u.risk?.level).toBe("high");
    expect(() => normalizeGenericHook("hermes", { tool_input: {} }, ctx)).toThrow();
  });
});
