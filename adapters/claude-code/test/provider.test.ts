import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { claudeCodeProvider, isQuestion, normalizeClaudeHook, parseStreamJsonLine } from "../src/provider.ts";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const events = (f: string) => readFileSync(join(FIX, f), "utf8").split("\n").flatMap(parseStreamJsonLine);

describe("parseStreamJsonLine on real captured stream-json (Claude Code 2.1.283)", () => {
  it("text reply: session id, assistant text, successful result with usage", () => {
    const all = events("text-hello.jsonl");
    const ev = all.filter((e) => e.type !== "provider.usage_delta");
    expect(ev.map((e) => e.type)).toEqual(["provider.session", "message.assistant", "provider.turn_hint", "provider.turn_result"]);
    // Mid-turn estimate from the per-message usage ≈ the real total (1 h cache-write rate).
    const deltas = all.filter((e) => e.type === "provider.usage_delta");
    expect(deltas[0]!.payload).toMatchObject({ model: "claude-haiku-4-5-20251001", message_id: "msg_011CfSZK1rJ7Q9KcEyL7GAxf" });
    const est = new Map(deltas.map((d) => [d.payload.message_id, d.payload.cost_usd_estimate as number]));
    const real = (ev[3]!.payload.usage as any).cost_usd as number;
    expect([...est.values()].reduce((a, b) => a + b, 0)).toBeCloseTo(real, 3);
    expect(ev[0]!.payload).toMatchObject({ provider_session_id: "54f79aa2-d399-44e7-906c-b84dc991304b", permission_mode: "default" });
    expect(ev[1]!.payload.text).toBe("hello");
    expect(ev[2]!.payload.status).toBe("completed");
    expect(ev[3]!.payload).toMatchObject({ ok: true, text: "hello", error: null, usage: { num_turns: 1, input_tokens: 10, output_tokens: 42 } });
    expect((ev[3]!.payload.usage as any).cost_usd).toBeGreaterThan(0);
    expect((ev[3]!.payload.usage as any).duration_ms).toBeGreaterThan(0);
  });

  it("tool use: tool.call with a command summary, tool.result ok, final text", () => {
    const all = events("tool-use.jsonl");
    const ev = all.filter((e) => e.type !== "provider.usage_delta");
    const est = new Map(all.filter((e) => e.type === "provider.usage_delta").map((d) => [d.payload.message_id, d.payload.cost_usd_estimate as number]));
    expect(est.size).toBe(2);
    expect([...est.values()].reduce((a, b) => a + b, 0)).toBeCloseTo((ev.at(-1)!.payload.usage as any).cost_usd, 2);
    expect(ev.map((e) => e.type)).toEqual(["provider.session", "tool.call", "tool.result", "message.assistant", "provider.turn_hint", "provider.turn_result"]);
    expect(ev[1]!.payload).toMatchObject({ tool: "Bash", summary: "ls -1 | wc -l", tool_use_id: "toolu_01Ah5c7c7LA7qccgYtjiwT6a" });
    expect(ev[2]!.payload).toMatchObject({ ok: true, tool_use_id: "toolu_01Ah5c7c7LA7qccgYtjiwT6a" });
    expect((ev[5]!.payload.usage as any).num_turns).toBe(2);
  });

  it("resumed turn ending in a question: same session id, blocked hint, isQuestion", () => {
    const ev = events("resume-question.jsonl");
    expect(ev[0]!.payload.provider_session_id).toBe("41ad9710-ae86-405f-b686-dd1ccd5ed4c9"); // same as tool-use run
    const hint = ev.find((e) => e.type === "provider.turn_hint")!;
    expect(hint.payload).toMatchObject({ status: "blocked", needs_action: expect.stringContaining("which file") });
    const last = ev.filter((e) => e.type === "message.assistant").pop()!.payload.text as string;
    expect(isQuestion(last)).toBe(true);
  });

  it("failed resume: only a result with is_error, errors[] surfaced", () => {
    const ev = events("resume-missing-session.jsonl");
    expect(ev).toHaveLength(1);
    expect(ev[0]!.payload).toMatchObject({ ok: false, subtype: "error_during_execution", error: expect.stringContaining("No conversation found"), usage: { num_turns: 0 } });
  });

  it("not logged in (real): subtype 'success' but is_error → failed with the reason from `result`", () => {
    const ev = events("not-logged-in.jsonl");
    const r = ev.find((e) => e.type === "provider.turn_result")!;
    expect(r.payload).toMatchObject({ ok: false, error: "Not logged in · Please run /login" });
  });

  it("tolerates garbage, unknown types and missing fields", () => {
    for (const l of ["", "not json", "[1,2]", '{"type":"stream_event","event":{}}', '{"type":"assistant"}', '{"type":"result"}', '{"type":"future_thing","x":1}']) {
      expect(() => parseStreamJsonLine(l)).not.toThrow();
    }
    expect(parseStreamJsonLine('{"type":"result"}')[0]!.payload).toMatchObject({ ok: true, usage: { cost_usd: null } });
  });
});

describe("isQuestion", () => {
  it.each([
    ["Which one would you like me to delete?", true],
    ["Done. Should I also update the README", true],
    ["I made the change. **Want me to run the tests?**", true],
    ["Please confirm before I push to main.", true],
    ["Let me know which approach you prefer.", true],
    ["All tests pass. The refactor is complete.", false],
    ["I fixed the bug in `parse()`.\n\nWhy? Because the index was off by one. It works now.", false],
    ["", false],
  ])("%j → %s", (t, q) => expect(isQuestion(t)).toBe(q));
});

describe("buildTurnCommand", () => {
  const p = claudeCodeProvider({ binary: "/Users/dev/.local/bin/claude", extraArgs: ["--model", "haiku", "--dangerously-skip-permissions", "--permission-mode", "bypassPermissions"] });
  it("prompt via stdin, stream-json, hook settings, --resume; never bypasses permissions", () => {
    const first = p.buildTurnCommand({ instruction: "--help fix it", cwd: "/w", hookSettingsPath: "/s.json" });
    expect(first.cmd).toBe("/Users/dev/.local/bin/claude");
    expect(first.stdin).toBe("--help fix it");
    expect(first.args).toEqual(["-p", "--output-format", "stream-json", "--verbose", "--settings", "/s.json", "--model", "haiku"]);
    const next = p.buildTurnCommand({ instruction: "go on", providerSessionId: "abc", cwd: "/w", hookSettingsPath: "/s.json" });
    expect(next.args).toContain("--resume");
    expect(next.args[next.args.indexOf("--resume") + 1]).toBe("abc");
    expect(JSON.stringify([first, next])).not.toMatch(/bypassPermissions|dangerously/);
  });
});

describe("normalizeClaudeHook (observed mode)", () => {
  const h = (hook_event_name: string, extra: Record<string, unknown> = {}) => normalizeClaudeHook({ session_id: "s1", cwd: "/w", hook_event_name, ...extra });
  it.each([
    ["SessionStart", { source: "startup" }, ["provider.hook", "session.started"]],
    ["UserPromptSubmit", { prompt: "do x" }, ["provider.hook", "message.user"]],
    ["PostToolUse", { tool_name: "Edit", tool_input: { file_path: "a.ts" }, tool_response: { success: true } }, ["provider.hook", "tool.result"]],
    ["Notification", { notification_type: "idle_prompt", message: "Claude is waiting for your input" }, ["provider.hook", "input.required"]],
    ["Notification", { notification_type: "permission_prompt", message: "Claude needs your permission to use Bash" }, ["provider.hook", "input.required"]],
    ["Notification", { notification_type: "auth_success", message: "ok" }, ["provider.hook"]],
    ["Stop", {}, ["provider.hook", "turn.completed"]],
    ["SessionEnd", { reason: "prompt_input_exit" }, ["provider.hook", "provider.session_end"]],
    ["SomethingNew", {}, ["provider.hook"]],
  ])("%s %j", (ev, extra, types) => {
    expect(h(ev, extra).map((e) => e.type)).toEqual(types);
  });
  it("garbage → []", () => {
    expect(normalizeClaudeHook(null)).toEqual([]);
    expect(normalizeClaudeHook({ hook_event_name: "Stop" })).toEqual([]);
  });
});

describe("isQuestion — real-device regressions", () => {
  it("Turkish question in the last paragraph followed by a closing sentence", () => {
    const text =
      "`src/server.js:13` dosyasına endpoint'i ekledim, ama işi bitirmeden önce isminin onayını bekliyorum. Henüz çalıştırıp test etmedim.\n\n```js\nif (req.url === \"/time\") { /* ? */ }\n```\n\nÖrnek yanıt: `{\"time\":\"…\"}`\n\n**Soru:** Endpoint adı küçük harfle `/time` olsun mu? Mevcut `/health` ve `/version` da küçük harf olduğu için böyle yazdım. Mesajınızdaki gibi `/Time` olmasını isterseniz değiştiririm.";
    expect(isQuestion(text)).toBe(true);
  });
  it("English question followed by a closing sentence", () => {
    expect(isQuestion("I added the endpoint.\n\nShould it be `/time` or `/now`? Happy to rename it.")).toBe(true);
  });
  it("does not treat a '?' inside code as a question", () => {
    expect(isQuestion("Done.\n\n```ts\nconst x = a ? b : c;\n```\n\nAll tests pass.")).toBe(false);
  });
  it("plain completion stays a completion", () => {
    expect(isQuestion("Added GET /time returning ISO time. Tests pass.")).toBe(false);
    expect(isQuestion("Endpoint'i ekledim, testler geçti.")).toBe(false);
  });
});

describe("cost kind + price table", () => {
  it("claude auth status → cost kind", async () => {
    const { costKindFromAuthStatus, estimateCostUsd, priceFor } = await import("../src/index.ts");
    expect(costKindFromAuthStatus('{"loggedIn":true,"authMethod":"claude.ai","subscriptionType":"max"}')).toBe("subscription_estimate");
    expect(costKindFromAuthStatus('{"loggedIn":true,"authMethod":"api_key","apiKeySource":"ANTHROPIC_API_KEY"}')).toBe("api");
    expect(costKindFromAuthStatus('{"loggedIn":true,"authMethod":"console"}')).toBe("api");
    expect(costKindFromAuthStatus("garbage")).toBe("unknown");
    expect(costKindFromAuthStatus("", { ANTHROPIC_API_KEY: "x" })).toBe("api");
    expect(priceFor("claude-some-future-model")).toEqual(priceFor("claude-opus-4")); // unknown → most expensive
    expect(estimateCostUsd("claude-sonnet-4-5", { input_tokens: 1_000_000, output_tokens: 1_000_000 })).toBeCloseTo(18);
  });
});
