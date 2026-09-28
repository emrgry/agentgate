import { describe, expect, it } from "vitest";
import {
  addOurCodexHooks,
  appendTrustBlock,
  buildCodexHookCommand,
  CODEX_INSTALL_MARKER,
  codexHookTrustHash,
  codexTrustEntries,
  findOurCodexCommands,
  hooksDisabledIn,
  otherPreToolUseHooks,
  removeOurCodexHooks,
  removeTrustBlock,
  removeOurTrust,
  renderTrustBlock,
  TRUST_BEGIN,
  TRUST_END,
  tomlString,
  trustConflict,
  trustedIn,
  validateCodexHooksDoc,
} from "../src/codex-hooks.ts";

/** Pure helpers behind `agentgate install codex`. */

// Golden vectors: hook definitions + trusted_hash values that codex-cli 0.158.0 (and, for the
// first, 0.131–0.150) accepted as trusted — the hook ran without --dangerously-bypass-hook-trust.
const LAB_CMD = "/private/tmp/claude-501/-Users-damlaipci-Dev-AgentGate-Mobile/148968c3-8379-4f5a-9e77-3d96a7a3936a/scratchpad/cx/lab/hook.sh --marker";
const OUR_CMD =
  "AGENTGATE_HOME=/private/var/folders/t0/7bd0x57j7ms0s6gn7458q8400000gn/T/agentgate-test-aU305y/home AGENTGATE_NODE=/Users/damlaipci/.local/node/bin/node AGENTGATE_HOOK_TIMEOUT_S=600 AGENTGATE_CODEX_INSTALL=project /Users/damlaipci/Dev/agentgate/daemon/agentgate/bin/agentgate-hook.sh --agentgate-provider=codex --agentgate-install=codex/v1";

const command = buildCodexHookCommand({ shimPath: "/Users/me/.agentgate/current/bin/agentgate-hook.sh", nodePath: "/Users/me/.agentgate/current/libexec/node", home: "/Users/me/.agentgate", scope: "user" });
const userGroup = { matcher: "Bash", hooks: [{ type: "command", command: "echo mine", timeout: 5 }] };

describe("Codex trust hash (matches real Codex)", () => {
  it("plain handler, timeout 20 (verified on 0.131–0.158)", () => {
    expect(codexHookTrustHash("PreToolUse", { type: "command", command: LAB_CMD, timeout: 20 })).toBe("sha256:bbf4f04c9575832bfc66a7e5e707e9de5e44f8a303415242f31113e9c50c8552");
  });
  it("our PreToolUse handler with statusMessage (verified on 0.158)", () => {
    expect(codexHookTrustHash("PreToolUse", { type: "command", command: OUR_CMD, timeout: 600, statusMessage: "AgentGate: checking policy (approve on your phone if asked)" })).toBe(
      "sha256:eef9d97e8ecadf26472da1684a607cce79972d432014a126e53406e3d2f40e39",
    );
  });
  it("our SessionEnd handler, timeout 3 (verified on 0.158)", () => {
    expect(codexHookTrustHash("SessionEnd", { type: "command", command: OUR_CMD, timeout: 3 })).toBe("sha256:abbd236137656324c12d31dd607bfbe4b5c7e25d66098e5558f1512ec35a7549");
  });
  it("normalization: default/clamped timeouts, async, default context limit", () => {
    const h = (x: Record<string, unknown>) => codexHookTrustHash("SessionEnd", { type: "command", command: "x", ...x });
    expect(h({ timeout: 99 })).toBe(h({ timeout: 3 }));
    expect(h({})).toBe(h({ timeout: 1 }));
    const p = (x: Record<string, unknown>) => codexHookTrustHash("PreToolUse", { type: "command", command: "x", ...x });
    expect(p({})).toBe(p({ timeout: 600 }));
    expect(p({ additionalContextLimit: 2500 })).toBe(p({}));
    expect(p({ async: true })).not.toBe(p({}));
    expect(p({ commandWindows: "y" })).toBe(p({}));
  });
});

describe("hooks.json merge", () => {
  it("command: absolute paths, scope, provider arg + marker; no secrets", () => {
    expect(command).toBe(
      "AGENTGATE_HOME=/Users/me/.agentgate AGENTGATE_NODE=/Users/me/.agentgate/current/libexec/node AGENTGATE_HOOK_TIMEOUT_S=600 AGENTGATE_CODEX_INSTALL=user /Users/me/.agentgate/current/bin/agentgate-hook.sh --agentgate-provider=codex --agentgate-install=codex/v1",
    );
  });
  it("appends after the user's groups, keeps everything else, is idempotent and reversible", () => {
    const doc = { description: "mine", hooks: { PreToolUse: [userGroup], Stop: [{ hooks: [{ type: "command", command: "echo stop" }] }] } };
    const once = addOurCodexHooks(doc, command);
    expect(once.description).toBe("mine");
    const hooks = once.hooks as any;
    expect(hooks.PreToolUse[0]).toEqual(userGroup);
    expect(hooks.PreToolUse[1]).toEqual({ hooks: [{ type: "command", command, timeout: 600, statusMessage: expect.any(String) }] });
    expect(hooks.SessionEnd).toEqual([{ hooks: [{ type: "command", command, timeout: 3 }] }]);
    expect(hooks.Stop).toEqual(doc.hooks.Stop);
    expect(addOurCodexHooks(once, command)).toEqual(once);
    expect(findOurCodexCommands(once).map((f) => f.event)).toEqual(["PreToolUse", "SessionEnd"]);
    const back = removeOurCodexHooks(once);
    expect(back.removed).toBe(2);
    expect(back.doc).toEqual({ ...doc, hooks: { ...doc.hooks, SessionEnd: [] } });
    expect(otherPreToolUseHooks(once)).toBe(1);
  });
  it("a user handler sharing a group with ours survives removal", () => {
    const doc = { hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "echo mine" }, { type: "command", command }] }] } };
    expect(removeOurCodexHooks(doc).doc).toEqual({ hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "echo mine" }] }] } });
  });
  it("only removes commands with the shim AND the marker", () => {
    const doc = { hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "/x/agentgate-hook.sh --agentgate-provider=codex" }, { type: "command", command: `echo ${CODEX_INSTALL_MARKER}` }] }] } };
    expect(removeOurCodexHooks(doc).removed).toBe(0);
  });
  it.each([
    [[], /not a JSON object/],
    [{ hooks: {}, version: 1 }, /unexpected top-level key/],
    [{ hooks: [] }, /"hooks" is not an object/],
    [{ hooks: { PreToolUse: {} } }, /not an array/],
    [{ hooks: { PreToolUse: [{ hooks: "x" }] } }, /malformed/],
  ])("refuses %j", (doc, re) => {
    expect(() => validateCodexHooksDoc(doc, "hooks.json")).toThrow(re);
  });
});

describe("trust entries + config.toml block", () => {
  const file = "/Users/me/.codex/hooks.json";
  const doc = addOurCodexHooks({ hooks: { PreToolUse: [userGroup] } }, command);
  const entries = codexTrustEntries(doc, file);

  it("keys use the hooks.json path, event label and indices", () => {
    expect(entries.map((e) => e.key)).toEqual([`${file}:pre_tool_use:1:0`, `${file}:session_end:0:0`]);
    expect(entries.every((e) => /^sha256:[0-9a-f]{64}$/.test(e.hash))).toBe(true);
  });
  it("block renders valid tables; append/remove is byte-exact; trustedIn sees it", () => {
    const block = renderTrustBlock(entries);
    expect(block).toContain(`[hooks.state.${tomlString(entries[0]!.key)}]\ntrusted_hash = "${entries[0]!.hash}"`);
    for (const original of ["", 'model = "o3"\n', 'model = "o3"', 'model = "o3"\n\n[mcp_servers.x]\ncommand = "y"\n\n']) {
      const { text, appended } = appendTrustBlock(original || null, block);
      expect(trustedIn(text, entries)).toBe(true);
      expect(removeTrustBlock(text, appended)).toBe(original);
      expect(removeTrustBlock(`${text}# user line after\n`, appended)).toBe(`${original}# user line after\n`);
      expect(removeOurTrust(text, entries, appended)).toBe(original);
      // Record lost → surgical removal: same content; trailing blank lines may differ by one.
      const norm = (x: string | null) => (x ?? "").replace(/\n+$/, "");
      expect(norm(removeOurTrust(text, entries))).toBe(norm(original));
    }
    expect(trustedIn('model = "o3"\n', entries)).toBe(false);
    expect(trustedIn(renderTrustBlock(entries.map((e) => ({ ...e, hash: `sha256:${"0".repeat(64)}` }))), entries)).toBe(false);
  });
  it("Codex inserted its own table inside our block (observed with 0.158 + toml_edit): ours go, Codex's stays", () => {
    const original = 'model = "gpt-5.5"\n\n[features]\nhooks = true\n';
    const { text } = appendTrustBlock(original, renderTrustBlock(entries));
    const project = '[projects."/Users/me/work"]\ntrust_level = "trusted"\n';
    const edited = text.replace(`${TRUST_END}\n`, `\n${project}${TRUST_END}\n`);
    expect(edited.indexOf(project)).toBeLessThan(edited.indexOf(TRUST_END));
    const back = removeOurTrust(edited, entries, text.slice(original.length));
    expect(back).toBe(`${original}\n${project}`);
    expect(back).not.toContain(TRUST_BEGIN);
    expect(back).not.toContain("hooks.state");
  });
  it("only our exact key+hash tables are removed; a user's own trust entry survives", () => {
    const other = '[hooks.state."/Users/me/.codex/hooks.json:stop:0:0"]\ntrusted_hash = "sha256:' + "a".repeat(64) + '"\n';
    const { text } = appendTrustBlock('x = 1\n', renderTrustBlock(entries));
    const edited = text.replace(`${TRUST_END}\n`, `\n${other}${TRUST_END}\n`);
    expect(removeOurTrust(edited, entries)).toBe(`x = 1\n\n${other}`);
    expect(removeOurTrust('x = 1\n', entries)).toBeNull();
  });
  it.each([
    ["hooks = { state = {} }\n", /inline table or dotted/],
    ["hooks.state.x.enabled = false\n", /inline table or dotted/],
    ["[hooks]\nstate = { }\n", /state/],
  ])("conflict: %j", (config, re) => {
    expect(trustConflict(config, entries)).toMatch(re);
  });
  it("conflict: an existing entry for one of our keys (e.g. trusted/disabled via /hooks)", () => {
    expect(trustConflict(`[hooks.state."${entries[0]!.key}"]\nenabled = false\n`, entries)).toMatch(/already has a hook-state entry/);
  });
  it.each(["", 'model = "o3"\n[[hooks.PreToolUse]]\nmatcher = "Bash"\n', '[hooks.state]\n"/other/hooks.json:stop:0:0" = { trusted_hash = "sha256:x" }\n', "[features]\nhooks = true\n"])(
    "no conflict: %j",
    (config) => {
      expect(trustConflict(config, entries)).toBeNull();
    },
  );
  it("tomlString escapes quotes, backslashes and control characters", () => {
    expect(tomlString('a"b\\c\nd\u0001')).toBe('"a\\"b\\\\c\\nd\\u0001"');
  });
  it("hooksDisabledIn", () => {
    expect(hooksDisabledIn("[features]\nhooks = false\n")).toBe(true);
    expect(hooksDisabledIn("[features]\ncodex_hooks = false\n[other]\nx = 1\n")).toBe(true);
    expect(hooksDisabledIn("features.hooks = false\n")).toBe(true);
    expect(hooksDisabledIn("[features]\nhooks = true\n[x]\nhooks = false\n")).toBe(false);
    expect(hooksDisabledIn(null)).toBe(false);
  });
});
