import { describe, expect, it } from "vitest";
import type { CanonicalAction } from "@agentgate/protocol";
import { actionHashInput, computeActionHash } from "../src/index.ts";
import { makeAction, makeDraft } from "./fixtures.ts";

const base = makeAction();
const baseHash = computeActionHash(base);

/** Deep-clone the base action and apply a mutation. */
function mutate(fn: (a: CanonicalAction) => void): CanonicalAction {
  const a = structuredClone(base);
  fn(a);
  return a;
}

describe("computeActionHash — stability", () => {
  it("is a 64-char lowercase hex SHA-256", () => {
    expect(baseHash).toMatch(/^[a-f0-9]{64}$/);
  });

  it("is deterministic", () => {
    expect(computeActionHash(structuredClone(base))).toBe(baseHash);
  });

  it("is independent of key insertion order at every level", () => {
    const reordered: CanonicalAction = {
      created_at: base.created_at,
      risk: { reason: base.risk.reason, level: base.risk.level },
      context: base.context,
      resource: { name: base.resource.name, environment: base.resource.environment, type: base.resource.type },
      action: {
        cwd: base.action.cwd,
        arguments: { flags: ["-v"], path: "temp.txt" },
        command: base.action.command,
        tool: base.action.tool,
        operation: base.action.operation,
        category: base.action.category,
      },
      agent: { version: base.agent.version, type: base.agent.type },
      session_id: base.session_id,
      action_id: base.action_id,
    };
    expect(computeActionHash(reordered)).toBe(baseHash);
  });

  it.each<[string, (a: CanonicalAction) => void]>([
    ["action_id", (a) => void (a.action_id = "act_other")],
    ["created_at", (a) => void (a.created_at = "2030-01-01T00:00:00.000Z")],
    ["risk level", (a) => void (a.risk = { level: "low", reason: "x" })],
    ["risk reason", (a) => void (a.risk.reason = "something else")],
    ["context", (a) => void (a.context = { repo: "other/repo", branch: "dev", hostname: "other", extra: "x" })],
    ["agent version", (a) => void (a.agent.version = "9.9.9")],
  ])("does not change when excluded field %s changes", (_name, fn) => {
    expect(computeActionHash(mutate(fn))).toBe(baseHash);
  });

  it("is the same for an ActionDraft and the CanonicalAction built from it", () => {
    expect(computeActionHash(makeDraft())).toBe(baseHash);
  });

  it("treats absent optional fields and explicit undefined identically", () => {
    const a = mutate((x) => {
      delete x.action.tool;
      delete x.action.cwd;
    });
    const b = mutate((x) => {
      x.action.tool = undefined;
      x.action.cwd = undefined;
    });
    expect(computeActionHash(a)).toBe(computeActionHash(b));
  });

  it("treats a missing resource like an empty resource", () => {
    const draft = makeDraft();
    const { resource: _r, ...noResource } = draft;
    expect(computeActionHash(noResource as typeof draft)).toBe(computeActionHash({ ...draft, resource: {} }));
  });
});

describe("computeActionHash — sensitivity (any covered field changes the hash)", () => {
  it.each<[string, (a: CanonicalAction) => void]>([
    ["command: rm temp.txt → rm -rf /", (a) => void (a.action.command = "rm -rf /")],
    ["command: trailing whitespace", (a) => void (a.action.command = "rm temp.txt ")],
    ["command: leading whitespace", (a) => void (a.action.command = " rm temp.txt")],
    ["command: inner whitespace", (a) => void (a.action.command = "rm  temp.txt")],
    ["command: tab vs space", (a) => void (a.action.command = "rm\ttemp.txt")],
    ["command: case", (a) => void (a.action.command = "RM temp.txt")],
    ["command: appended chained command", (a) => void (a.action.command = "rm temp.txt; rm -rf /")],
    ["command: removed", (a) => void delete a.action.command],
    ["cwd", (a) => void (a.action.cwd = "/")],
    ["cwd: removed", (a) => void delete a.action.cwd],
    ["tool", (a) => void (a.action.tool = "Write")],
    ["tool: removed", (a) => void delete a.action.tool],
    ["arguments: value", (a) => void (a.action.arguments = { path: "/etc/passwd", flags: ["-v"] })],
    ["arguments: array order", (a) => void (a.action.arguments = { path: "temp.txt", flags: ["-v", "-f"] })],
    ["arguments: extra key", (a) => void (a.action.arguments = { ...a.action.arguments, force: true })],
    ["arguments: removed", (a) => void delete a.action.arguments],
    ["arguments: empty object vs absent", (a) => void (a.action.arguments = {})],
    ["resource.environment", (a) => void (a.resource.environment = "production")],
    ["resource.environment: removed", (a) => void delete a.resource.environment],
    ["resource.name", (a) => void (a.resource.name = "prod-db")],
    ["resource.type", (a) => void (a.resource.type = "database")],
    ["agent type", (a) => void (a.agent.type = "codex")],
    ["session_id", (a) => void (a.session_id = "ses_2")],
    ["category", (a) => void (a.action.category = "filesystem")],
    ["operation", (a) => void (a.action.operation = "delete")],
  ])("%s", (_name, fn) => {
    expect(computeActionHash(mutate(fn))).not.toBe(baseHash);
  });

  it("does not confuse fields with each other (command vs cwd swap)", () => {
    const a = makeAction({ action: { category: "shell", operation: "execute", command: "x", cwd: "y" } });
    const b = makeAction({ action: { category: "shell", operation: "execute", command: "y", cwd: "x" } });
    expect(computeActionHash(a)).not.toBe(computeActionHash(b));
  });

  it("distinguishes an empty-string field from an absent one", () => {
    const a = mutate((x) => void (x.action.cwd = ""));
    const b = mutate((x) => void delete x.action.cwd);
    expect(computeActionHash(a)).not.toBe(computeActionHash(b));
  });
});

describe("actionHashInput", () => {
  it("covers exactly the documented fields", () => {
    expect(Object.keys(actionHashInput(base)).sort()).toEqual(
      ["agent", "arguments", "category", "command", "cwd", "operation", "resource", "session_id", "tool", "v"].sort(),
    );
    expect(Object.keys(actionHashInput(base).resource).sort()).toEqual(["environment", "name", "type"]);
  });

  it("carries a version tag", () => {
    expect(actionHashInput(base).v).toBe(1);
  });
});
