import { describe, expect, it } from "vitest";
import { DEFAULT_POLICY_YAML, loadPolicyYaml, parsePolicy } from "../src/index.ts";
import { evalShell } from "./helpers.ts";

describe("DEFAULT_POLICY_YAML", () => {
  const policy = loadPolicyYaml(DEFAULT_POLICY_YAML);

  it("parses", () => {
    expect(policy.version).toBe(1);
  });

  it("has the documented defaults", () => {
    expect(policy.defaults).toEqual({ low: "allow", medium: "allow", high: "ask", critical: "ask", unrecognized: "ask" });
  });

  it("has the documented rules, in order", () => {
    expect(policy.rules.map((r) => [r.id, r.decision])).toEqual([
      ["deny-rm-rf", "deny"],
      ["deny-mcp-self-reconfigure", "deny"],
      ["deny-protected-paths", "deny"],
      ["ask-mcp-destructive", "ask"],
      ["ask-git-push", "ask"],
      ["ask-kubectl-production", "ask"],
      ["allow-git-status", "allow"],
      ["allow-npm-test", "allow"],
      ["allow-dev-scripts", "allow"],
    ]);
  });

  it("deny-rm-rf is a structured argv match, not a regex", () => {
    const rule = policy.rules.find((r) => r.id === "deny-rm-rf")!;
    expect(rule.match.regex).toBeUndefined();
    expect(rule.match.binary).toEqual(["rm"]);
    expect(rule.match.flags).toEqual(["-r|-R|--recursive", "-f|--force"]);
  });
});

describe("loadPolicyYaml — defaults and normalisation", () => {
  it("empty document → all defaults, no rules", () => {
    const p = loadPolicyYaml("");
    expect(p).toEqual({
      version: 1,
      defaults: { low: "allow", medium: "allow", high: "ask", critical: "ask", unrecognized: "ask" },
      rules: [],
    });
  });

  it("partial defaults are filled in", () => {
    expect(loadPolicyYaml("defaults: { high: deny }").defaults).toEqual({
      low: "allow",
      medium: "allow",
      high: "deny",
      critical: "ask",
      unrecognized: "ask",
    });
  });

  it("assigns ids to rules without one", () => {
    const p = loadPolicyYaml(`
rules:
  - match: { command_prefix: a }
    decision: allow
  - id: named
    match: { command_prefix: b }
    decision: deny
  - match: { command_prefix: c }
    decision: ask
`);
    expect(p.rules.map((r) => r.id)).toEqual(["rule_1", "named", "rule_3"]);
  });

  it("command_prefix / action_type accept a string or a list", () => {
    const p = loadPolicyYaml(`
rules:
  - match: { command_prefix: "git push", action_type: git.push }
    decision: ask
  - match: { command_prefix: ["a", "b"], action_type: [x.y, z.w] }
    decision: ask
`);
    expect(p.rules[0]!.match.command_prefix).toEqual(["git push"]);
    expect(p.rules[0]!.match.action_type).toEqual(["git.push"]);
    expect(p.rules[1]!.match.command_prefix).toEqual(["a", "b"]);
  });
});

describe("decisions are case-insensitive", () => {
  it.each(["ASK", "Ask", "aSk"])("rule decision %s → ask", (d) => {
    const p = loadPolicyYaml(`rules:\n  - match: { command_prefix: ls }\n    decision: ${d}\n`);
    expect(p.rules[0]!.decision).toBe("ask");
    expect(evalShell("ls", { policy: p }).decision).toBe("ask");
  });

  it.each([
    ["DENY", "deny"],
    ["Allow", "allow"],
  ])("rule decision %s → %s", (d, expected) => {
    expect(loadPolicyYaml(`rules:\n  - match: { contains: [x] }\n    decision: ${d}\n`).rules[0]!.decision).toBe(expected);
  });

  it("defaults are case-insensitive too", () => {
    const p = loadPolicyYaml("defaults: { low: ASK, medium: Deny, high: DENY, critical: Deny }");
    expect(p.defaults).toEqual({ low: "ask", medium: "deny", high: "deny", critical: "deny", unrecognized: "ask" });
    expect(evalShell("ls", { policy: p }).decision).toBe("ask");
  });
});

describe("invalid policies throw", () => {
  it.each([
    ["invalid regex", `rules:\n  - match: { regex: "([a-z" }\n    decision: deny\n`],
    ["invalid regex (bad quantifier)", `rules:\n  - match: { regex: "*rm" }\n    decision: deny\n`],
    ["unknown rule key", `rules:\n  - match: { command_prefix: ls }\n    decision: allow\n    priority: 1\n`],
    ["unknown match key", `rules:\n  - match: { command_prefx: ls }\n    decision: allow\n`],
    ["unknown top-level key", `rulez: []\n`],
    ["unknown defaults key (typo)", `defaults: { hihg: deny }\n`],
    ["bad decision", `rules:\n  - match: { command_prefix: ls }\n    decision: maybe\n`],
    ["bad default decision", `defaults: { high: block }\n`],
    ["missing decision", `rules:\n  - match: { command_prefix: ls }\n`],
    ["missing match", `rules:\n  - decision: allow\n`],
    ["empty match (would match everything)", `rules:\n  - match: {}\n    decision: allow\n`],
    ["empty command_prefix list", `rules:\n  - match: { command_prefix: [] }\n    decision: allow\n`],
    ["empty contains list", `rules:\n  - match: { contains: [] }\n    decision: allow\n`],
    ["bad risk_at_least", `rules:\n  - match: { risk_at_least: extreme }\n    decision: deny\n`],
    ["unsupported version", `version: 2\n`],
    ["rules not a list", `rules: { a: 1 }\n`],
    ["non-string decision", `rules:\n  - match: { command_prefix: ls }\n    decision: 1\n`],
    ["malformed YAML", `rules: [\n`],
    ["scalar document", `just a string`],
  ])("%s", (_name, yaml) => {
    expect(() => loadPolicyYaml(yaml)).toThrow();
  });

  it("parsePolicy validates plain objects the same way", () => {
    expect(() => parsePolicy({ rules: [{ match: { regex: "(" }, decision: "deny" }] })).toThrow();
    expect(() => parsePolicy({ rules: [{ match: { command_prefix: "ls" }, decision: "yes" }] })).toThrow();
    expect(parsePolicy({}).rules).toEqual([]);
  });
});
