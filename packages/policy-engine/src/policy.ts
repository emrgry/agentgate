import { z } from "zod";
import { parse as parseYaml } from "yaml";
import { PolicyDecision, RiskLevel } from "@agentgate/protocol";

/** Decisions are case-insensitive in YAML ("ASK", "Deny"). */
const decision = z
  .string()
  .transform((s) => s.toLowerCase())
  .pipe(PolicyDecision);

const stringOrList = z.union([z.string(), z.array(z.string()).min(1)]).transform((v) => (Array.isArray(v) ? v : [v]));

export const RuleMatch = z
  .object({
    /** Token-aware prefix of the effective command ("git push" ≠ "git pushx"). */
    command_prefix: stringOrList.optional(),
    /** All substrings must appear in the command segment. */
    contains: z.array(z.string()).min(1).optional(),
    /** JS regular expression tested against the command segment. */
    regex: z.string().optional(),
    /** Effective command name(s), compared by basename after wrappers are stripped ("rm" matches `sudo /bin/rm`). */
    binary: stringOrList.optional(),
    /**
     * Options that must all be present in the effective argv (before `--`). Each entry is a
     * `|`-separated list of alternatives; short flags also match inside bundles:
     * ["-r|-R|--recursive", "-f|--force"] matches `rm -rf`, `rm -Rf`, `rm -r -f`, `rm -rfv`.
     */
    flags: z.array(z.string().min(1)).min(1).optional(),
    /** Wrapper(s) the command was run through (`sudo`, `doas`, `env`, `nice`, …); any listed one matches. */
    wrapper: stringOrList.optional(),
    category: z.string().optional(),
    operation: z.string().optional(),
    /** "category.operation", e.g. "git.push". */
    action_type: stringOrList.optional(),
    environment: z.string().optional(),
    agent: z.string().optional(),
    risk_at_least: RiskLevel.optional(),
    /** Only matches when the (floored) risk is at most this level — keeps allow rules from allowing risky variants. */
    risk_at_most: RiskLevel.optional(),
    /**
     * Path globs (`**`, `*`, `?`, `~`). Matches when the segment writes or removes a
     * matching path (redirections, tee, cp/mv, rm, sed -i, chmod, …) or when a structured
     * filesystem write/delete targets one. Paths are normalized against action.cwd and
     * home; removing an ancestor of a pattern (e.g. `mv ~ /tmp/x`) also matches.
     */
    writes_to: stringOrList.optional(),
    /** MCP server name glob(s) (`*`, `?`); only matches mcp.invoke actions. */
    mcp_server: stringOrList.optional(),
    /** MCP tool name glob(s) (`get_*`, `list_*`); only matches mcp.invoke actions. */
    mcp_tool: stringOrList.optional(),
  })
  .strict()
  .refine((m) => Object.keys(m).length > 0, "match must have at least one condition");
export type RuleMatch = z.infer<typeof RuleMatch>;

export const Rule = z
  .object({
    id: z.string().optional(),
    description: z.string().optional(),
    match: RuleMatch,
    decision,
  })
  .strict();
export type Rule = z.infer<typeof Rule>;

export const Policy = z
  .object({
    version: z.literal(1).default(1),
    /** Decision by risk level when no rule matches. Strict: a typo'd level must not be silently ignored. */
    defaults: z
      .object({
        low: decision.default("allow"),
        medium: decision.default("allow"),
        high: decision.default("ask"),
        critical: decision.default("ask"),
        /** Shell commands that match no known-safe shape (see classifyShellSegment). */
        unrecognized: decision.default("ask"),
      })
      .strict()
      .default({}),
    rules: z.array(Rule).default([]),
  })
  .strict();
export type Policy = z.infer<typeof Policy>;

export function parsePolicy(input: unknown): Policy {
  const policy = Policy.parse(input);
  policy.rules.forEach((r, i) => {
    r.id ??= `rule_${i + 1}`;
    if (r.match.regex) new RegExp(r.match.regex); // fail fast on invalid regex
  });
  return policy;
}

export function loadPolicyYaml(source: string): Policy {
  return parsePolicy(parseYaml(source) ?? {});
}
