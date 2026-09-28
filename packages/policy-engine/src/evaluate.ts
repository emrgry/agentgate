import type { ActionDraft, CanonicalAction, PolicyDecision, Risk } from "@agentgate/protocol";
import type { Policy, Rule } from "./policy.ts";
import { analyzeShell, hasFlags, parseSegment, type ParsedSegment } from "./shell.ts";
import { assessShellSegment, classifyStructured, inferEnvironment, maxRisk, RISK_ORDER } from "./risk.ts";
import { assessMcp, globMatch, isMcpInvoke, type McpIdentity } from "./mcp.ts";
import { defaultHome, normalizePath, pathMatchesAny, structuredPaths, type PathContext } from "./paths.ts";

export interface SegmentEvaluation {
  segment: string;
  decision: PolicyDecision;
  risk: Risk;
  rule_id: string | null;
}

export interface PolicyEvaluation {
  decision: PolicyDecision;
  risk: Risk;
  /** Rule that produced the final (most restrictive) decision, if any. */
  rule_id: string | null;
  reason: string;
  environment: string | undefined;
  segments: SegmentEvaluation[];
}

const DECISION_ORDER: Record<PolicyDecision, number> = { allow: 0, ask: 1, deny: 2 };

export interface EvaluateOptions {
  /** Home directory for `~` / `$HOME` expansion. Defaults to os.homedir(). */
  home?: string;
}

/** Per-segment facts used for rule matching. */
interface SegmentFacts {
  parsed: ParsedSegment | null;
  writes: string[];
  deletes: string[];
  recognized: boolean;
  mcp?: McpIdentity;
}

/**
 * Evaluate an action against a policy. Pure and deterministic.
 *
 * Shell commands are split into sub-commands; each is judged independently and the
 * most restrictive result wins (`git status && rm -rf /` is not "git status").
 * Commands we cannot see through (substitution, eval, sh -c) are never auto-allowed.
 */
export function evaluatePolicy(policy: Policy, action: CanonicalAction | ActionDraft, opts: EvaluateOptions = {}): PolicyEvaluation {
  const environment = inferEnvironment(action.action, action.resource);
  const ctx: PathContext = { cwd: action.action.cwd, home: opts.home ?? defaultHome() };
  const isShell = typeof action.action.command === "string" && action.action.command.trim().length > 0;

  const segments: SegmentEvaluation[] = [];
  let opaqueReason: string | null = null;
  // Adapters may assert a higher risk than we infer; it is a floor for every segment, so
  // it also drives risk-based defaults and `risk_at_least` rules (never lowers anything).
  const floor = (r: Risk): Risk => (action.risk ? maxRisk(r, action.risk) : r);

  if (isShell) {
    const analysis = analyzeShell(action.action.command!);
    opaqueReason = analysis.opaqueReason;
    const segs = analysis.segments.length ? analysis.segments : [action.action.command!.trim()];
    for (const segment of segs) {
      const a = assessShellSegment(segment, environment, ctx);
      const facts: SegmentFacts = { parsed: parseSegment(segment), writes: a.writes, deletes: a.deletes, recognized: a.recognized };
      segments.push(decide(policy, action, environment, floor(a.risk), segment, facts, ctx));
    }
    // A typed action (e.g. database.drop) that also carries a command is judged on both:
    // the command cannot launder the category's risk. Plain shell actions have no
    // category-level classification beyond the command itself.
    if (action.action.category !== "shell") {
      segments.push(decideStructured(policy, action, environment, floor, ctx));
    }
  } else {
    segments.push(decideStructured(policy, action, environment, floor, ctx));
    // Shell commands passed as MCP tool arguments are judged like shell commands too
    // (rules such as deny-rm-rf apply; opaque constructs are never auto-allowed).
    if (isMcpInvoke(action.action)) {
      for (const command of assessMcp(action.action, ctx).commands) {
        const analysis = analyzeShell(command);
        opaqueReason ??= analysis.opaqueReason;
        for (const segment of analysis.segments) {
          const a = assessShellSegment(segment, environment, ctx);
          const facts: SegmentFacts = { parsed: parseSegment(segment), writes: a.writes, deletes: a.deletes, recognized: a.recognized };
          segments.push(decide(policy, action, environment, floor(a.risk), segment, facts, ctx));
        }
      }
    }
  }

  let final = segments[0]!;
  let risk = final.risk;
  for (const s of segments.slice(1)) {
    if (DECISION_ORDER[s.decision] > DECISION_ORDER[final.decision]) final = s;
    risk = maxRisk(risk, s.risk);
  }

  let decision = final.decision;
  let reason = final.rule_id ? `matched rule ${final.rule_id}: ${final.risk.reason}` : final.risk.reason;
  if (opaqueReason && decision === "allow") {
    decision = "ask";
    risk = maxRisk(risk, { level: "high", reason: `cannot statically analyze: ${opaqueReason}` });
    reason = `cannot statically analyze: ${opaqueReason}`;
  }
  // Adapters may assert a higher risk than we inferred; never lower it.
  if (action.risk && RISK_ORDER[action.risk.level] > RISK_ORDER[risk.level]) risk = action.risk;

  return { decision, risk, rule_id: final.rule_id, reason, environment, segments };
}

function decideStructured(
  policy: Policy,
  action: CanonicalAction | ActionDraft,
  environment: string | undefined,
  floor: (r: Risk) => Risk,
  ctx: PathContext,
): SegmentEvaluation {
  const risk = floor(classifyStructured(action.action, environment, ctx));
  if (isMcpInvoke(action.action)) {
    const m = assessMcp(action.action, ctx);
    const facts: SegmentFacts = { parsed: null, writes: m.writes, deletes: m.deletes, recognized: m.recognized, mcp: m.identity };
    return decide(policy, action, environment, risk, null, facts, ctx);
  }
  const isFs = action.action.category === "filesystem" && action.action.operation !== "read";
  const paths = isFs ? structuredPaths(action.action.arguments).map((p) => normalizePath(p, ctx)) : [];
  const del = action.action.operation === "delete";
  const facts: SegmentFacts = { parsed: null, writes: del ? [] : paths, deletes: del ? paths : [], recognized: true };
  return decide(policy, action, environment, risk, null, facts, ctx);
}

function decide(
  policy: Policy,
  action: CanonicalAction | ActionDraft,
  environment: string | undefined,
  risk: Risk,
  segment: string | null,
  facts: SegmentFacts,
  ctx: PathContext,
): SegmentEvaluation {
  for (const rule of policy.rules) {
    if (ruleMatches(rule, action, environment, risk, segment, facts, ctx)) {
      return { segment: segment ?? "", decision: rule.decision, risk, rule_id: rule.id ?? null };
    }
  }
  let decision = policy.defaults[risk.level];
  // Allowlist posture: a shell command that matches no known-safe shape is never
  // auto-allowed by the risk defaults alone.
  if (!facts.recognized && DECISION_ORDER[policy.defaults.unrecognized] > DECISION_ORDER[decision]) {
    decision = policy.defaults.unrecognized;
  }
  return { segment: segment ?? "", decision, risk, rule_id: null };
}

function ruleMatches(
  rule: Rule,
  action: CanonicalAction | ActionDraft,
  environment: string | undefined,
  risk: Risk,
  segment: string | null,
  facts: SegmentFacts,
  ctx: PathContext,
): boolean {
  const m = rule.match;
  const needsCommand = m.command_prefix || m.contains || m.regex || m.binary || m.flags || m.wrapper;
  if (needsCommand && segment === null) return false;
  const parsed = facts.parsed;
  if (m.writes_to) {
    const hit =
      facts.writes.some((t) => pathMatchesAny(t, m.writes_to!, ctx, false)) ||
      facts.deletes.some((t) => pathMatchesAny(t, m.writes_to!, ctx, true));
    if (!hit) return false;
  }
  if (m.risk_at_most && RISK_ORDER[risk.level] > RISK_ORDER[m.risk_at_most]) return false;
  if (m.mcp_server || m.mcp_tool) {
    // MCP keys only apply to the mcp.invoke segment itself (not to shell commands found in its arguments).
    if (!facts.mcp || segment !== null) return false;
    if (m.mcp_server && !m.mcp_server.some((g) => globMatch(g, facts.mcp!.server))) return false;
    if (m.mcp_tool && !m.mcp_tool.some((g) => globMatch(g, facts.mcp!.tool))) return false;
  }

  if (m.binary && !m.binary.some((b) => basename(b) === parsed!.argv[0])) return false;
  if (m.flags && !hasFlags(parsed!.argv, m.flags)) return false;
  if (m.wrapper && !m.wrapper.some((w) => parsed!.wrappers.includes(basename(w)))) return false;
  if (m.command_prefix) {
    const argv = parsed!.argv;
    const ok = m.command_prefix.some((prefix) => {
      // Normalize the rule the same way as the command (`/usr/bin/git push` ≡ `git push`).
      const p = prefix.trim().split(/\s+/);
      if (p[0]!.includes("/")) p[0] = p[0]!.slice(p[0]!.lastIndexOf("/") + 1);
      return p.length <= argv.length && p.every((tok, i) => argv[i] === tok);
    });
    if (!ok) return false;
  }
  if (m.contains && !m.contains.every((s) => segment!.includes(s))) return false;
  if (m.regex && !new RegExp(m.regex).test(segment!)) return false;
  if (m.category && m.category !== action.action.category) return false;
  if (m.operation && m.operation !== action.action.operation) return false;
  if (m.action_type && !m.action_type.includes(`${action.action.category}.${action.action.operation}`)) return false;
  if (m.environment && m.environment !== environment) return false;
  if (m.agent && m.agent !== action.agent.type) return false;
  if (m.risk_at_least && RISK_ORDER[risk.level] < RISK_ORDER[m.risk_at_least]) return false;
  return true;
}

function basename(word: string): string {
  const i = word.lastIndexOf("/");
  return i >= 0 && i < word.length - 1 ? word.slice(i + 1) : word;
}
