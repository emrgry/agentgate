import type { ActionDraft, ActionSpec, Resource, Risk } from "@agentgate/protocol";
import { DEFAULT_POLICY_YAML, evaluatePolicy, loadPolicyYaml, type Policy, type PolicyEvaluation } from "../src/index.ts";

export const DEFAULT_POLICY = loadPolicyYaml(DEFAULT_POLICY_YAML);
/** Fixed home so `~` expansion is deterministic across machines. */
export const HOME = "/Users/tester";
export const PROJECT = "/Users/tester/proj";

export interface ShellOpts {
  policy?: Policy;
  environment?: string;
  risk?: Risk;
  agent?: string;
  cwd?: string;
}

export function shellAction(command: string, opts: ShellOpts = {}): ActionDraft {
  const resource: Resource = opts.environment ? { environment: opts.environment } : {};
  return {
    session_id: "ses_1",
    agent: { type: opts.agent ?? "claude-code" },
    action: { category: "shell", operation: "execute", tool: "Bash", command, ...(opts.cwd ? { cwd: opts.cwd } : {}) },
    resource,
    context: {},
    ...(opts.risk ? { risk: opts.risk } : {}),
  };
}

export function evalShell(command: string, opts: ShellOpts = {}): PolicyEvaluation {
  return evaluatePolicy(opts.policy ?? DEFAULT_POLICY, shellAction(command, opts), { home: HOME });
}

export function structuredAction(
  spec: Omit<ActionSpec, "command"> & { command?: string },
  opts: { environment?: string; risk?: Risk; agent?: string } = {},
): ActionDraft {
  return {
    session_id: "ses_1",
    agent: { type: opts.agent ?? "claude-code" },
    action: spec,
    resource: opts.environment ? { environment: opts.environment } : {},
    context: {},
    ...(opts.risk ? { risk: opts.risk } : {}),
  };
}
