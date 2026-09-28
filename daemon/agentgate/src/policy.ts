import { existsSync, readFileSync } from "node:fs";
import { DEFAULT_POLICY_YAML, loadPolicyYaml, type Policy } from "@agentgate/policy-engine";
import { paths } from "./config.ts";

export interface EffectivePolicy {
  policy: Policy;
  /** Absolute path of the user policy, or "built-in". */
  source: string;
  yaml: string;
}

/**
 * Loads ~/.agentgate/policy.yaml if present, else the built-in default.
 * A present-but-invalid policy file THROWS — callers must fail closed rather than
 * silently falling back to the (possibly more permissive) default.
 */
export function loadEffectivePolicy(): EffectivePolicy {
  const p = paths.policy();
  if (existsSync(p)) {
    const yaml = readFileSync(p, "utf8");
    try {
      return { policy: loadPolicyYaml(yaml), source: p, yaml };
    } catch (err) {
      throw new Error(`invalid policy file ${p}: ${(err as Error).message}`);
    }
  }
  return { policy: loadPolicyYaml(DEFAULT_POLICY_YAML), source: "built-in", yaml: DEFAULT_POLICY_YAML };
}
