import { createHash } from "node:crypto";
import type { ActionDraft, CanonicalAction } from "@agentgate/protocol";
import { canonicalJson } from "./canonical-json.ts";

/**
 * The subset of an action that defines *what will be executed*. Identifiers,
 * timestamps, risk annotations and informational context are deliberately excluded:
 * they do not change the effect of the action, and including them would make the
 * hash unverifiable at execution time.
 *
 * Covered: agent type, category, operation, tool, command, arguments, cwd,
 * resource (type, environment, name), session.
 */
export function actionHashInput(a: CanonicalAction | ActionDraft) {
  return {
    v: 1,
    session_id: a.session_id,
    agent: a.agent.type,
    category: a.action.category,
    operation: a.action.operation,
    tool: a.action.tool ?? null,
    command: a.action.command ?? null,
    arguments: a.action.arguments ?? null,
    cwd: a.action.cwd ?? null,
    resource: {
      type: a.resource?.type ?? null,
      environment: a.resource?.environment ?? null,
      name: a.resource?.name ?? null,
    },
  };
}

/** SHA-256 (hex) over the canonical JSON of the hash input. */
export function computeActionHash(a: CanonicalAction | ActionDraft): string {
  return createHash("sha256").update(canonicalJson(actionHashInput(a)), "utf8").digest("hex");
}
