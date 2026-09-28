import type { ActionDraft, Approval, CanonicalAction } from "@agentgate/protocol";

/** A fully populated canonical action; override any part per test. */
export function makeAction(overrides: Partial<CanonicalAction> = {}): CanonicalAction {
  return {
    action_id: "act_1",
    session_id: "ses_1",
    agent: { type: "claude-code", version: "2.0.0" },
    action: {
      category: "shell",
      operation: "execute",
      tool: "Bash",
      command: "rm temp.txt",
      arguments: { path: "temp.txt", flags: ["-v"] },
      cwd: "/work/demo",
    },
    resource: { type: "file", environment: "development", name: "temp.txt" },
    context: { repo: "agentgate/demo", branch: "main", hostname: "mbp" },
    risk: { level: "high", reason: "file deletion" },
    created_at: "2026-09-24T14:32:00.000Z",
    ...overrides,
  };
}

export function makeDraft(overrides: Partial<ActionDraft> = {}): ActionDraft {
  const { action_id: _a, created_at: _c, risk: _r, ...draft } = makeAction();
  return { ...draft, ...overrides };
}

export const T0 = new Date("2026-09-24T12:00:00.000Z");
export const at = (ms: number) => new Date(T0.getTime() + ms);

export function makeApproval(overrides: Partial<Approval> = {}): Approval {
  return {
    approval_id: "apr_1",
    action_id: "act_1",
    status: "pending",
    decision: null,
    requested_at: T0.toISOString(),
    expires_at: at(120_000).toISOString(),
    resolved_at: null,
    resolved_by_device_id: null,
    ...overrides,
  };
}
