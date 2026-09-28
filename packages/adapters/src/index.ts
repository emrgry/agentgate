import type { ActionDraft } from "@agentgate/protocol";

/**
 * An adapter translates one agent's native events into canonical AgentGate actions
 * and translates AgentGate decisions back into that agent's control mechanism.
 * Adapters must stay thin: no policy, no approval logic, no network calls.
 */
export interface AgentAdapter<NativeEvent = unknown, NativeResponse = unknown> {
  /** Stable adapter type, used as `agent.type` in canonical actions. */
  readonly type: string;

  /** Returns null when the event is not an action AgentGate governs. */
  normalize(event: NativeEvent, ctx: AdapterContext): ActionDraft | null;

  /** Render the final decision in the agent's native response format. */
  render(decision: AdapterDecision): NativeResponse;
}

export interface AdapterContext {
  session_id: string;
  agent_version?: string;
  cwd: string;
  repo?: string;
  branch?: string;
  environment?: string;
}

export type AdapterDecision =
  | { kind: "allow"; reason: string; rewrittenCommand?: string }
  | { kind: "deny"; reason: string };

// ── Control Center (docs/control-center.md §5): provider abstraction ─────────────────

/**
 * Normalized, provider-agnostic event. `type` is a session event type
 * (message.assistant, tool.call, tool.result, …) or one of the provider-internal
 * signals the supervisor consumes and never stores verbatim:
 *   provider.session      {provider_session_id}            — identity for --resume
 *   provider.turn_result  {ok, text, error, usage}          — end of a turn
 *   provider.turn_hint    {status: "completed"|"blocked", needs_action}
 *   provider.hook         {event, …}                        — observed-mode lifecycle
 */
export interface NormalizedEvent {
  type: string;
  payload: Record<string, unknown>;
}

export interface TurnUsage {
  cost_usd: number | null;
  input_tokens: number | null;
  output_tokens: number | null;
  duration_ms: number | null;
  num_turns: number | null;
}

export interface TurnCommand {
  cmd: string;
  args: string[];
  env?: Record<string, string>;
  /** Written to the process's stdin, then stdin is closed (keeps prompts out of argv/ps). */
  stdin?: string;
  /**
   * Gating tripwire: file (JSONL) where the provider's AgentGate PreToolUse hook records every
   * invocation/decision for this turn. When set, the supervisor kills the turn if a tool runs
   * without a matching record (hooks silently not firing = no gating).
   */
  gateReceipts?: string;
}

/** Per-turn stateful parser (delta accumulation, synthesized results at exit). */
export interface TurnParser {
  line(line: string): NormalizedEvent[];
  /** Called once when the process exits (before the supervisor evaluates the turn). */
  end(exitCode: number | null): NormalizedEvent[];
}

export type CostKind = "api" | "subscription_estimate" | "unknown";

export interface PreflightResult {
  ok: boolean;
  reason?: string;
}

export interface AgentProvider {
  id: string;
  /** Executable the provider runs (absolute path or a name looked up on the turn PATH). */
  binary?: string;
  /** Human name for notifications ("Claude Code"). */
  displayName: string;
  capabilities: { resume: boolean; pause: "signal" | "none"; observe: boolean; cost: boolean };
  buildTurnCommand(req: { instruction: string; providerSessionId?: string; cwd: string; hookSettingsPath: string; sessionId?: string }): TurnCommand;
  /** stream → events (pure; unknown input → []). */
  parseOutputLine(line: string): NormalizedEvent[];
  /** Heuristic for input_required at turn end. */
  isQuestion?(lastAssistantText: string): boolean;
  /** Observed mode: hook payload → events (pure). */
  normalizeHook?(hookEvent: unknown): NormalizedEvent[];
  /** Stateful per-turn parsing; when present it is used instead of parseOutputLine. */
  createParser?(): TurnParser;
  /** Checked before every turn (binary version, feature detection). Failing → the turn fails closed. */
  preflight?(env: NodeJS.ProcessEnv): PreflightResult;
  /** false = tool calls are not gated by AgentGate (default true). */
  gated?: boolean;
  /** How reported cost should be read (API billing vs a subscription's API-price estimate). Absent → "unknown". */
  detectCostKind?(env: NodeJS.ProcessEnv): Promise<CostKind>;
}
