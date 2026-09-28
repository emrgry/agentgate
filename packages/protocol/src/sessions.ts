import { z } from "zod";
import { SignedDecision } from "./local-first.ts";

/**
 * Control Center contract (docs/control-center.md). Provider-agnostic: adapters map
 * provider output (Claude stream-json, hooks, Codex JSON, PTY) into these shapes.
 */

export const SESSION_STATUSES = [
  "starting",
  "running",
  "waiting_input",
  "awaiting_approval",
  "paused",
  "stopping",
  "completed",
  "failed",
  "stopped",
  "killed",
  "lost",
] as const;
export const SessionStatus = z.enum(SESSION_STATUSES);
export type SessionStatus = z.infer<typeof SessionStatus>;

export const TERMINAL_SESSION_STATUSES: readonly SessionStatus[] = [
  "completed",
  "failed",
  "stopped",
  "killed",
  "lost",
];

export const SessionMode = z.enum(["managed", "observed"]);
export type SessionMode = z.infer<typeof SessionMode>;

export const SessionUsage = z.object({
  /**
   * For subscription logins (e.g. Claude Code signed in with claude.ai) this is the
   * provider's API-price ESTIMATE, not money charged — see cost_kind.
   */
  cost_usd: z.number().nonnegative().nullable(),
  cost_kind: z.enum(["api", "subscription_estimate", "unknown"]).optional(),
  input_tokens: z.number().int().nonnegative().nullable(),
  output_tokens: z.number().int().nonnegative().nullable(),
  duration_ms: z.number().int().nonnegative().nullable(),
  turns: z.number().int().nonnegative(),
});
export type SessionUsage = z.infer<typeof SessionUsage>;

export const SessionSummary = z.object({
  /** Last assistant message, trimmed (≤ 4 KB). */
  last_message: z.string().max(4096).nullable(),
  /** `git diff --stat` style numbers for the session's cwd, if a git repo. */
  files_changed: z.number().int().nonnegative().nullable(),
  additions: z.number().int().nonnegative().nullable(),
  deletions: z.number().int().nonnegative().nullable(),
  changed_files: z.array(z.string()).max(200).default([]),
  error: z.string().max(2048).nullable(),
});
export type SessionSummary = z.infer<typeof SessionSummary>;

export const AgentSession = z.object({
  id: z.string(),
  provider: z.string(), // "claude-code" | "codex" | …
  provider_session_id: z.string().nullable(),
  mode: SessionMode,
  title: z.string().max(200),
  cwd: z.string(),
  repo: z.string().nullable(),
  branch: z.string().nullable(),
  status: SessionStatus,
  /** Phase 2: the running/current task and how many are queued behind it (optional for older servers). */
  current_task_id: z.string().nullable().optional(),
  queued_tasks: z.number().int().nonnegative().optional(),
  /**
   * false = tool calls of this session are NOT checked by AgentGate (provider without hooks,
   * started via an explicit per-workspace opt-in). The phone shows a red "UNGATED" badge.
   * Absent = gated (older servers).
   */
  gated: z.boolean().optional(),
  /** Pending interaction the user should answer (status waiting_input). */
  pending_interaction_id: z.string().nullable(),
  started_at: z.string().datetime(),
  last_event_at: z.string().datetime(),
  ended_at: z.string().datetime().nullable(),
  usage: SessionUsage,
  summary: SessionSummary.nullable(),
  /** What the phone may do right now, computed by the server from mode + status. */
  can: z.object({
    instruct: z.boolean(),
    pause: z.boolean(),
    resume: z.boolean(),
    stop: z.boolean(),
    kill: z.boolean(),
    continue_remotely: z.boolean(),
  }),
});
export type AgentSession = z.infer<typeof AgentSession>;

export const SESSION_EVENT_TYPES = [
  "session.started",
  "status.changed",
  "message.user",
  "message.assistant",
  "tool.call",
  "tool.result",
  "approval.requested",
  "input.required",
  "turn.completed",
  "session.completed",
  "session.failed",
  "session.terminated",
  "control.applied",
] as const;
/** Open string on the wire (forward compatible); these are the known values. */
export const SessionEventType = z.string().min(1).max(64);

export const SessionEvent = z.object({
  id: z.string(),
  session_id: z.string(),
  /** Monotonic per session; clients page and dedupe by seq. */
  seq: z.number().int().nonnegative(),
  type: SessionEventType,
  /**
   * Type-specific, already redacted (secrets masked) and size-capped (≤ 8 KB):
   * message.*: {text}; tool.call: {tool, summary}; tool.result: {tool, ok, summary};
   * status.changed: {from, to, reason?}; input.required: {interaction_id, prompt};
   * turn.completed: {usage}; session.completed: {summary}; session.failed: {error};
   * approval.requested: {approval_id}; control.applied: {command, by_device}.
   */
  payload: z.record(z.string(), z.unknown()),
  created_at: z.string().datetime(),
});
export type SessionEvent = z.infer<typeof SessionEvent>;

export const Interaction = z.object({
  id: z.string(),
  session_id: z.string(),
  kind: z.string(), // "input_required" | "question" | "budget" (Phase 4)
  prompt: z.string().max(4096),
  status: z.enum(["pending", "answered", "expired", "cancelled"]),
  answer: z.string().max(16_384).nullable(),
  created_at: z.string().datetime(),
  resolved_at: z.string().datetime().nullable(),
});
export type Interaction = z.infer<typeof Interaction>;

export const Workspace = z.object({
  id: z.string(),
  path: z.string(),
  label: z.string(),
  /** Providers explicitly allowed to run UNGATED in this workspace (`agentgate workspace allow-ungated`). */
  ungated_providers: z.array(z.string()).optional(),
});
export type Workspace = z.infer<typeof Workspace>;

// ── Phone-signed control commands ────────────────────────────────────────────
export const CONTROL_COMMANDS = [
  "instruct", "answer", "pause", "resume", "stop", "kill", "start",
  // Phase 2 — task queue
  "enqueue_task", "cancel_task", "move_task",
  // Phase 3 — review
  "request_changes", "open_pr", "approve_next",
  // Phase 4 — limits
  "set_limits",
] as const;
export const ControlCommandName = z.enum(CONTROL_COMMANDS);
export type ControlCommandName = z.infer<typeof ControlCommandName>;

/**
 * Signed exactly like DecisionPayloadV2 (same compact "v2." envelope, same device key),
 * but `kind: "command"` so a decision can never be replayed as a command or vice versa.
 * `payload_hash` = SHA-256 hex of canonicalJson(command body) — the body travels next to
 * the signature and the verifier recomputes the hash.
 */
export const CommandPayloadV2 = z.object({
  v: z.literal(2),
  kind: z.literal("command"),
  command: ControlCommandName,
  /** Target session; for "start" the literal "new". */
  session_id: z.string(),
  payload_hash: z.string().regex(/^[a-f0-9]{64}$/),
  device_id: z.string(),
  issued_at: z.string().datetime(),
  expires_at: z.string().datetime(),
  nonce: z.string().min(16).max(64).regex(/^[A-Za-z0-9_-]+$/),
});
export type CommandPayloadV2 = z.infer<typeof CommandPayloadV2>;

/** Command bodies (what payload_hash covers). */
export const CommandBody = z.discriminatedUnion("command", [
  z.object({ command: z.literal("instruct"), text: z.string().min(1).max(16_384) }),
  z.object({ command: z.literal("answer"), interaction_id: z.string(), text: z.string().min(1).max(16_384) }),
  z.object({ command: z.literal("pause") }),
  z.object({ command: z.literal("resume") }),
  z.object({ command: z.literal("stop") }),
  z.object({ command: z.literal("kill") }),
  z.object({ command: z.literal("enqueue_task"), text: z.string().min(1).max(16_384), title: z.string().max(200).optional() }),
  z.object({ command: z.literal("cancel_task"), task_id: z.string() }),
  /** Review feedback → delivered to the agent as the next instruction (queued if running). */
  z.object({ command: z.literal("request_changes"), text: z.string().min(1).max(16_384), task_id: z.string().optional() }),
  /** Server pushes the branch and runs `gh pr create` in the session cwd (never force-push). */
  z.object({
    command: z.literal("open_pr"),
    title: z.string().max(200).optional(),
    draft: z.boolean().optional(),
    base: z.string().max(200).optional(),
    /**
     * When the session is on the default branch: create this branch at HEAD first
     * (must match ^[A-Za-z0-9._/-]{1,100}$, no "..", not the default branch). The local
     * default branch is left as-is; only the new branch is pushed.
     */
    create_branch: z.string().max(100).optional(),
  }),
  /**
   * Phase 4: set/replace limits for a session (session_id = target) or globally
   * (session_id = "global"). Raising a limit is as sensitive as approving — signed + Face ID.
   */
  z.object({
    command: z.literal("set_limits"),
    limits: z.lazy(() => Limits),
  }),
  /** Accept the reviewed task: continue with the next queued task (like resume on a paused queue). */
  z.object({ command: z.literal("approve_next"), task_id: z.string().optional() }),
  z.object({ command: z.literal("move_task"), task_id: z.string(), position: z.number().int().nonnegative() }),
  z.object({
    command: z.literal("start"),
    provider: z.string(),
    workspace_id: z.string(),
    prompt: z.string().min(1).max(16_384),
    title: z.string().max(200).optional(),
  }),
]);
export type CommandBody = z.infer<typeof CommandBody>;

/** POST /v1/agent-sessions/:id/commands  (and POST /v1/agent-sessions for "start"). */
export const SubmitCommandRequest = z.object({
  device_id: z.string(),
  body: CommandBody,
  signed_command: SignedDecision, // same compact envelope format
});
export const SubmitCommandResponse = z.object({
  command_id: z.string(),
  status: z.enum(["queued", "applied", "rejected"]),
  session: z.lazy(() => AgentSession),
  reason: z.string().nullable(),
  /** Machine-readable rejection code, e.g. "default_branch" (clients can offer a fix). */
  reason_code: z.string().nullable().optional(),
});

// ── REST ──────────────────────────────────────────────────────────────────────
/** GET /v1/agent-sessions?status=active|all&limit= */
export const ListAgentSessionsResponse = z.object({ items: z.array(AgentSession) });
/** GET /v1/agent-sessions/:id → AgentSession.  GET /v1/agent-sessions/:id/events?after_seq=|before_seq=&limit= (before_seq pages backwards; items always ascending by seq) */
export const ListSessionEventsResponse = z.object({ items: z.array(SessionEvent), next_after_seq: z.number().int().nullable() });
/** GET /v1/workspaces */
export const ListWorkspacesResponse = z.object({ items: z.array(Workspace) });

// ── Realtime (device WebSocket) ───────────────────────────────────────────────
export const SessionUpdatedEvent = z.object({ type: z.literal("session.updated"), session: AgentSession });
export const SessionEventPushed = z.object({ type: z.literal("session.event"), event: SessionEvent });

// ── Phase 2: task queue ──────────────────────────────────────────────────────
export const TASK_STATUSES = ["queued", "running", "waiting", "completed", "failed", "cancelled"] as const;
export const TaskStatus = z.enum(TASK_STATUSES);
export type TaskStatus = z.infer<typeof TaskStatus>;

/**
 * A unit of work inside a session. The first prompt of a session is task #1; each
 * `enqueue_task` appends one. The supervisor runs the next queued task (as a --resume
 * turn) when the current one completes without a pending question. `waiting` = the task's
 * turn ended with a question (session waiting_input); answering continues the same task.
 * A plain `instruct` (not a task) is delivered to the running/current task.
 */
export const AgentTask = z.object({
  id: z.string(),
  session_id: z.string(),
  position: z.number().int().nonnegative(),
  title: z.string().max(200),
  prompt: z.string().max(16_384),
  status: TaskStatus,
  created_at: z.string().datetime(),
  started_at: z.string().datetime().nullable(),
  ended_at: z.string().datetime().nullable(),
  usage: SessionUsage.nullable(),
  summary: SessionSummary.nullable(),
});
export type AgentTask = z.infer<typeof AgentTask>;

/** GET /v1/agent-sessions/:id/tasks — ordered by position. */
export const ListTasksResponse = z.object({ items: z.array(AgentTask) });
/** WS (device sockets). */
export const TaskUpdatedEvent = z.object({ type: z.literal("task.updated"), task: AgentTask });

/** Phase 2: providers the server can run (GET /v1/providers). */
export const ProviderInfo = z.object({
  id: z.string(),
  display_name: z.string(),
  available: z.boolean(),
  /** Why unavailable, e.g. "codex not found on PATH". */
  reason: z.string().nullable(),
  capabilities: z.object({ resume: z.boolean(), pause: z.boolean(), cost: z.boolean(), observe: z.boolean() }),
  /** false = AgentGate can't gate this provider's tool calls (needs a workspace opt-in). Absent = gated. */
  gated: z.boolean().optional(),
});
export type ProviderInfo = z.infer<typeof ProviderInfo>;
export const ListProvidersResponse = z.object({ items: z.array(ProviderInfo) });

// ── Phase 3: mobile PR / diff review ─────────────────────────────────────────
export const ChangedFile = z.object({
  path: z.string(),
  old_path: z.string().nullable(),
  status: z.string(), // added | modified | deleted | renamed | untracked | …
  additions: z.number().int().nonnegative().nullable(),
  deletions: z.number().int().nonnegative().nullable(),
  binary: z.boolean(),
});
export type ChangedFile = z.infer<typeof ChangedFile>;

export const TestRun = z.object({
  command: z.string(),
  ok: z.boolean(),
  passed: z.number().int().nonnegative().nullable(),
  failed: z.number().int().nonnegative().nullable(),
  skipped: z.number().int().nonnegative().nullable(),
  /** Last lines of output, redacted, ≤ 4 KB. */
  output_tail: z.string().max(4096),
  finished_at: z.string().datetime(),
});
export type TestRun = z.infer<typeof TestRun>;

export const PullRequestInfo = z.object({
  url: z.string().url(),
  number: z.number().int().positive(),
  state: z.string(), // open | draft | merged | closed
  title: z.string().max(300),
});
export type PullRequestInfo = z.infer<typeof PullRequestInfo>;

/**
 * GET /v1/agent-sessions/:id/changes[?task_id=] — what the session (or one task) changed
 * relative to the base captured when the session/task started (not HEAD of an older run).
 */
export const ChangeSet = z.object({
  session_id: z.string(),
  task_id: z.string().nullable(),
  base_ref: z.string().nullable(),
  branch: z.string().nullable(),
  files: z.array(ChangedFile).max(1000),
  totals: z.object({ files: z.number().int(), additions: z.number().int(), deletions: z.number().int() }),
  /** Latest test run observed in the session (a Bash tool call matching a test command). */
  tests: TestRun.nullable(),
  pr: PullRequestInfo.nullable(),
  truncated: z.boolean(),
});
export type ChangeSet = z.infer<typeof ChangeSet>;

/** GET /v1/agent-sessions/:id/diff?path=&task_id= — unified diff for one file, redacted. */
export const FileDiff = z.object({
  path: z.string(),
  patch: z.string().max(262_144),
  truncated: z.boolean(),
  binary: z.boolean(),
});
export type FileDiff = z.infer<typeof FileDiff>;

// ── Phase 4: cost & resource control ─────────────────────────────────────────
export const LIMIT_ACTIONS = ["notify", "ask", "pause", "stop"] as const;
export const LimitAction = z.enum(LIMIT_ACTIONS);
export type LimitAction = z.infer<typeof LimitAction>;

/**
 * All optional; null/absent = no limit. Evaluated by the supervisor after every event;
 * `on_exceed` decides what happens: notify only, ask (pause + budget interaction the user
 * answers with "continue"/"stop"), pause, or stop.
 */
export const Limits = z.object({
  max_cost_usd_per_task: z.number().positive().nullable().optional(),
  max_cost_usd_per_session: z.number().positive().nullable().optional(),
  max_session_minutes: z.number().int().positive().nullable().optional(),
  max_task_minutes: z.number().int().positive().nullable().optional(),
  max_retries: z.number().int().nonnegative().nullable().optional(),
  max_rss_mb: z.number().int().positive().nullable().optional(),
  on_exceed: LimitAction.default("ask"),
});
export type Limits = z.infer<typeof Limits>;

/** Live resource sample for a running turn's process tree (sampled ~every 5 s). */
export const ResourceSample = z.object({
  at: z.string().datetime(),
  cpu_percent: z.number().nonnegative(),
  rss_mb: z.number().nonnegative(),
  processes: z.number().int().nonnegative(),
});
export type ResourceSample = z.infer<typeof ResourceSample>;

/** GET /v1/agent-sessions/:id/metrics */
export const SessionMetrics = z.object({
  session_id: z.string(),
  usage: SessionUsage,
  /** Retries = failed turns re-run + provider api_retry events. */
  retries: z.number().int().nonnegative(),
  resources: ResourceSample.nullable(),
  /** Recent samples for a sparkline (≤ 120). */
  history: z.array(ResourceSample).max(120),
  limits: Limits.nullable(),
  /** Which limits were hit (keys of Limits), latest first. */
  exceeded: z.array(z.object({ limit: z.string(), value: z.number(), at: z.string().datetime(), action: LimitAction })),
  /** Processes a turn left running (e.g. Claude Code background Bash commands); killed by kill/stop. */
  background_processes: z.array(z.object({ pid: z.number().int(), command: z.string() })).optional(),
  /** Human notes, e.g. "Codex reports no cost; cost limits are not enforced for this session". */
  notes: z.array(z.string()).optional(),
});
export type SessionMetrics = z.infer<typeof SessionMetrics>;

/** GET /v1/usage?range=today|7d|30d — aggregates for the dashboard. */
export const UsageReport = z.object({
  range: z.string(),
  total_cost_usd: z.number().nonnegative().nullable(),
  by_provider: z.array(
    z.object({
      provider: z.string(),
      sessions: z.number().int(),
      cost_usd: z.number().nullable(),
      input_tokens: z.number().int().nullable(),
      output_tokens: z.number().int().nullable(),
      duration_ms: z.number().int(),
      /** How to read cost_usd for this provider (see SessionUsage.cost_kind). */
      cost_kind: z.enum(["api", "subscription_estimate", "unknown"]).optional(),
    }),
  ),
  by_day: z.array(z.object({ day: z.string(), cost_usd: z.number().nullable(), sessions: z.number().int() })),
  global_limits: Limits.nullable(),
});
export type UsageReport = z.infer<typeof UsageReport>;

/** Interaction kind added in Phase 4 (open string on the wire for older clients): "budget". */
