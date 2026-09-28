import {
  bigserial,
  boolean,
  integer,
  char,
  index,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
} from "drizzle-orm/pg-core";

/** Schema from docs/architecture.md §3. Timestamps are set by the app clock, not DB now(). */

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });

export const users = pgTable("users", {
  id: text("id").primaryKey(),
  email: text("email").notNull().unique(),
  display_name: text("display_name"),
  created_at: ts("created_at").notNull(),
});

export const devices = pgTable(
  "devices",
  {
    id: text("id").primaryKey(),
    user_id: text("user_id")
      .notNull()
      .references(() => users.id),
    name: text("name").notNull(),
    push_token: text("push_token"),
    platform: text("platform").notNull(),
    created_at: ts("created_at").notNull(),
    last_seen_at: ts("last_seen_at"),
    revoked_at: ts("revoked_at"),
    /** Ed25519 raw public key (base64url), registered at pairing; changes only via a signed rekey. */
    public_key: text("public_key"),
    /** Last key rotation (POST /v1/devices/:id/rekey) and its proof signed by the previous key. */
    rekeyed_at: ts("rekeyed_at"),
    rekey_proof_json: jsonb("rekey_proof_json"),
  },
  (t) => [index("devices_user_idx").on(t.user_id)],
);

export const agents = pgTable(
  "agents",
  {
    id: text("id").primaryKey(),
    user_id: text("user_id")
      .notNull()
      .references(() => users.id),
    name: text("name").notNull(),
    type: text("type").notNull(),
    machine_id: text("machine_id").notNull(),
    created_at: ts("created_at").notNull(),
  },
  (t) => [uniqueIndex("agents_user_machine_type_uq").on(t.user_id, t.machine_id, t.type)],
);

export const sessions = pgTable(
  "sessions",
  {
    id: text("id").primaryKey(),
    agent_id: text("agent_id")
      .notNull()
      .references(() => agents.id),
    status: text("status", { enum: ["active", "ended"] }).notNull(),
    started_at: ts("started_at").notNull(),
    ended_at: ts("ended_at"),
  },
  (t) => [index("sessions_agent_idx").on(t.agent_id)],
);

export const EXECUTION_STATUSES = ["not_started", "started", "completed", "failed", "blocked"] as const;
export type ExecutionStatus = (typeof EXECUTION_STATUSES)[number];

export const actions = pgTable(
  "actions",
  {
    id: text("id").primaryKey(),
    session_id: text("session_id")
      .notNull()
      .references(() => sessions.id),
    category: text("category").notNull(),
    operation: text("operation").notNull(),
    payload_json: jsonb("payload_json").notNull(),
    action_hash: char("action_hash", { length: 64 }).notNull(),
    risk_level: text("risk_level").notNull(),
    policy_decision: text("policy_decision", { enum: ["allow", "ask", "deny"] }).notNull(),
    policy_rule_id: text("policy_rule_id"),
    execution_status: text("execution_status", { enum: EXECUTION_STATUSES }).notNull(),
    created_at: ts("created_at").notNull(),
  },
  (t) => [index("actions_session_created_idx").on(t.session_id, t.created_at)],
);

export const approvals = pgTable(
  "approvals",
  {
    id: text("id").primaryKey(),
    action_id: text("action_id")
      .notNull()
      .unique()
      .references(() => actions.id),
    status: text("status", {
      enum: ["pending", "approved", "denied", "expired", "cancelled"],
    }).notNull(),
    decision: text("decision", { enum: ["approve", "deny"] }),
    requested_at: ts("requested_at").notNull(),
    expires_at: ts("expires_at").notNull(),
    resolved_at: ts("resolved_at"),
    resolved_by_device_id: text("resolved_by_device_id").references(() => devices.id),
    token_nonce: text("token_nonce"),
    /** v2: the phone's SignedDecision, relayed verbatim as the approval token. */
    signed_decision: text("signed_decision"),
  },
  (t) => [index("approvals_status_expires_idx").on(t.status, t.expires_at)],
);

export const auditLogs = pgTable(
  "audit_logs",
  {
    id: text("id").primaryKey(),
    /** Monotonic tie-breaker so entries written in the same millisecond keep their order. */
    seq: bigserial("seq", { mode: "number" }).notNull(),
    user_id: text("user_id")
      .notNull()
      .references(() => users.id),
    event: text("event").notNull(),
    action_id: text("action_id"),
    approval_id: text("approval_id"),
    payload_json: jsonb("payload_json").notNull(),
    created_at: ts("created_at").notNull(),
  },
  (t) => [index("audit_logs_user_created_idx").on(t.user_id, t.created_at.desc())],
);

export const refreshTokens = pgTable(
  "refresh_tokens",
  {
    id: text("id").primaryKey(),
    user_id: text("user_id")
      .notNull()
      .references(() => users.id),
    /** All tokens rotated from one login share a family; reuse revokes the family. */
    family_id: text("family_id").notNull(),
    /** SHA-256 (hex) of the opaque token. The token itself is never stored. */
    token_hash: char("token_hash", { length: 64 }).notNull().unique(),
    audience: text("audience", { enum: ["agent", "device"] }).notNull(),
    /** Device families: the paired device the tokens are bound to (revoking it revokes them). */
    device_id: text("device_id"),
    created_at: ts("created_at").notNull(),
    expires_at: ts("expires_at").notNull(),
    used_at: ts("used_at"),
    replaced_by: text("replaced_by"),
    revoked_at: ts("revoked_at"),
  },
  (t) => [index("refresh_tokens_family_idx").on(t.family_id), index("refresh_tokens_device_idx").on(t.device_id)],
);

export const pairingCodes = pgTable(
  "pairing_codes",
  {
    id: text("id").primaryKey(),
    user_id: text("user_id")
      .notNull()
      .references(() => users.id),
    /** HMAC-SHA256(auth secret, normalized code). The code itself is never stored. */
    code_hash: char("code_hash", { length: 64 }).notNull().unique(),
    created_at: ts("created_at").notNull(),
    expires_at: ts("expires_at").notNull(),
    used_at: ts("used_at"),
  },
  (t) => [index("pairing_codes_user_created_idx").on(t.user_id, t.created_at)],
);

export const pairingRequests = pgTable(
  "pairing_requests",
  {
    id: text("id").primaryKey(),
    user_id: text("user_id")
      .notNull()
      .references(() => users.id),
    status: text("status", { enum: ["pending", "approved", "denied", "expired"] }).notNull(),
    /** "device" (new approver) or "agent" (new computer, remote agent login). */
    kind: text("kind", { enum: ["device", "agent"] }).notNull().default("device"),
    device_name: text("device_name").notNull(),
    platform: text("platform").notNull(),
    ip: text("ip"),
    /** SHA-256 of the poll secret only the new device holds. */
    poll_secret_hash: char("poll_secret_hash", { length: 64 }).notNull(),
    requested_at: ts("requested_at").notNull(),
    expires_at: ts("expires_at").notNull(),
    resolved_at: ts("resolved_at"),
    resolved_by_device_id: text("resolved_by_device_id").references(() => devices.id),
    /** Device created when the approved login was delivered. */
    device_id: text("device_id").references(() => devices.id),
    login_delivered_at: ts("login_delivered_at"),
    /** Key the new device presented; set on the device when the login is delivered. */
    device_public_key: text("device_public_key"),
  },
  (t) => [index("pairing_requests_user_status_idx").on(t.user_id, t.status)],
);

export const workspaces = pgTable("workspaces", {
  id: text("id").primaryKey(),
  user_id: text("user_id").notNull().references(() => users.id),
  path: text("path").notNull(),
  label: text("label").notNull(),
  created_at: ts("created_at").notNull(),
  ungated_providers: jsonb("ungated_providers").$type<string[]>().notNull().default([]),
});

export const agentSessions = pgTable("agent_sessions", {
  id: text("id").primaryKey(),
  user_id: text("user_id").notNull().references(() => users.id),
  provider: text("provider").notNull(),
  provider_session_id: text("provider_session_id"),
  mode: text("mode", { enum: ["managed", "observed"] }).notNull(),
  title: text("title").notNull(),
  cwd: text("cwd").notNull(),
  repo: text("repo"),
  branch: text("branch"),
  status: text("status").notNull(),
  pending_interaction_id: text("pending_interaction_id"),
  pid: integer("pid"),
  next_seq: integer("next_seq").notNull().default(0),
  started_at: ts("started_at").notNull(),
  last_event_at: ts("last_event_at").notNull(),
  ended_at: ts("ended_at"),
  summary_json: jsonb("summary_json"),
  usage_json: jsonb("usage_json").notNull(),
  current_task_id: text("current_task_id"),
  queued_tasks: integer("queued_tasks").notNull().default(0),
  gated: boolean("gated").notNull().default(true),
  base_json: jsonb("base_json"),
  tests_json: jsonb("tests_json"),
  pr_json: jsonb("pr_json"),
  limits_json: jsonb("limits_json"),
  retries: integer("retries").notNull().default(0),
  exceeded_json: jsonb("exceeded_json").notNull().default([]),
  background_json: jsonb("background_json").$type<Array<{ pid: number; start: string; command: string; outputs?: string[] }>>().notNull().default([]),
});

/** Single-use nonces (rekey, device recovery) — survive restarts. */
export const usedNonces = pgTable("used_nonces", {
  nonce: text("nonce").primaryKey(),
  kind: text("kind").notNull(),
  expires_at: ts("expires_at").notNull(),
});

export const controlSettings = pgTable("control_settings", {
  user_id: text("user_id").primaryKey().references(() => users.id),
  limits_json: jsonb("limits_json"),
  updated_at: ts("updated_at").notNull(),
});

export const tasks = pgTable("tasks", {
  id: text("id").primaryKey(),
  session_id: text("session_id").notNull().references(() => agentSessions.id),
  position: integer("position").notNull(),
  title: text("title").notNull(),
  prompt: text("prompt").notNull(),
  status: text("status", { enum: ["queued", "running", "waiting", "completed", "failed", "cancelled"] }).notNull(),
  created_at: ts("created_at").notNull(),
  started_at: ts("started_at"),
  ended_at: ts("ended_at"),
  usage_json: jsonb("usage_json"),
  summary_json: jsonb("summary_json"),
  base_json: jsonb("base_json"),
  tests_json: jsonb("tests_json"),
  reviewed_at: ts("reviewed_at"),
});
export type TaskRow = typeof tasks.$inferSelect;

export const sessionEvents = pgTable("session_events", {
  id: text("id").primaryKey(),
  session_id: text("session_id").notNull().references(() => agentSessions.id),
  seq: integer("seq").notNull(),
  type: text("type").notNull(),
  payload_json: jsonb("payload_json").notNull(),
  created_at: ts("created_at").notNull(),
});

export const interactions = pgTable("interactions", {
  id: text("id").primaryKey(),
  session_id: text("session_id").notNull().references(() => agentSessions.id),
  kind: text("kind").notNull(),
  prompt: text("prompt").notNull(),
  status: text("status").notNull(),
  answer: text("answer"),
  answered_by_device: text("answered_by_device"),
  created_at: ts("created_at").notNull(),
  resolved_at: ts("resolved_at"),
});

export const controlCommands = pgTable("control_commands", {
  id: text("id").primaryKey(),
  user_id: text("user_id").notNull().references(() => users.id),
  session_id: text("session_id"),
  command: text("command").notNull(),
  payload_json: jsonb("payload_json").notNull(),
  signed_command: text("signed_command"),
  nonce: text("nonce").unique(),
  status: text("status").notNull(),
  reason: text("reason"),
  device_id: text("device_id"),
  created_at: ts("created_at").notNull(),
  applied_at: ts("applied_at"),
});

export type AgentSessionRow = typeof agentSessions.$inferSelect;
export type InteractionRow = typeof interactions.$inferSelect;

export const schema = { users, devices, agents, sessions, actions, approvals, auditLogs, refreshTokens, pairingCodes, pairingRequests, workspaces, agentSessions, sessionEvents, interactions, controlCommands, tasks, controlSettings, usedNonces };

export type UserRow = typeof users.$inferSelect;
export type DeviceRow = typeof devices.$inferSelect;
export type AgentRow = typeof agents.$inferSelect;
export type SessionRow = typeof sessions.$inferSelect;
export type ActionRow = typeof actions.$inferSelect;
export type ApprovalRow = typeof approvals.$inferSelect;
export type AuditRow = typeof auditLogs.$inferSelect;
export type RefreshTokenRow = typeof refreshTokens.$inferSelect;
export type PairingRequestRow = typeof pairingRequests.$inferSelect;
