import { sql } from "drizzle-orm";
import type { Db } from "./client.ts";

/**
 * Idempotent schema bootstrap, executed on every startup. Mirrors src/db/schema.ts.
 * Kept as plain SQL (one statement per entry) so it runs identically on PGlite and pg.
 * When the schema starts evolving in production, switch to drizzle-kit migrations.
 */
export const BOOTSTRAP_SQL: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS users (
    id text PRIMARY KEY,
    email text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS devices (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id),
    name text NOT NULL,
    push_token text,
    platform text NOT NULL,
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz
  )`,
  `CREATE INDEX IF NOT EXISTS devices_user_idx ON devices (user_id)`,
  `ALTER TABLE devices ADD COLUMN IF NOT EXISTS revoked_at timestamptz`,
  `CREATE TABLE IF NOT EXISTS agents (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id),
    name text NOT NULL,
    type text NOT NULL,
    machine_id text NOT NULL,
    created_at timestamptz NOT NULL
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS agents_user_machine_type_uq ON agents (user_id, machine_id, type)`,
  `CREATE TABLE IF NOT EXISTS sessions (
    id text PRIMARY KEY,
    agent_id text NOT NULL REFERENCES agents(id),
    status text NOT NULL CHECK (status IN ('active','ended')),
    started_at timestamptz NOT NULL,
    ended_at timestamptz
  )`,
  `CREATE INDEX IF NOT EXISTS sessions_agent_idx ON sessions (agent_id)`,
  `CREATE TABLE IF NOT EXISTS actions (
    id text PRIMARY KEY,
    session_id text NOT NULL REFERENCES sessions(id),
    category text NOT NULL,
    operation text NOT NULL,
    payload_json jsonb NOT NULL,
    action_hash char(64) NOT NULL,
    risk_level text NOT NULL,
    policy_decision text NOT NULL CHECK (policy_decision IN ('allow','ask','deny')),
    policy_rule_id text,
    execution_status text NOT NULL
      CHECK (execution_status IN ('not_started','started','completed','failed','blocked')),
    created_at timestamptz NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS actions_session_created_idx ON actions (session_id, created_at)`,
  `CREATE TABLE IF NOT EXISTS approvals (
    id text PRIMARY KEY,
    action_id text NOT NULL UNIQUE REFERENCES actions(id),
    status text NOT NULL CHECK (status IN ('pending','approved','denied','expired','cancelled')),
    decision text CHECK (decision IN ('approve','deny')),
    requested_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    resolved_at timestamptz,
    resolved_by_device_id text REFERENCES devices(id),
    token_nonce text
  )`,
  `CREATE INDEX IF NOT EXISTS approvals_status_expires_idx ON approvals (status, expires_at)`,
  `CREATE TABLE IF NOT EXISTS audit_logs (
    id text PRIMARY KEY,
    seq bigserial NOT NULL,
    user_id text NOT NULL REFERENCES users(id),
    event text NOT NULL,
    action_id text,
    approval_id text,
    payload_json jsonb NOT NULL,
    created_at timestamptz NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS audit_logs_user_created_idx ON audit_logs (user_id, created_at DESC)`,
  // Rotating refresh tokens (hash at rest). A family = one login/pairing; reuse revokes it.
  `CREATE TABLE IF NOT EXISTS refresh_tokens (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id),
    family_id text NOT NULL,
    token_hash char(64) NOT NULL UNIQUE,
    audience text NOT NULL CHECK (audience IN ('agent', 'device')),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    replaced_by text,
    revoked_at timestamptz
  )`,
  `CREATE INDEX IF NOT EXISTS refresh_tokens_family_idx ON refresh_tokens (family_id)`,
  // Device refresh families (bound to a device; revoking the device revokes them).
  `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS device_id text`,
  `CREATE INDEX IF NOT EXISTS refresh_tokens_device_idx ON refresh_tokens (device_id)`,
  // Older databases were created with CHECK (audience IN ('agent')): widen it (idempotent).
  `ALTER TABLE refresh_tokens DROP CONSTRAINT IF EXISTS refresh_tokens_audience_check`,
  `ALTER TABLE refresh_tokens ADD CONSTRAINT refresh_tokens_audience_check CHECK (audience IN ('agent', 'device'))`,
  // One-time device pairing codes (HMAC at rest), created by an agent, consumed by device login.
  `CREATE TABLE IF NOT EXISTS pairing_codes (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id),
    code_hash char(64) NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz
  )`,
  `CREATE INDEX IF NOT EXISTS pairing_codes_user_created_idx ON pairing_codes (user_id, created_at)`,
  // A new device waiting for an already-paired device to approve it.
  `CREATE TABLE IF NOT EXISTS pairing_requests (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id),
    status text NOT NULL CHECK (status IN ('pending','approved','denied','expired')),
    device_name text NOT NULL,
    platform text NOT NULL,
    ip text,
    poll_secret_hash char(64) NOT NULL,
    requested_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    resolved_at timestamptz,
    resolved_by_device_id text REFERENCES devices(id),
    device_id text REFERENCES devices(id),
    login_delivered_at timestamptz
  )`,
  `CREATE INDEX IF NOT EXISTS pairing_requests_user_status_idx ON pairing_requests (user_id, status)`,
  `ALTER TABLE pairing_requests ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'device'`,
  // M7 local-first: owner display name, device public keys, phone-signed decisions.
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name text`,
  `ALTER TABLE devices ADD COLUMN IF NOT EXISTS public_key text`,
  `ALTER TABLE pairing_requests ADD COLUMN IF NOT EXISTS device_public_key text`,
  `ALTER TABLE approvals ADD COLUMN IF NOT EXISTS signed_decision text`,
  // Control Center (docs/control-center.md §3)
  `CREATE TABLE IF NOT EXISTS workspaces (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id),
    path text NOT NULL,
    label text NOT NULL,
    created_at timestamptz NOT NULL
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS workspaces_user_path_uq ON workspaces (user_id, path)`,
  `CREATE TABLE IF NOT EXISTS agent_sessions (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id),
    provider text NOT NULL,
    provider_session_id text,
    mode text NOT NULL CHECK (mode IN ('managed','observed')),
    title text NOT NULL,
    cwd text NOT NULL,
    repo text,
    branch text,
    status text NOT NULL,
    pending_interaction_id text,
    pid integer,
    next_seq integer NOT NULL DEFAULT 0,
    started_at timestamptz NOT NULL,
    last_event_at timestamptz NOT NULL,
    ended_at timestamptz,
    summary_json jsonb,
    usage_json jsonb NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS agent_sessions_user_last_idx ON agent_sessions (user_id, last_event_at DESC)`,
  `CREATE INDEX IF NOT EXISTS agent_sessions_provider_sid_idx ON agent_sessions (provider, provider_session_id)`,
  `CREATE TABLE IF NOT EXISTS session_events (
    id text PRIMARY KEY,
    session_id text NOT NULL REFERENCES agent_sessions(id),
    seq integer NOT NULL,
    type text NOT NULL,
    payload_json jsonb NOT NULL,
    created_at timestamptz NOT NULL
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS session_events_session_seq_uq ON session_events (session_id, seq)`,
  `CREATE TABLE IF NOT EXISTS interactions (
    id text PRIMARY KEY,
    session_id text NOT NULL REFERENCES agent_sessions(id),
    kind text NOT NULL,
    prompt text NOT NULL,
    status text NOT NULL,
    answer text,
    answered_by_device text,
    created_at timestamptz NOT NULL,
    resolved_at timestamptz
  )`,
  // Control Center Phase 2: task queue per session
  `CREATE TABLE IF NOT EXISTS tasks (
    id text PRIMARY KEY,
    session_id text NOT NULL REFERENCES agent_sessions(id),
    position integer NOT NULL,
    title text NOT NULL,
    prompt text NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    started_at timestamptz,
    ended_at timestamptz,
    usage_json jsonb,
    summary_json jsonb
  )`,
  `CREATE INDEX IF NOT EXISTS tasks_session_position_idx ON tasks (session_id, position)`,
  `ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS current_task_id text`,
  `ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS queued_tasks integer NOT NULL DEFAULT 0`,
  // Control Center Phase 2 (providers): ungated opt-in per workspace; gated flag per session.
  `ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS ungated_providers jsonb NOT NULL DEFAULT '[]'::jsonb`,
  `ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS gated boolean NOT NULL DEFAULT true`,
  // Phase 3 (review): git base per session/task, last test run, PR; reviewed tasks.
  `ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS base_json jsonb`,
  `ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS tests_json jsonb`,
  `ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS pr_json jsonb`,
  `ALTER TABLE tasks ADD COLUMN IF NOT EXISTS base_json jsonb`,
  `ALTER TABLE tasks ADD COLUMN IF NOT EXISTS tests_json jsonb`,
  `ALTER TABLE tasks ADD COLUMN IF NOT EXISTS reviewed_at timestamptz`,
  // Phase 4 (cost & resources): limits, retries, exceeded log; global limits per user.
  `ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS limits_json jsonb`,
  `ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS retries integer NOT NULL DEFAULT 0`,
  `ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS exceeded_json jsonb NOT NULL DEFAULT '[]'::jsonb`,
  // Processes a turn left running (Claude "run_in_background" commands etc.).
  `ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS background_json jsonb NOT NULL DEFAULT '[]'::jsonb`,
  // Device key rotation + recovery
  `ALTER TABLE devices ADD COLUMN IF NOT EXISTS rekeyed_at timestamptz`,
  `ALTER TABLE devices ADD COLUMN IF NOT EXISTS rekey_proof_json jsonb`,
  `CREATE TABLE IF NOT EXISTS used_nonces (
    nonce text PRIMARY KEY,
    kind text NOT NULL,
    expires_at timestamptz NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS control_settings (
    user_id text PRIMARY KEY REFERENCES users(id),
    limits_json jsonb,
    updated_at timestamptz NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS control_commands (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id),
    session_id text,
    command text NOT NULL,
    payload_json jsonb NOT NULL,
    signed_command text,
    nonce text UNIQUE,
    status text NOT NULL,
    reason text,
    device_id text,
    created_at timestamptz NOT NULL,
    applied_at timestamptz
  )`,
];

export async function bootstrapSchema(db: Db): Promise<void> {
  for (const stmt of BOOTSTRAP_SQL) {
    await db.execute(sql.raw(stmt));
  }
}
