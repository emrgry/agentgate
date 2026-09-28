# AgentGate — Architecture (MVP)

> The human authorization layer between AI agents and the real world.
> Agent integrations are thin. AgentGate core is generic.

## 1. Repo architecture

```
agentgate/
├── apps/
│   ├── api/                 Fastify HTTP + WebSocket server (approval authority, audit, push)
│   └── mobile/              Expo / React Native control plane (inbox, detail, approve/deny)
├── packages/
│   ├── protocol/            Zod schemas: canonical action, approval, API contract, WS events
│   ├── core/                Framework-free domain: canonical JSON, action hash, approval
│   │                        state machine, signed approval tokens, ids
│   ├── policy-engine/       YAML rules + shell analysis + risk heuristics → allow/ask/deny
│   ├── sdk/                 (M2+) typed HTTP/WS client shared by daemon & future adapters
│   └── adapters/            AgentAdapter interface (agent-agnostic)
├── adapters/
│   └── claude-code/         (M4) Claude Code PreToolUse hook → canonical action
├── daemon/
│   └── agentgate/           `agentgate` CLI: login, status, request, run <agent>
├── examples/claude-demo/    (M4) demo repo for the final scenario
└── docs/
```

Dependency direction is strictly inward:
`apps/*, daemon, adapters → sdk → policy-engine, core → protocol`. Nothing in
`protocol`, `core` or `policy-engine` imports Fastify, React Native, or anything
Claude-specific. The mobile app (separate repo) imports only `protocol` and `signing` (no `node:crypto`).

## 2. Stack and reasons

| Area | Choice | Why |
|---|---|---|
| Language | TypeScript (strict) everywhere | One contract (`protocol`) shared by API, daemon, mobile |
| Validation | Zod | Runtime validation at every trust boundary; types inferred from schemas |
| API | Fastify 5 + `@fastify/websocket` | Fast, schema-friendly, first-class WS plugin, low ceremony |
| DB | PostgreSQL via Drizzle ORM | Typed SQL, migrations, no heavy runtime |
| DB (dev) | PGlite (embedded Postgres/WASM) | Real Postgres semantics without Docker; `DATABASE_URL` switches to a real server |
| Realtime | WebSocket | Daemon must not poll; bidirectional heartbeat |
| Mobile | Expo (React Native) + expo-router | Fast iteration, deep links, Expo Notifications |
| Push | Expo Push API | One API for APNs/FCM; swap to direct APNs/FCM later |
| Daemon | Node/TypeScript (MVP) | Go toolchain isn't installed here and TS reuses `core`/`policy-engine` directly. Long-term: Go port for single-binary distribution — the protocol is language-neutral (canonical JSON + SHA-256 + Ed25519) so a Go daemon can verify the same tokens |
| Crypto | Ed25519 (node:crypto) | Small, fast, deterministic signatures, no deps |
| Tests | Vitest | Policy engine, hashing, state machine, API flow |

## 3. Database schema

```
users        (id pk, email unique, created_at)
devices      (id pk, user_id fk, name, push_token null, platform, created_at, last_seen_at)
agents       (id pk, user_id fk, name, type, machine_id, created_at)   unique(user_id, machine_id, type)
sessions     (id pk, agent_id fk, status 'active'|'ended', started_at, ended_at null)
actions      (id pk, session_id fk, category, operation, payload_json jsonb, action_hash char(64),
              risk_level, policy_decision, policy_rule_id null,
              execution_status 'not_started'|'started'|'completed'|'failed'|'blocked',
              created_at)
approvals    (id pk, action_id fk unique, status, decision null, requested_at, expires_at,
              resolved_at null, resolved_by_device_id fk null, token_nonce null)
audit_logs   (id pk, user_id fk, event, action_id null, approval_id null, payload_json jsonb, created_at)
```

Indexes: `approvals(status, expires_at)` for the expiry sweeper; `audit_logs(user_id, created_at desc)`;
`actions(session_id, created_at)`. `payload_json` stores the full `CanonicalAction`
(secrets redacted by the daemon before submission).

## 4. Canonical action schema

Defined in `packages/protocol/src/action.ts`. Example:

```json
{
  "action_id": "act_…", "session_id": "ses_…",
  "agent":    { "type": "claude-code", "version": "2.x" },
  "action":   { "category": "shell", "operation": "execute", "tool": "Bash",
                "command": "git push origin main", "cwd": "/work/demo" },
  "resource": { "type": "git_remote", "environment": "production", "name": "origin/main" },
  "context":  { "repo": "agentgate/demo", "branch": "main", "hostname": "mbp" },
  "risk":     { "level": "high", "reason": "pushes commits to a remote" },
  "created_at": "2026-09-24T14:32:00.000Z"
}
```

`category` and `operation` are open lowercase identifiers (`git.push`, `filesystem.delete`,
`payment.create`, `mcp.invoke`, …) so new agents/actions need no protocol change.

**Action hash** (`packages/core/src/action-hash.ts`):
`SHA-256(canonical_json({v, session_id, agent, category, operation, tool, command, arguments, cwd, resource{type, environment, name}}))`.
IDs, timestamps, risk and informational context are excluded — they don't change what runs.

## 5. Approval state machine

`packages/core/src/approval-state.ts` — pure function `transitionApproval(approval, event, now)`.

```
pending ──approve──▶ approved      (signed token issued)
pending ──deny─────▶ denied
pending ──expire───▶ expired       (sweeper, or any decision arriving at/after expires_at)
pending ──cancel───▶ cancelled     (session ended / agent exited)
```
All non-pending states are terminal; any other transition throws. The DB update is a
compare-and-set (`UPDATE … WHERE id = $1 AND status = 'pending'`) so two devices racing
produce exactly one winner. Default TTL 120 s (clamped 30–900 s).

## 6. API contract (v1)

Schemas: `packages/protocol/src/api.ts`, events: `packages/protocol/src/events.ts`.

| Method | Path | Caller | Purpose |
|---|---|---|---|
| POST | `/v1/auth/login` | both | Dev auth: `{email, client:"device"\|"agent"}` → short-lived bearer token |
| GET | `/v1/keys` | daemon | Ed25519 public key for approval-token verification |
| POST | `/v1/devices` | mobile | Register device + Expo push token |
| POST | `/v1/agents` | daemon | Register agent (idempotent per machine/type) |
| POST | `/v1/sessions` | daemon | Start session |
| POST | `/v1/sessions/:id/end` | daemon | End session; cancels its pending approvals |
| GET | `/v1/sessions/:id/actions` | both | Actions of a session |
| POST | `/v1/actions` | daemon | Report action + local policy decision; `ask` ⇒ approval created + push |
| POST | `/v1/actions/:id/execution` | daemon | `started`/`completed`/`failed`/`blocked` |
| POST | `/v1/approvals` | daemon | Create approval for an existing action (explicit form) |
| GET | `/v1/approvals?status=` | mobile | Inbox |
| GET | `/v1/approvals/:id` | both | Detail (logs `approval.viewed` when called by a device) |
| POST | `/v1/approvals/:id/approve` | mobile | → `{approval, approval_token}` |
| POST | `/v1/approvals/:id/deny` | mobile | → `{approval, approval_token:null}` |
| GET | `/v1/activity` | mobile | Audit timeline |
| WS | `/v1/agent/connect` | daemon | Receives `approval.resolved` |
| WS | `/v1/device/connect` | mobile | Receives `approval.created` / `approval.resolved` |

## 7. Local daemon design (`daemon/agentgate`)

```
agentgate login  [--server URL] [--email E]   → ~/.agentgate/config.json (0600): server, token, agent_id, public key
agentgate status                              → server reachability, auth, WS round-trip
agentgate config [--policy]                   → show config / effective policy path
agentgate logout
agentgate request [--env production] -- <cmd> → M2 vertical slice: evaluate → ask → wait → verify → exec
agentgate run claude                          → M4: launches Claude Code with the AgentGate hook installed
```

Per intercepted action:
1. Adapter builds `ActionDraft` → daemon evaluates local policy (`~/.agentgate/policy.yaml` or built-in).
2. `deny` → block immediately (still reported for audit).
3. `allow` → report + execute.
4. `ask` → open WS first, `POST /v1/actions`, wait for `approval.resolved` for that id
   (on reconnect: re-fetch `GET /v1/approvals/:id`). Timeout = approval TTL + grace.
5. On `approved`: verify token signature with cached server key, recompute action hash
   from the *exact* command about to run, check expiry + single-use nonce. Any failure → block.
6. Execute, stream output, report `execution.completed|failed` with exit code.

Failure handling is **fail closed**: server unreachable, WS error, timeout, bad token,
expired, hash mismatch → the action does not run and the exit code is non-zero (77).

## 8. Claude Code integration strategy (M4 — not started until the slice is proven)

Enforce at the execution boundary, not via prompting:
- `agentgate run claude` spawns `claude --settings <generated.json>` whose `PreToolUse`
  hook (matcher `Bash|Write|Edit|MultiEdit|NotebookEdit`, timeout ≥ approval TTL) runs
  `agentgate hook claude-code`.
- The hook reads the tool-call JSON on stdin, `adapters/claude-code` normalizes it to a
  canonical action, and the daemon returns `permissionDecision: allow | deny`.
- For approved Bash calls the hook returns `updatedInput.command =
  "agentgate exec --token <t> -- <original>"`. `agentgate exec` re-hashes the command it
  was actually given and refuses on mismatch — so even if the command were altered between
  approval and execution, it cannot run with that approval.
- Any hook error/timeout ⇒ `deny` (fail closed).

## 9. Security threat model

| Threat | Mitigation |
|---|---|
| Action swapped after approval (TOCTOU) | Token binds `action_hash`; executor recomputes hash from what it runs |
| Token replay | Single-use nonce (daemon nonce store) + short expiry + bound to approval_id |
| Forged approval | Ed25519 signature by server; daemon pins server public key at login |
| Approval sweeps after timeout | State machine turns late decisions into `expired` |
| Double resolve / device race | Compare-and-set update on `status='pending'` |
| Backend down / network partition | Fail closed: ask/unknown ⇒ block; never "backend down → allow" |
| Compound / obfuscated commands | Per-segment evaluation, most-restrictive wins; substitution/eval/`sh -c` never auto-allowed |
| Stolen device token | Short-lived access tokens, per-device identity, every decision audited with device id |
| Secret leakage via logs | Daemon redacts env-style secrets / tokens from commands before submission; server never logs bearer tokens |
| Agent bypassing daemon | Out of scope for MVP (agent runs as the same user). Phase 2: execution proxy + short-lived credentials |
| Push notification spoofing / lock-screen leakage | Push carries only approval id + short summary; decision requires authenticated in-app action |

## 10. Milestone status

Current design: `docs/local-first.md` and `docs/control-center.md`.
