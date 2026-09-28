# @agentgate/api

The AgentGate approval authority: Fastify 5 HTTP + WebSocket server with audit log,
approval state machine, Ed25519-signed approval tokens, and Expo push.

Spec: `docs/architecture.md` §3, §5, §6, §9. Contract: `packages/protocol`.

## Run

Node isn't on PATH on this machine, so prefix commands with
`export PATH=$HOME/.local/node/bin:$PATH &&`.

```bash
npm install                            # from the repo root
npm run dev -w @agentgate/api          # tsx watch, http://0.0.0.0:8787
npm run start -w @agentgate/api        # no watch
npm test -w @agentgate/api             # vitest, in-memory PGlite
npm run typecheck -w @agentgate/api
```

A phone on the same LAN reaches the server at `http://<your-mac-LAN-IP>:8787`.

### Configuration (env)

| Var | Default | Notes |
|---|---|---|
| `PORT` / `HOST` | `8787` / `0.0.0.0` | |
| `DATABASE_URL` | unset | If set, uses PostgreSQL via `pg`; otherwise embedded PGlite in `DATA_DIR/pglite` |
| `DATA_DIR` | `apps/api/.data` | PGlite files, generated signing key, generated auth secret |
| `AUTH_SECRET` | generated once into `DATA_DIR/auth-secret` | HS256 secret for access tokens. **Set it in production.** |
| `APPROVAL_SIGNING_KEY_PEM` | generated once into `DATA_DIR/approval-signing-key.pem` | Ed25519 PKCS#8 PEM (literal `\n` accepted) |
| `EXPO_ACCESS_TOKEN` | unset | Only needed if Expo push security is enabled |
| `LOG_LEVEL` | `info` | pino level |
| `SWEEP_INTERVAL_MS` | `2000` | Expiry sweeper interval |

Tables are created on startup with idempotent `CREATE … IF NOT EXISTS` SQL
(`src/db/bootstrap.ts`, mirrors `src/db/schema.ts`). Delete `.data/` to reset dev state
(this also rotates the signing key — re-run `agentgate login`).

## Layout

```
src/
  main.ts            process entry: config → db → signer → app → listen; sweeper + heartbeat
  app.ts             buildApp(): Fastify wiring, logger redaction, JSON parser, background jobs
  config.ts, keys.ts env config; Ed25519 signer (kid = sha256(SPKI) prefix)
  auth/tokens.ts     HS256 access tokens (node:crypto)
  db/                drizzle schema, bootstrap SQL, pglite|pg client
  domain/            framework-free services (db + clock + notifier + signer)
    approvals.ts     create / resolve (state machine + CAS) / expire / cancel / token issuing
    actions.ts       submit (hash check, audit, ask ⇒ approval in same tx), execution reports
    sessions.ts, identity.ts, activity.ts, audit.ts, mappers.ts
  http/              thin routes: zod-validate in, call service, zod-validate out; error mapping
  realtime/          WS hub (per-user fan-out, heartbeat) + /v1/{agent,device}/connect
  push/expo.ts       Expo push sender + lock-screen-safe message builder
  notifier.ts        Notifier = WS fan-out + fire-and-forget push
```

## Endpoints

All bodies/responses follow `@agentgate/protocol`. Errors: `{ "error": { "code", "message" } }`.
Tokens: `client:"device"` (mobile, 12 h) or `client:"agent"` (daemon, 1 h).

| Method | Path | Token | Notes |
|---|---|---|---|
| POST | `/v1/auth/login` | – | `{email, client}` → `LoginResponse` |
| GET | `/v1/keys` | – | `KeysResponse` |
| GET | `/healthz` | – | `{ok:true}` |
| POST | `/v1/devices` | device | `RegisterDeviceRequest` → `Device` (idempotent per push_token) |
| POST | `/v1/agents` | agent | `RegisterAgentRequest` → `Agent` (idempotent per machine_id+type) |
| POST | `/v1/sessions` | agent | `{agent_id}` → `Session` |
| POST | `/v1/sessions/:id/end` | agent | → `Session`; cancels pending approvals |
| GET | `/v1/sessions/:id/actions` | any | → `{items: ActionRecord[]}` |
| POST | `/v1/actions` | agent | `SubmitActionRequest` → `ActionRecord` (201) |
| POST | `/v1/actions/:id/execution` | agent | `ReportExecutionRequest` → `ActionRecord` |
| POST | `/v1/approvals` | agent | `{action_id, ttl_seconds?}` → `ApprovalDetail` (201) |
| GET | `/v1/approvals?status=&limit=` | any | → `ListApprovalsResponse` |
| GET | `/v1/approvals/:id` | any | → `ApprovalDetail`; agent tokens also get `approval_token` |
| POST | `/v1/approvals/:id/approve` | device | `{device_id}` → `ResolveApprovalResponse` |
| POST | `/v1/approvals/:id/deny` | device | `{device_id}` → `ResolveApprovalResponse` |
| GET | `/v1/activity?limit=` | any | → `ActivityResponse` (newest first, limit ≤ 200) |
| WS | `/v1/agent/connect?session_id=` | agent | `hello`, `pong`, `approval.resolved` |
| WS | `/v1/device/connect[?device_id=]` | device | `hello`, `pong`, `approval.created`, `approval.resolved` |

WS auth: `Authorization: Bearer …` or `?access_token=…` (redacted in logs). Send
`{"type":"ping"}` → `{"type":"pong"}`. The server pings every 30 s and drops dead sockets.

Notable error codes: `unauthorized` (401), `wrong_client` / `forbidden` (403), `not_found`
(404), `validation_error` / `hash_mismatch` (400), `approval_already_resolved` /
`approval_expired` (409, body also carries the current `approval`), `session_ended`,
`not_approved`, `invalid_execution_transition` (409).

## curl walkthrough

Requires `jq`. Run from the repo root (hash is computed with `@agentgate/core`).

```bash
S=http://localhost:8787
H='content-type: application/json'

DEV=$(curl -s $S/v1/auth/login -H "$H" -d '{"email":"me@example.com","client":"device"}' | jq -r .access_token)
AGT=$(curl -s $S/v1/auth/login -H "$H" -d '{"email":"me@example.com","client":"agent"}'  | jq -r .access_token)

DEVICE_ID=$(curl -s $S/v1/devices -H "$H" -H "authorization: Bearer $DEV" \
  -d '{"name":"My iPhone","platform":"ios","push_token":null}' | jq -r .id)
AGENT_ID=$(curl -s $S/v1/agents -H "$H" -H "authorization: Bearer $AGT" \
  -d '{"name":"Claude Code","type":"claude-code","machine_id":"mbp-1"}' | jq -r .id)
SES=$(curl -s $S/v1/sessions -H "$H" -H "authorization: Bearer $AGT" \
  -d "{\"agent_id\":\"$AGENT_ID\"}" | jq -r .id)

# Build the action draft and compute its hash exactly like the daemon does.
ACTION=$(jq -nc --arg ses "$SES" '{session_id:$ses, agent:{type:"claude-code"},
  action:{category:"git",operation:"push",tool:"Bash",command:"git push origin main",cwd:"/work/demo"},
  resource:{type:"git_remote",environment:"production",name:"origin/main"}, context:{}}')
HASH=$(npx tsx -e "import { computeActionHash } from '@agentgate/core'; console.log(computeActionHash($ACTION))")

# Report an `ask` action → pending approval + approval.created (WS) + Expo push.
APR=$(curl -s $S/v1/actions -H "$H" -H "authorization: Bearer $AGT" \
  -d "{\"action\":$ACTION,\"policy\":{\"decision\":\"ask\",\"rule_id\":\"git-push\",\"risk\":\"high\",\"reason\":\"pushes to main\"},\"action_hash\":\"$HASH\"}" \
  | jq -r .approval.approval_id)

curl -s "$S/v1/approvals?status=pending" -H "authorization: Bearer $DEV" | jq .
curl -s $S/v1/approvals/$APR/approve -H "$H" -H "authorization: Bearer $DEV" \
  -d "{\"device_id\":\"$DEVICE_ID\"}" | jq .          # → approval + approval_token
curl -s $S/v1/approvals/$APR/approve -H "$H" -H "authorization: Bearer $DEV" \
  -d "{\"device_id\":\"$DEVICE_ID\"}" | jq .error     # → 409 approval_already_resolved
curl -s -X POST $S/v1/sessions/$SES/end -H "authorization: Bearer $AGT" | jq .
curl -s "$S/v1/activity?limit=10" -H "authorization: Bearer $DEV" | jq -r '.items[] | "\(.event) | \(.summary)"'
```

Watch realtime events (any WS client, e.g. `npx wscat`):

```bash
npx wscat -c "ws://localhost:8787/v1/device/connect?access_token=$DEV"
npx wscat -c "ws://localhost:8787/v1/agent/connect?session_id=$SES&access_token=$AGT"
```

## Approval token

On approve the server signs (`@agentgate/core` `signApprovalToken`) an
`ApprovalTokenPayload` v1 with `expires_at = min(approval.expires_at + 60 s, now + 5 min)`
and a fresh nonce (stored in `approvals.token_nonce`). The token is fully derived from
stored fields, and Ed25519 is deterministic, so `GET /v1/approvals/:id` with an agent token
returns the byte-identical token — a daemon that missed the WS event can recover it. The
daemon must still verify signature, hash, expiry and nonce (`verifyApprovalToken`).

## Production notes / not yet done

- Single-node realtime hub; horizontal scaling needs pub/sub (PG LISTEN/NOTIFY or Redis).
- No rate limiting, CORS, or real login (magic link/OAuth) yet — dev auth upserts any email.
- Expo push receipts aren't polled; stale push tokens aren't pruned.
- Schema bootstrap is idempotent SQL; switch to drizzle-kit migrations before the first
  breaking schema change.
