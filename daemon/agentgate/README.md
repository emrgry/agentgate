# `agentgate` CLI (`@agentgate/cli`)

Local daemon/CLI for AgentGate: evaluates agent actions against local policy, routes
risky ones to your phone for approval, and only executes after verifying the signed
approval token against the exact command it is about to run. Milestone 2 (vertical slice).

TypeScript for the MVP, run through `tsx` (no build step). The design is deliberately
portable to Go: everything security-relevant is canonical JSON + SHA-256 + Ed25519.

```bash
# from the repo root
npx agentgate --help
npm run agentgate -- status        # note: `npm run` sets cwd to the repo root
```

## Commands

| Command | What it does |
|---|---|
| `agentgate login [--server http://localhost:8787] [--email dev@agentgate.local]` | `POST /v1/auth/login` (client `agent`), `GET /v1/keys` → **pins** the Ed25519 key, `POST /v1/agents` (name = hostname, type `cli`, stable `machine_id`). Writes `config.json` (0600). |
| `agentgate status` | Server reachability, pinned key vs. server key, token expiry, WS connect + ping/pong RTT, policy source. Exit 0 healthy / 1 not. |
| `agentgate config [--policy]` | Print config (token redacted) / effective policy YAML and its source. |
| `agentgate logout` | Delete the access token (machine id + pinned key kept). |
| `agentgate request [opts] -- <command...>` | The vertical slice (below). |
| `agentgate run claude [--env E] [--ttl N] [-- claude args…]` | Launch Claude Code gated by AgentGate (see below). |
| `agentgate exec --approval <apr_id> -- <cmd>` | Execution boundary for approved Claude Bash calls. |
| `agentgate hook claude-code` | The PreToolUse hook (stdin JSON → decision). Normally invoked via `bin/agentgate-hook.sh`. |

`request` options: `--agent-type cli` · `--env production` (→ `resource.environment`) ·
`--repo` / `--branch` (default: detected from git) · `--ttl 120` (approval TTL, server
clamps 30–900) · `--dry-run` (evaluate policy locally and print; nothing sent or run) ·
`-v/--verbose` (debug output, tokens redacted).

Command string: a single argument after `--` is used verbatim as a shell line
(`agentgate request -- "npm test && git push"`); several arguments are POSIX-quoted and
joined so the string means exactly what the argv meant (`-- echo "a b"` → `echo 'a b'`).
That string is what is hashed, shown on the phone, and passed to `/bin/sh -c`.

## `request` flow

1. `POST /v1/sessions` (the session id is part of the action hash).
2. Build the `ActionDraft` (`shell`/`execute`, cwd = `process.cwd()`), evaluate local policy
   (`$AGENTGATE_HOME/policy.yaml` or the built-in default), compute the action hash.
3. **deny** → report (`POST /v1/actions`, then execution `blocked`), exit 77.
   **allow** → report, execute, report `started` → `completed|failed`.
   **ask** → open `WS /v1/agent/connect?session_id=…` **first**, then `POST /v1/actions`,
   wait for `approval.resolved`. On reconnect, and at the deadline, re-check
   `GET /v1/approvals/:id`. Deadline = server approval window + 10 s grace.
4. On **approved**: recompute the hash from the draft whose command is about to be spawned,
   then `verifyApprovalToken` with the **pinned** key, expected hash, expected approval id and
   a persistent nonce store (`$AGENTGATE_HOME/nonces/`, one `O_EXCL` file per nonce). Also
   checks the token's `action_id`/`session_id`. Only then `spawn('/bin/sh', ['-c', command])`
   with inherited stdio.
5. The session is always ended (`POST /v1/sessions/:id/end`), including on Ctrl-C, which
   cancels the pending approval server-side.

The server's decision can only make things stricter: effective = max(local, server).

### Exit codes

| Code | Meaning |
|---|---|
| *n* | The command ran; its own exit code (128+signo if killed by a signal). |
| 77 | Blocked — policy deny, denied/expired/cancelled on device, timeout, token verification failure, server or WS unreachable, not logged in, invalid policy file, any unexpected error. |
| 130 | Interrupted (Ctrl-C) before execution; approval cancelled. |
| 2 | Usage error / `run` not available yet. |
| 1 | Management command failed (`login`, `status`, …). |

A wrapped command that itself exits 77 is indistinguishable by exit code; the stderr line
(`✖ blocked: …` vs `✖ exit code 77`) tells them apart.

## Fail-closed guarantees

- `execute()` is reached only from (a) effective decision `allow` after the action was
  accepted by the server, or (b) `ask` + `gateExecution()` returning ok. The command passed
  to `spawn` is taken from the gate's result — the same draft whose hash was verified.
- Every exception in the pipeline is caught and turned into exit 77 (the catch path never
  executes). Uncaught exceptions / rejections anywhere in the process exit 77.
- No server ⇒ no session ⇒ nothing runs, not even `allow` actions (nothing un-audited).
- Invalid `policy.yaml` ⇒ block (no silent fallback to the default policy).
- Token verification uses only the key pinned at `login`, never a freshly fetched one.
  `status` warns if the server's key no longer matches the pin.
- Tokens are single-use across processes (nonce file created with `O_EXCL`); I/O errors
  in the nonce store count as replay.

## Claude Code integration (Milestone 4)

`agentgate run claude` checks login, server reachability and the pinned key, registers the
agent (`type: claude-code`), creates a session, writes a 0600 settings file in a private temp
dir, and runs `claude --settings <file> …args` with inherited stdio. It forwards
SIGTERM/SIGHUP (the terminal delivers SIGINT itself). On exit it ends the session, which
cancels pending approvals, removes that session's unused tokens and deletes the temp dir.
If `claude` is not on PATH it prints the install command and exits 2
(`AGENTGATE_CLAUDE_BIN` overrides the binary).

Settings: `PreToolUse` with matcher `Bash|Write|Edit|MultiEdit|NotebookEdit|mcp__.*` and
timeout 600 s. The hook command is
`AGENTGATE_SESSION_ID=… AGENTGATE_HOME=… AGENTGATE_NODE=… AGENTGATE_HOOK_TIMEOUT_S=600 '<abs>/bin/agentgate-hook.sh'`:
ids and paths only, never tokens.

Per tool call, `hook claude-code` normalizes the event with `@agentgate/adapter-claude-code`
and runs the same pipeline as `request` (policy → report → WebSocket wait). Then:

| Outcome | Hook result |
|---|---|
| ungoverned tool (Read, Grep, …) | exit 0, no output (Claude's normal flow) |
| policy allow | exit 0, `permissionDecision: allow` |
| approved **Bash** | token verified now (nonce **not** consumed) and stored in `$AGENTGATE_HOME/approvals/<apr_id>.json` (0600). Result: `allow` with `updatedInput.command = [AGENTGATE_HOME=…] '<abs>/bin/agentgate.sh' exec --approval apr_… -- '<original>'`. Other tool_input fields are preserved. |
| approved Write/Edit/MultiEdit/NotebookEdit/MCP | token verified **and consumed** in the hook, then `allow`. Claude executes the exact tool_input that was hashed. |
| anything else | **exit 2**, reason on stderr |

`exec` loads the stored token and recomputes the action hash. It uses the command string it
received, its own `realpath(cwd)`, and the approved session (a different
`AGENTGATE_SESSION_ID` in env → blocked). It verifies signature (pinned key), expiry,
approval id, action/session binding and the single-use nonce, deletes the stored token, then
spawns `/bin/sh -c` and reports started/completed/failed. Any failure → 77, nothing runs.
Changing the command or the directory after approval is refused at the real execution
boundary.

Risk for file writes: the adapter asserts **high** for `.env*`, key material (`*.pem`,
`*.key`, `id_*`), `~/.ssh`, `.git/hooks` and other `.git/` internals, cloud credential
dirs, shell rc files, and anything outside the project root (git toplevel). If no explicit
policy rule matched, the daemon applies `defaults[<asserted risk>]` (so `ask` with the
built-in policy). `evaluatePolicy` itself only raises the reported risk, not the decision.
Write/Edit content is never uploaded: arguments carry `path`, `bytes`/`edits` and
`input_sha256`, which binds the exact edit into the approval.

### `agentgate install claude-code` (desktop app, IDE extensions, plain `claude`)

```bash
agentgate install claude-code [--project <dir>]        # default: cwd → <dir>/.claude/settings.local.json
agentgate install claude-code --user --yes             # ~/.claude/settings.json — gates EVERY session, fail-closed
agentgate uninstall claude-code [--project <dir> | --user]
```

- Merges a `PreToolUse` group (same matcher, timeout 600) and a `SessionEnd` group
  (timeout 10) into the JSON. Other keys and hooks are left alone. Invalid JSON → refuse.
- The command records absolute paths (GUI apps have no shell PATH):
  `AGENTGATE_HOME=… AGENTGATE_NODE=<node> AGENTGATE_HOOK_TIMEOUT_S=600 '<repo>/bin/agentgate-hook.sh' --agentgate-install=claude-code/v1`.
  The shim ignores the marker arg; uninstall only removes commands that contain both
  `agentgate-hook.sh` and the marker. No secrets.
- A timestamped `*.agentgate-backup-*` copy is written before every modification.
  Install is idempotent. What we created (file, dir, `hooks` key, event arrays) is
  recorded in `$AGENTGATE_HOME/installs.json`, so uninstall restores the exact previous
  content and deletes only containers we created.
- Project scope: `settings.local.json` is added to `.git/info/exclude` if it isn't already
  ignored (personal, not committed). Installing in a second scope is refused, because both
  hooks would fire and every action would be asked twice. `agentgate run claude` detects an
  installed hook and doesn't add its own. `status` reports the install and flags broken
  paths (for example, node was upgraded).
- Sessions: without `AGENTGATE_SESSION_ID`, the hook maps Claude's `session_id` to an
  AgentGate session (`$AGENTGATE_HOME/sessions/<id>.json`, 0600). Creation uses a per-session
  O_EXCL lock plus a re-read, so parallel hooks create exactly one session. If the server
  reports the session ended or unknown, the hook re-maps once. `SessionEnd` ends it
  (best effort, ≤ 5 s, always exit 0). Approved Bash records carry the session, so `exec`
  needs no env var.

### Token refresh

Agent login returns a rotating refresh token, stored in `config.json` (0600). Any command
whose access token has less than 5 min left refreshes it transparently via
`POST /v1/auth/refresh`, under an O_EXCL lock (`config.lock`) with a re-read, so parallel
hooks rotate once. On a rotation race it re-reads and retries once. All config writes go
through the lock, so a stale writer can't resurrect a rotated token. If refresh fails
(reused / revoked / expired / no token) and the access token has expired → blocked, with
"run `agentgate login`".

### Why the hook can't fail open

Claude Code treats hook exit 2 as block. **Any other** non-zero exit, a crash or a timeout
lets the call proceed. So:

- `bin/agentgate-hook.sh` returns 0 only when the node hook returned 0. Node missing,
  entry missing, a crash (agentgate's crash handler exits 77), tsx failing (127), a signal,
  or any other code becomes exit 2 with a reason.
- `hook claude-code` returns only 0 or 2. Every exception becomes 2. `main` wraps the hook
  in its own catch that returns 2.
- An internal deadline of (hook timeout − 30 s) calls `process.exit(2)` before Claude's
  timeout can fire. The approval wait is capped at the remaining budget − 2 s.
- No session (neither `AGENTGATE_SESSION_ID` nor a Claude `session_id`), session creation
  failing, token refresh failing, unparseable or non-PreToolUse stdin, invalid policy,
  not logged in, server/WS unreachable, denied/expired/cancelled/timeout, or a bad token
  all exit 2.

## Control Center Phase 1

```bash
agentgate session start [--provider claude-code] [--cwd DIR] "<prompt>"
agentgate session list | tail <id> [-f] | send <id> "<text>" | stop|kill|pause|resume <id>
agentgate workspace add [dir] [--label L] | list | remove <dir|id>
```

- **Managed sessions.** The supervisor inside `agentgate serve` runs one
  `claude -p --output-format stream-json --verbose --settings <managed-hooks.json> [--resume <id>]`
  process per turn, in its own process group.
  - The instruction goes on stdin (never argv).
  - `managed-hooks.json` holds the AgentGate PreToolUse and PostToolUse hooks, so every tool
    call is still policy-gated and phone-approved.
  - Permission-bypass flags are never passed.
- **Turn environment.** Turns run with the owner's PATH (captured at `setup`, plus
  `~/.local/bin`), HOME, USER and LOGNAME. The binary comes from `AGENTGATE_CLAUDE_BIN`;
  extra args from `AGENTGATE_CLAUDE_ARGS`.
- **Observed sessions.** `agentgate install claude-code` also installs SessionStart,
  UserPromptSubmit, Notification and Stop hooks with `--agentgate-observe`. The shim then
  always exits 0 with no stdout, even when node is missing, because a Stop hook exiting 2
  would keep Claude running. The hook reports a trimmed subset of each event (no file
  contents or tool output) to `POST /v1/agent-sessions/observe`. Re-run the install to pick
  these up.
- **Local convenience.** The `session`/`workspace` commands use this machine's agent token
  over loopback. The local owner may start, instruct, stop and kill LOCAL sessions without
  a phone signature. Every phone command must be device-signed. Only a local agent can
  change the workspace allowlist.

## Local-first (M7)

```bash
agentgate setup [--port 8787] [--host 0.0.0.0] [--no-start] [--no-pair]
agentgate serve                    # foreground (what launchd runs)
agentgate server start|stop|status|logs [-f]
agentgate uninstall-server [--purge]
```

`setup` (idempotent):
1. Creates `~/.agentgate/server/{data,secrets,logs}` (0700) and `server.json`: port, host,
   owner name (`id -F`, else `$USER`), machine name, and
   `require_device_signatures: true` for new installs.
2. Writes `~/Library/LaunchAgents/dev.agentgate.server.plist`, which runs
   `node agentgate.mjs serve` with `RunAtLoad`/`KeepAlive` and logs to
   `server/logs/server.log`. It runs `launchctl bootstrap` (or re-bootstraps when the plist
   changed); if already running, nothing happens. On other OSes it prints the `serve`
   command to run yourself.
3. Waits for `/healthz` and logs this machine's agent in over loopback without an email
   (local-first servers map it to the single owner). The server key is pinned.
4. Prints the v2 pairing QR:
   `agentgate://pair?v=2&url=<LAN or public_url>&code=<code>&fp=<server key fingerprint>&name=<machine>`.

`serve` sets `AGENTGATE_MODE=local`, `DATA_DIR`/`SECRETS_DIR` under `~/.agentgate/server`,
`AGENTGATE_OWNER_NAME`, `AGENTGATE_MACHINE_NAME` and (new installs)
`AGENTGATE_REQUIRE_DEVICE_SIGNATURES=1`, then starts `apps/api/src/main.ts` in-process
(same node/tsx runtime).

Phone-signed approvals: every executor (`request`, hook, `exec`, MCP gateway) verifies
`v2.` tokens with `verifyDecision` against device keys fetched from the loopback-only
`GET /v1/devices/keys`. Keys are pinned on first sight in `~/.agentgate/device-keys.json`
(0600, per server). A different key later reported for a known device id is refused, and
revocation is sticky. The single-use nonce is consumed by the executor. v1 server-signed
tokens are refused when `require_device_signatures` is set (config) or
`AGENTGATE_REQUIRE_DEVICE_SIGNATURES=1`. All exec-binding checks (PATH, binaries,
scripts, push target) still apply.

## MCP gateway (M6)

```bash
agentgate mcp wrap [--name N] [--env E] [--ttl S] -- <upstream MCP server command…>
agentgate mcp install   --client <claude-desktop|cursor|claude-code|codex> [--project DIR] (--server NAME… | --all)
agentgate mcp uninstall --client <…> [--project DIR] [--server NAME… | --all]
agentgate mcp status [--project DIR]
```

`wrap` is a raw stdio JSON-RPC relay (newline-delimited). Every message passes through
byte-for-byte in both directions (initialize, lists, notifications, server→client
sampling/elicitation, unknown/future methods), except client `tools/call`:

- **Action:** `mcp.invoke`, tool `<server>/<tool>`, arguments `{server, tool, arguments, annotations}`.
  `agent.type` comes from `initialize.clientInfo.name` (claude-ai → claude-desktop, cursor,
  claude-code, codex, else `mcp-client`).
- **Annotations:** learned from `tools/list`, via the client's own calls or an internal one
  the client never sees, and refreshed on `notifications/tools/list_changed`. With MCP
  defaults an unannotated tool is presumed destructive → high risk → ask. `readOnlyHint`
  tools are classified normally.
- **Allow / approved:** the signed token is verified (pinned key, single-use nonce), then the
  parsed request is forwarded (same id, same arguments). `started` is reported, then
  `completed` or `failed` from the response (`isError` or JSON-RPC error → failed).
- **Everything else is answered by the gateway itself** with
  `{isError:true, content:[{type:"text", text:"Blocked by AgentGate: <reason>"}]}` and never
  forwarded: deny, denied, expired, timeout, API unreachable, bad token, gateway error.

Also:
- One AgentGate session per gateway process, created on the first gated call and ended on
  stdin EOF / upstream exit / signal, which cancels pending approvals.
- `notifications/cancelled` for a pending call cancels its approval, and no response is sent.
- Lines that aren't JSON, and requests whose raw text contains `"method":"tools/call"` but
  don't parse as one (duplicate keys), are refused.
- If the upstream crashes, every pending request gets a JSON-RPC error and the gateway
  exits non-zero.
- Logging goes to stderr only; tool arguments are never logged.

**Client timeouts (not ours to control).** Approval can take up to the TTL (120 s default);
clients give up earlier:
- Claude Code: `MCP_TOOL_TIMEOUT` env var.
- Codex: `tool_timeout_sec` per server (default 60 s).
- Cursor and Claude Desktop: fixed internal timeouts, roughly a minute, undocumented.
- Clients built on the TS SDK with `resetTimeoutOnProgress` extend the deadline on our
  `notifications/progress` heartbeat (every 5 s, only when the request carried
  `_meta.progressToken`).

If the client times out, it usually sends `notifications/cancelled`, which cancels the
approval. Otherwise a late approval is still forwarded; the client just no longer sees the
result.

**install** rewrites `{command, args, env}` stdio entries to
`{command: <abs agentgate.sh>, args: ["mcp","wrap","--name",N,"--",command,...args], env: {...env, AGENTGATE_HOME, AGENTGATE_NODE, AGENTGATE_MCP_WRAPPED:"1"}}`.
Other keys are kept. `url`/HTTP/SSE servers are skipped. Originals go in
`$AGENTGATE_HOME/mcp-installs.json`, with a timestamped backup on every change.
Uninstall restores the file byte-for-byte when it is unchanged since install; otherwise it
restores just our entries.

Codex `config.toml` is edited at the `[mcp_servers.<name>]` table level and verified by
re-parsing: the rest of the document must be identical. Inline/dotted or split definitions
are refused.

Config locations:
- Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Cursor: `~/.cursor/mcp.json`, or `<project>/.cursor/mcp.json` with `--project`
- Claude Code: `<project>/.mcp.json`
- Codex: `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`)

Restart the client after install/uninstall. Note: Claude Code sessions that also have the
installed PreToolUse hook see `mcp__*` calls twice (hook + gateway); for Claude Code prefer
one or the other.

## Security model details (M5 security pass)

**Pairing (C2).** Device login needs a one-time code: run `agentgate pair` (8 chars, 5 min,
single use; also shown as a QR of `agentgate://pair?server=…&email=…&code=…`), then
the app logs in with `POST /v1/auth/login {email, client:"device", pairing_code}`. Agent
login is accepted from loopback only (`AGENTGATE_ALLOW_REMOTE_AGENT_LOGIN=1` to override).
Device tokens issued before this change keep working until they expire (12 h); after
that the phone must pair.

**Login (H4).** `agentgate login` refuses a server signing key that differs from the
pinned one, prints both fingerprints, and requires `--accept-new-key`. Plain `http://` is
only accepted for loopback servers unless `--insecure-lan` is passed.

**Execution binding (H2).** Approved shell actions carry `arguments.exec_context` (hashed,
so the signed approval covers it). It contains the PATH at approval time, the absolute
path of every segment's first binary (including wrappers like `sudo`/`env`), the sha256 of
interpreter scripts (`bash|sh|zsh|node|python… <file>`) and of project-local executables,
and every `git push` target (push URL + refspec, also shown on the phone as the
resource). At execution, `request`/`exec` re-resolve all of it with the approved PATH.
Any difference blocks with `binary_changed` / `script_changed` / `push_target_changed`
(77). The command runs with the approved PATH and a scrubbed environment: `GIT_*`,
`LD_*`/`DYLD_*`, `BASH_ENV`, `ENV`, `NODE_OPTIONS`, `PYTHONSTARTUP`/`PYTHONPATH`,
`PERL5*`, `RUBY*`, `ZDOTDIR`, `IFS`, `CDPATH`, `BASH_FUNC_*` and `AGENTGATE_*` are dropped.
Git hooks are disabled via `GIT_CONFIG_*` → `core.hooksPath=/dev/null` (context shows
"git_hooks: disabled"), unless `AGENTGATE_ALLOW_GIT_HOOKS=1` was set when the action was
approved. That setting is recorded in the binding. The shims also strip `NODE_OPTIONS`,
`NODE_PATH`, `BASH_ENV`, `ENV`, `DYLD_*`, `LD_*` before starting node.
Note: for installed hooks the PATH is the one Claude Code gives its hooks, which can be
shorter than the Bash tool's.

**Self-protection (H3/H4).** The hook matcher includes `Read`, but only sensitive reads
are governed (`$AGENTGATE_HOME/**`, API secrets and `.data` key files, `~/.ssh/**`,
`.env*`). They are asked; all other reads get no output. These are denied regardless of
policy:
- `agentgate login|logout|install|uninstall|pair` run by the agent;
- direct calls to `/v1/pairing`, `/v1/auth/login|refresh`, `/v1/devices` and
  `/v1/approvals/:id/approve|deny|cancel`;
- writes to `$AGENTGATE_HOME`, to AgentGate's own code (`daemon/agentgate`,
  `adapters/claude-code`, `packages`, `node_modules`), to the API data/secrets dirs, and
  to `.claude/settings*.json`.

Other Bash commands that mention those paths are asked. Other `.claude/**` writes are
high risk.

**Blocks vs. failures.** Every block prints exactly one
`agentgate: BLOCKED [<reason>] <message>` line on stderr, exits 77 (130 if interrupted)
and reports `blocked` with `detail = "<reason>: <message>"`. A command that itself exits
77 prints no such line and is reported `failed` with exit 77 and a note. The shell's exit
status is always reported as-is. For `;`/newline/`&`-separated lists (e.g.
`git push; git log -1`) that status only reflects the last command, and the audit detail
says so.

**Upgrading an existing install.** Re-run `agentgate install claude-code` (idempotent) to
pick up the `Read` matcher and the `PostToolUse` hook. Approvals made by an older daemon
have no binding; `exec` refuses them (`binding_missing`).

## Test / demo hooks (only honored with `AGENTGATE_DEV=1`)

| Env | Effect |
|---|---|
| `AGENTGATE_TAMPER_COMMAND="<cmd>"` | After approval, replaces the command right before the final hash re-check (in `request`, and in `exec` at the Claude execution boundary), simulating an action swapped between approval and execution. Expected: `approval token rejected (hash_mismatch)`, exit 77, nothing runs, execution reported `blocked`. |
| `AGENTGATE_WAIT_GRACE_MS=<ms>` | Overrides the 10 s timeout grace (tests). |

`AGENTGATE_HOME` (any mode) relocates `config.json`, `policy.yaml` and `nonces/`.

```bash
AGENTGATE_DEV=1 AGENTGATE_TAMPER_COMMAND="git push --force" npx agentgate request -- git push
```

## Secret hygiene (trade-off)

The command is **not** redacted before submission: the approval token binds the hash of the
exact command that executes, and the human must see what they approve. Redacting would
either break verification or make the phone show something other than what runs. Instead:
access/approval tokens are never printed; `--verbose` debug output redacts `Authorization`,
`access_token`, `approval_token` and token-shaped strings; WS auth uses the `Authorization`
header (not the query string) so tokens don't land in access logs. Don't put secrets in
commands you route through AgentGate; a future version may refuse commands that look like
they embed credentials.

## Layout

```
bin/agentgate.mjs        tsx shim
bin/agentgate.sh         node-locating runner (used in rewritten Claude Bash commands)
bin/agentgate-hook.sh    fail-closed Claude Code hook entry (anything but 0 → exit 2)
src/main.ts              arg parsing (node:util parseArgs) + dispatch
src/client/              HTTP client, agent WebSocket, ApprovalWaiter — no CLI deps (→ packages/sdk later)
src/commands/            login, status, request, exec, hook, run, config/logout
src/authorize.ts         shared policy → report → wait pipeline (request + hook)
src/approval-store.ts    hook → exec token hand-off (0600, keyed by approval id)
src/verify.ts            execution gate (hash recompute + token verify)
src/nonce-store.ts       persistent single-use nonce store
src/action.ts exec.ts config.ts policy.ts git.ts output.ts
test/                    vitest: gate unit tests + subprocess e2e against an in-process fake API
                         (request, hook, shim, exec, run with a fake `claude`)
```

Tests: `npx vitest run --project cli` (root) or `npm test -w @agentgate/cli`.
