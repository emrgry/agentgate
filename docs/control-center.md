# AgentGate Control Center — plan

> "AI agents work for me, but I still have to sit in front of them." — the problem.
> Give the agent the work, walk away; AgentGate pulls you in only when needed.

Builds on M7 (local-first): each developer machine runs the AgentGate server
(`agentgate setup`, launchd), the phone pairs per machine, and anything the phone sends
is signed with its device key.

## 1. What we reuse

| Existing | Reused for |
|---|---|
| Local server (Fastify + PGlite), launchd service | sessions / events / interactions / commands storage + supervisor host |
| WS hub `/v1/device/connect`, push (Expo), audit log | realtime session updates, smart notifications, audit |
| Device keys + `@agentgate/signing` (phone-signed decisions) | phone-signed **control commands** (instruct / answer / pause / stop / kill) |
| Policy engine + PreToolUse hook + approvals | unchanged: managed sessions still gate every risky tool call on the phone |
| `claude-sessions.ts` (Claude session_id ↔ AgentGate session) | provider session identity |
| Mobile multi-computer store, Face ID signing, inbox | Sessions tab across all paired computers (= fleet view) |

## 2. How we get control of an agent (verified against Claude Code docs, 2026-09)

Two integration modes per provider, same normalized model:

**A. Managed sessions (primary, full control).** The AgentGate *supervisor* (inside the
local server process) runs the agent headless, one process per turn:
`claude -p <instruction> [--resume <provider_session_id>] --output-format stream-json --verbose --settings <agentgate hook>`.
- stream-json → normalized events (init/session_id, assistant text, tool_use, tool_result,
  result with `total_cost_usd`, `usage`, `duration_ms`).
- Turn ends → status `waiting_input` if the last assistant message asks the user something
  or no queued work, else `completed`. **Remote instruction = next turn with `--resume`**
  (documented: resume loads full context, also for sessions started interactively).
- Pause = SIGSTOP/SIGCONT on the turn's process group; Stop = SIGINT (ends turn cleanly)
  and no further turns; Kill = SIGKILL process tree.
- Tool calls still go through the AgentGate PreToolUse hook → phone approvals.

**B. Observed sessions (interactive terminal / desktop app / IDE).** Installed hooks
(SessionStart, UserPromptSubmit, PostToolUse, Notification, Stop, SessionEnd) report events.
- Monitoring works for any session.
- **Handoff** = when the interactive session is idle/closed, the phone can "Continue remotely",
  which starts a managed turn with `--resume <session_id>`. Same conversation, continues
  where it left off.
- Experimental (Phase 2, needs empirical verification): Stop hook "away mode" that holds the
  turn open and feeds the phone's reply back as the continuation reason.
- Not possible via documented APIs: answering Claude's `AskUserQuestion` from outside,
  injecting text into a live interactive TTY. We don't fake these.

Providers: Claude Code (Phase 1); Codex (`codex exec --json`, `codex exec resume`) and a
generic PTY/command provider for Hermes and others (Phase 2).

## 3. Data model (server)

```
agent_sessions   id, computer-local; provider, provider_session_id, mode(managed|observed),
                 title, cwd, repo, branch, status, current_task_id, pid, started_at,
                 last_event_at, ended_at, summary_json, usage_json
session_events   id, session_id, seq, type, payload_json, created_at     (append-only)
interactions     id, session_id, kind(input_required|question), prompt, status
                 (pending|answered|expired|cancelled), answer, answered_by_device, timestamps
control_commands id, session_id, command(instruct|answer|pause|resume|stop|kill), payload_json,
                 signed_command, status(queued|applied|rejected|failed), device_id, timestamps
workspaces       id, path, label   (allowlist of dirs where the phone may start sessions)
tasks            (Phase 2) id, session_id, prompt, status(queued|running|waiting|completed|failed), order
```

Session status: `starting · running · waiting_input · awaiting_approval · paused · stopping ·
completed · failed · stopped · killed · lost`.

## 4. Event model (normalized, provider-agnostic)

`session.started · status.changed · message.user · message.assistant · tool.call ·
tool.result · approval.requested · input.required · turn.completed(usage, cost, duration) ·
session.completed(summary) · session.failed(error) · session.terminated(unexpected)`.
Adapters map provider output → these; core never sees provider formats. Clients get
`session.updated` + `session.event` over the existing device WebSocket; history via REST
(paged by `seq`).

## 5. Provider abstraction

```ts
interface AgentProvider {
  id: "claude-code" | "codex" | string;
  capabilities: { resume: boolean; pause: "signal"|"none"; observe: boolean; cost: boolean };
  buildTurnCommand(req: { instruction: string; providerSessionId?: string; cwd: string; hookSettingsPath: string }): { cmd: string; args: string[]; env?: Record<string,string> };
  parseOutputLine(line: string): NormalizedEvent[];     // stream → events (pure)
  isQuestion?(lastAssistantText: string): boolean;       // heuristic for input_required
  normalizeHook?(hookEvent: unknown): NormalizedEvent[]; // observed mode (pure)
}
```
Supervisor = provider-agnostic: spawns turns, applies control commands, owns status machine.

## 6. Security

- Every remote **instruction, answer and control command is signed on the phone** (device
  key, Face ID for kill; instruction/answer signing reuses the per-decision key prompt) and
  verified by the supervisor before acting. A compromised relay/server can't inject prompts.
- Sessions can only be started by the phone inside allowlisted `workspaces`.
- Managed sessions never use `bypassPermissions`; tool calls still go through policy + phone.
- Push bodies stay content-free ("Claude Code is waiting for you"); details only in-app.

## 7. Phases

| Phase | Scope |
|---|---|
| **1 — vertical slice** | Claude managed sessions (start from CLI or phone), realtime status + event timeline, remote instruction, `input_required` + notification + reply → resume, Pause/Resume/Stop/Kill, completion summary (last message, `git diff --stat`, cost/tokens/duration) + notification; observed sessions via hooks (monitor + "Continue remotely"); signed commands; Sessions tab (fleet across computers) |
| 2 | Task queue per session; fleet dashboard polish; Codex provider; generic PTY provider (Hermes); Stop-hook away mode (verified) |
| 3 | Mobile PR/diff review (files, +/-, tests, diff viewer, request changes / open PR via `gh`, approve next step); smart notification rules (stuck / repeated failure / PR ready); voice (iOS dictation + native speech recognition, no extra LLM) |
| 4 | Cost & resource control: per session/task/provider cost, duration, retries, CPU/RAM; policies (max cost/duration/retries → pause/ask/stop); process-tree kill, credential revoke |
| — | Relay (phone ↔ computer outside the LAN), required before "walk away" works off-Wi-Fi |

## 8. Phase 2 — providers (server side)

Every provider implements `AgentProvider` (`packages/adapters`). The supervisor runs one
process per turn in its own process group and calls `preflight` before each turn
(failures fail the task closed). It uses `createParser()` (stateful, with `end(exitCode)`)
when the provider has one. `GET /v1/providers` reports `available` (the binary resolves on
the owner's PATH) and `gated`.

### Claude Code
Unchanged from Phase 1: `claude -p --output-format stream-json`, with gating by the managed
PreToolUse/PostToolUse hook settings.

### Codex (`adapters/codex`)
- **Turn:**
  `codex exec --json -C <cwd> --sandbox workspace-write --skip-git-repo-check --dangerously-bypass-hook-trust [extra] -`,
  with the prompt on stdin.
- **Resume:** `codex exec resume --json … <thread_id> -`. The `thread_id` comes from
  `thread.started`.
- **Never passed:** `--yolo`, `--dangerously-bypass-approvals-and-sandbox`,
  `danger-full-access`, `--full-auto` or `--ephemeral` (resume would break). A user
  `--sandbox/-s` is also filtered out. `AGENTGATE_CODEX_ARGS` can add other flags.
- **Gating:** each managed session gets its own `CODEX_HOME` under
  `<server dir>/provider-homes/codex/<session>`. It holds a copy of the owner's
  `auth.json`/`config.toml` plus a `hooks.json` whose `PreToolUse` runs
  `agentgate-hook.sh --agentgate-provider=codex`, which calls `agentgate hook codex`.
  The owner's `~/.codex` is never modified.
  - The hook normalizes Bash to `shell.execute`, `apply_patch`/Edit/Write to
    `filesystem.write` (with the patch paths and sensitive-path risk), and `mcp__*` to
    `mcp.invoke`. Any other tool becomes `tool.invoke` with high risk.
  - It asks the phone when the policy says so. Deny means exit 2 with the reason on stderr.
  - An approved token is verified **and consumed in the hook** for every tool, including
    Bash. (Codex does accept a rewritten input, but a rewritten `agentgate exec …` would run
    inside Codex's sandbox, which can't write `~/.agentgate` or reach the server; see below.)
  - Self-protection (`codexGuard`) and the Bash exec-context binding + re-check described
    under "Interactive Codex" apply to managed turns too.
- **Version:** `codex --version` must parse and be ≥ `AGENTGATE_CODEX_MIN_VERSION`
  (default 0.40.0). Otherwise every turn fails closed. The hook contract below was only
  verified on 0.131.0–0.158.0.
- **Cost:** Codex reports tokens only, so `usage.cost_usd` stays null.

### Interactive Codex (`agentgate install codex`)
Gates the user's normal Codex — `codex` in a terminal, `codex exec`, and (not run here) the
IDE extension / app, which use the same `CODEX_HOME` — not only Control Center turns.

```bash
agentgate install codex --user --yes      # every Codex session for this OS user (recommended)
agentgate install codex --project DIR     # only DIR (loads only when Codex trusts the project)
agentgate uninstall codex [--user | --project DIR]
```

What it writes (backups next to each file; `agentgate uninstall codex` and the full
`agentgate uninstall` restore the original bytes if the file wasn't edited since, otherwise
remove only our entries):
- `<CODEX_HOME>/hooks.json` (default `~/.codex`; `$CODEX_HOME` is honored) or
  `<DIR>/.codex/hooks.json`: a `PreToolUse` group with no matcher (every tool, timeout 600 s)
  and a `SessionEnd` group (3 s), appended after the user's groups. The command is
  `AGENTGATE_HOME=… AGENTGATE_NODE=… AGENTGATE_HOOK_TIMEOUT_S=600 AGENTGATE_CODEX_INSTALL=user|project
  ~/.agentgate/current/bin/agentgate-hook.sh --agentgate-provider=codex --agentgate-install=codex/v1`
  (the checkout's `daemon/agentgate/bin/agentgate-hook.sh` in dev) — absolute paths, no tokens.
- `<CODEX_HOME>/config.toml` (always the user file, also for `--project`): a marked block of
  `[hooks.state."<hooks.json path>:<event>:<group>:<handler>"] trusted_hash = "sha256:…"`
  tables. Codex **skips non-managed hooks that aren't trusted**, silently, so without this
  the install would gate nothing. If the file can't safely take new tables (an inline
  `hooks = {…}`/`hooks.state = {…}`, or an existing entry for our key), the hook is still
  installed but the command warns loudly and asks the user to trust it in Codex's `/hooks`.
  Codex edits `config.toml` itself (e.g. when you trust a project) and may insert its tables
  inside our marked block; uninstall then removes exactly our `hooks.state` tables and the
  markers and keeps Codex's additions (verified with 0.158).
- `$AGENTGATE_HOME/codex-installs.json`: the install record (for uninstall).

`agentgate status` shows whether the hook is installed **and trusted**, whether hooks are
turned off in config.toml, and when the hook last ran.

**Hook behavior** (`agentgate hook codex` with `AGENTGATE_CODEX_INSTALL` set):
1. Tools that run and write nothing (`update_plan`, goal tools, `request_user_input`,
   `tool_search`, subagent control, `view_image` of a non-secret file) exit 0 without a
   round trip. Everything else is governed; unknown/future tools are high risk (→ ask).
2. `codexGuard` floor: `agentgate install|uninstall|login|pair|update|…`, AgentGate's
   credential/approval endpoints, AgentGate's own files, `.codex/hooks.json|config.toml|
   requirements.toml` (user or project, and a custom `CODEX_HOME`), Claude and Cursor hook
   settings → **deny** (exit 2, nothing submitted). Nested `codex` launched with another
   `CODEX_HOME`/hook bypass, commands touching AgentGate paths, and bare interactive
   interpreters (`python3`, `bash -i`, `psql` … — later `write_stdin` input is never hooked)
   → at least **ask**.
3. Policy → allow (exit 0, no stdout) / deny (exit 2 + reason) / ask: the approval is created
   and pushed, the hook **blocks** until the phone's signed decision arrives, verifies the
   token against the pinned key (and pinned device keys when device signatures are
   required), consumes its one-time nonce, and only then exits 0.
4. Bash approvals carry the exec context (resolved binaries, script hashes, push target;
   `git_hooks: "allowed"`, since nothing can disable git hooks without an exec wrapper). The
   context is recomputed right before allowing; any difference → exit 2 ("changed while
   waiting for approval"), so a script rewritten while the phone was deciding is caught.
5. Deadline: the hook stops itself at `AGENTGATE_HOOK_TIMEOUT_S − 30` s (570 s), well before
   Codex's 600 s timeout (a timeout would fail open), withdraws the approval from the phone
   and blocks with "nothing was run; ask Codex to retry and approve the request on your
   phone". The approval TTL (`--ttl`, default 120 s) usually ends the wait first.
6. Server unreachable, logged out, bad input, crash, missing node → exit 2 with a reason.
7. `SessionEnd`: withdraws still-pending approvals and ends the hook-managed AgentGate
   session (`codex:<session_id>`), within Codex's 3 s cap.
8. A **project** install inside a Control Center turn (CODEX_HOME = a supervisor-prepared
   home under `$AGENTGATE_HOME` whose hooks.json runs the managed hook, and the matching
   receipts file) exits 0 and lets the managed hook gate — no double approvals. A user
   install is never loaded in managed turns (their CODEX_HOME is different). Managed homes
   copy the owner's `config.toml`, including our trust block; it's inert there.

**What is gated / not gated**

| Gated | Not gated |
|---|---|
| Shell (`exec_command`/`shell` → `Bash`) | `write_stdin` into an already-running command (Codex never hooks it; hence the ask floor on bare interpreters) |
| `apply_patch` (every file in the patch) | Hosted tools (web search) — no local code runs |
| MCP tool calls (`mcp__server__tool`) | Anything Codex runs outside the tool path ("specialized tool paths can opt out", per the docs) |
| Other local function tools (unknown → ask) | A nested agent/Codex the agent launches with its own config (the launch itself is asked) |
| Sensitive `view_image` reads | Codex versions without hooks / hooks turned off / the hook untrusted — Codex then runs ungated; `agentgate status` reports it |

**Residual risks**
- **Fail-open surfaces owned by Codex.** Exit codes other than 2, exit 2 with empty stderr,
  a crash or the hook timeout all let the tool run. The shim maps everything but 0/2 to 2
  with a reason, and the node deadline fires 30 s early, but a killed/hung shell before the
  shim runs, or the machine sleeping through the 600 s, would fail open.
- **Trust is Codex's switch.** Anyone who can edit `hooks.json` or `config.toml` can untrust,
  disable (`[features] hooks = false`, `hooks.state.<key>.enabled = false`) or remove the
  hook; so can the user in `/hooks`. The guard and the default policy deny agent writes to
  those files, and the trust key includes the group index, so the user inserting a group
  *before* ours also untrusts it (status shows NOT GATING; re-run install).
- **TOCTOU.** There is no `agentgate exec` wrapper: after the hook returns, Codex runs the
  command itself. The command text can't change (Codex runs the tool input it passed us,
  and the token is bound to it), and the exec context is re-checked at the last moment, but
  a change in the milliseconds between hook exit and execution isn't caught; PATH can also
  differ because Codex runs commands in a login shell (`zsh -lc`). Git hooks are not
  disabled for approved commands.
- **Another PreToolUse hook's `updatedInput` wins.** Hooks run concurrently and the last
  rewrite applies; a user's own rewriting hook could change an approved command. Install
  warns when other PreToolUse hooks exist.
- **`workdir` is invisible.** Codex's shell tool can run in a `workdir` the hook input
  doesn't include; relative paths, repo/branch context and exec-context resolution use the
  session `cwd`.
- **Hook sessions** are registered under the machine's `claude-code` agent record (shared
  helper); actions still carry `agent.type: "codex"`.

#### Codex hooks contract (verified)
Sources: the official docs <https://developers.openai.com/codex/hooks> (`.md` version),
<https://github.com/openai/codex/blob/main/docs/config.md>, the generated schemas in
<https://github.com/openai/codex/tree/main/codex-rs/hooks/schema/generated>
(`pre-tool-use.command.{input,output}.schema.json`) and the implementation in
`codex-rs/hooks/src/events/pre_tool_use.rs`, `codex-rs/hooks/src/engine/{output_parser,discovery}.rs`,
`codex-rs/hooks/src/config_rules.rs`, `codex-rs/hooks/src/lib.rs` (`hook_key`),
`codex-rs/config/src/{hook_config,fingerprint}.rs` and `codex-rs/utils/home-dir/src/lib.rs`
(openai/codex `main`, 2026-09-28). **Run-verified** by driving the real `@openai/codex`
binaries 0.131.0, 0.132.0, 0.133.0, 0.136.0, 0.138.0, 0.140.0, 0.150.0 and 0.158.0 against a
mock Responses API with a temp `HOME`/`CODEX_HOME`, and 0.158.0 end to end through
`agentgate install codex` + a fake AgentGate server (allow, ask→approve, ask→deny, policy
deny, guard deny, apply_patch, deadline, server down, project scope, SessionEnd).

- **Config:** `hooks.json` next to each active config layer, or inline `[hooks]` in
  `config.toml`: `~/.codex/hooks.json` (really `$CODEX_HOME`; `$CODEX_HOME` is canonicalized,
  `~/.codex` is not), `~/.codex/config.toml`, `<repo>/.codex/hooks.json|config.toml`
  (per the docs the project layer loads only when Codex trusts the project; verified that it
  loads in a trusted project, also when Codex starts in a subdirectory). All matching hooks from all layers run, concurrently. `hooks.json` accepts
  only `description` and `hooks` at the top level. Hooks are on by default (`[features]
  hooks = false`, deprecated alias `codex_hooks`, turns them off); admins can force
  `allow_managed_hooks_only` in `requirements.toml`.
- **Trust:** non-managed hooks run only if `hooks.state."<key>".trusted_hash` in the **user**
  `config.toml` (or `-c` session flags) equals the current hash; otherwise they're skipped
  (verified: untrusted and hash-mismatched hooks don't run; no error in `codex exec`).
  `key = "<abs hooks.json path>:<event_snake>:<group idx>:<handler idx>"`;
  `hash = "sha256:" + sha256(key-sorted compact JSON of {event_name, matcher?, hooks:[{type,
  command, timeout, async, statusMessage?, additionalContextLimit?}]})` with the timeout
  normalized. `/hooks` in the TUI reviews/trusts; `--dangerously-bypass-hook-trust` skips the
  check for one invocation (Control Center turns use it).
- **Events:** PreToolUse, PermissionRequest, PostToolUse, Pre/PostCompact, SessionStart/End,
  UserPromptSubmit, SubagentStart/Stop, Stop, Interrupt. Matcher = regex on the tool name;
  omitted/`*`/`""` = all.
- **PreToolUse stdin:** `{session_id, turn_id, transcript_path, cwd, hook_event_name, model,
  permission_mode, tool_name, tool_input, tool_use_id}` (+ `agent_id/agent_type` for
  subagents). Shell/unified exec → `tool_name: "Bash"`, `tool_input: {command: "<string>"}`
  (no `workdir`); `apply_patch` → `{command: "<patch>"}` (the adapter used to read
  `input`/`patch` only — **fixed**); MCP → `mcp__<server>__<tool>` with the arguments; other
  local tools by name (`spawn_agent` also matches `Agent`). Hosted tools and `write_stdin`
  don't run PreToolUse.
- **Deny:** exit 2 **with non-empty stderr** (verified), or stdout
  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
  "permissionDecisionReason":"…"}}` (verified), or legacy `{"decision":"block","reason":…}`.
- **Fail-open (verified):** exit 2 with empty stderr, exit 1/any other code, a crash, the hook
  timeout (default 600 s; SessionEnd/Interrupt 1 s, max 3 s), `permissionDecision: "ask"`,
  `allow` without `updatedInput`, and `continue/stopReason/suppressOutput` are all treated as
  "hook failed" and the tool runs.
- **Blocking and waiting:** synchronous hooks block the tool until they exit (verified with a
  30 s sleep and 20 s timeout → killed at 20 s, tool ran). Hooks run **outside** Codex's
  sandbox (verified: network + writes outside the workspace work), while the command itself
  runs sandboxed (`workspace-write`: no writes outside the workspace/tmp, no network —
  verified), which is why an `agentgate exec` rewrite can't work.
- **Rewriting:** `permissionDecision: "allow"` + `updatedInput` (`{command: string}` for
  Bash/apply_patch, the argument object for MCP/other tools) replaces the input (verified on
  0.133 and 0.158); with several hooks the last to finish wins.
- **Minimum version:** hooks.json + trust + exit-2 blocking verified on 0.131.0–0.158.0.
  **Not verified:** ≤ 0.130.0 (those builds are SIGKILLed on the macOS used here), the TUI
  and IDE extension/app (same hooks engine, not run), MCP payloads (docs only),
  PermissionRequest, Windows.

### Generic providers (`adapters/generic`, providers.yaml)
Profiles are the built-in `adapters/generic/profiles/*.yaml` (currently Hermes) plus
`~/.agentgate/providers/*.yaml`. A user file overrides a built-in with the same id; the ids
`claude-code` and `codex` are reserved. Invalid files are skipped with a warning naming the
file and field.

A profile declares:
- the binary, the args and how the prompt is passed (`stdin` | `arg` | `flag`);
- an optional resume template containing `{session_id}`;
- the output format:
  - `text`: the final text only;
  - `jsonl`: matchers for session id, assistant text (delta/full), tool call/result, usage,
    error and done. The result is synthesized from `success_exit_codes` if no done event
    arrives.
- the approval mode:
  - `hook`: a per-session home dir (`home_env`, e.g. `HERMES_HOME`) copied from `copy_from`,
    with `config_patch` merged into `config_file`. `{hook_command}` becomes
    `agentgate-hook.sh --agentgate-provider=<id>`.
  - `sandbox-only` | `none`: **ungated**.
- optional `detect`: a help-text feature probe with a fallback mode.

**Hermes (built-in):**
- `hermes chat --oneshot -Q --format stream-json --query-file -`, resumed with `-r <id>`.
- If `hermes chat --help` does not mention `--format` (stream-json landed in September 2026),
  the provider falls back to text mode: `-z`, final text only, **no resume**.
- The Hermes shell hook gets the same PreToolUse contract as Codex.

### Gating tripwire (defense in depth)
When a turn command sets `gateReceipts`, the hook appends JSONL receipts to that file:
- `invoked` is written **before** the hook asks anyone;
- `decision` (allow/deny) is written afterwards.

A receipt that cannot be written blocks the call.

The supervisor matches every tool the provider reports:
- **Tool started:** after `tripwireGraceMs` (default 2 s) an `invoked` receipt must exist.
  Matching is by tool id, then command text or path overlap, then the oldest unconsumed
  receipt of the same kind.
- **Tool completed (not declined):** the same matching applies. If the matched receipt's
  decision was `deny`, that is a bypass.

With no match (the hooks silently didn't fire, e.g. an untrusted hook, the wrong config
format or an old version), the supervisor:
- sends SIGKILL to the process group;
- fails the task with "gating inactive: tool ran without AgentGate check" (or "gating
  bypassed: …");
- sends a `task_failed` push and writes an `execution.blocked` audit entry.

Hosted tools such as Codex web search run no local code and are not checked.

### Ungated providers
Providers with `gated: false` (profiles with approval `none`/`sandbox-only`) are listed with
`gated: false`. They only start in a workspace where the owner opted in **on the computer**:
`agentgate workspace allow-ungated <dir> <provider>`, which calls
`POST /v1/workspaces/:id/allow-ungated`. That route is for a local agent only; the phone
can't opt in. Sessions carry `gated: false`, which the phone shows as a red UNGATED badge.
`disallow-ungated` revokes the opt-in.

### Approvals → session status
The Codex/generic hooks put `agentgate_control_session` (from `AGENTGATE_CONTROL_SESSION`,
which the supervisor sets per turn) into the action context. An approval request therefore
moves the right session to `awaiting_approval`. Claude still maps through
`claude_session_id`.

## 9. Phase 3: review and smart notifications (server side)

### Git base
When a session starts, and again when each task starts, the supervisor records a **base**:
- a snapshot tree of the whole working copy (tracked and untracked files; `.gitignore` is
  respected), written with a throwaway index
  (`GIT_INDEX_FILE=<tmp> git add -A && git write-tree`);
- the HEAD sha and the branch.

The user's index, stash and refs are never touched. When a task ends, its end snapshot is
stored as well, so a finished task's diff stays stable while later tasks keep editing. Files
that were already dirty or untracked before the session therefore only show the session's own
edits. Summaries (`files_changed`/`additions`/`deletions`/`changed_files`) use this base
instead of HEAD, which fixes the Phase 1 gap. If the snapshot objects are gone (`git gc`
prunes unreferenced objects after about two weeks), the diff falls back to HEAD.

### Endpoints
- `GET /v1/agent-sessions/:id/changes[?task_id=]` returns a `ChangeSet`:
  - `git diff --name-status/--numstat -z -M` between the base and a fresh snapshot (or a
    task's end snapshot);
  - statuses: added | modified | deleted | renamed (with `old_path`) | copied | typechange;
  - binary files have `binary: true` and null counts;
  - at most 1000 files, with `truncated` set beyond that and `totals` still counting
    everything;
  - it also carries the last `tests` run and the `pr`.
- `GET /v1/agent-sessions/:id/diff?path=&task_id=` returns a `FileDiff` (unified, ≤ 256 KB,
  otherwise `truncated`).
  - `path` must be repo-relative and normalized: no `..`, no absolute path, no `~`, nothing
    under `.git/`, no NUL. The file (or its nearest existing parent, for deleted files) must
    resolve inside the repo after symlinks. Anything else returns 400.
  - Redaction: known token formats are masked on every line. In sensitive files (`.env*`,
    `.npmrc`, `credentials*`, keys/pems, …) every value is masked.

### Test runs
A shell tool call whose command matches a known runner is tracked: npm/pnpm/yarn/bun test,
vitest, jest, mocha, pytest, `python -m pytest|unittest`, `go test`, `cargo test|nextest`,
`node --test`, deno, mix, dotnet, gradle, mvn, `make test|check`, tox.

Its tool result is parsed for passed/failed/skipped. Supported formats: vitest, jest, pytest,
cargo, mocha, TAP/node:test, and `go test` (-v lines or package lines). Unknown formats give
null counts; `ok` then comes from the exit status.

The last run is stored per session and per task, with a redacted output tail of ≤ 4 KB, and
a `test.run` event is added to the timeline. The raw output tail (`output_tail` on the
provider's tool.result) is used only for this. It is stripped before the tool.result event
is stored.

### Commands
- `request_changes`: the text is prefixed "Review feedback: " and delivered like `instruct`
  (queued into a running turn, or a new turn). When `instruct` isn't possible (e.g. parked),
  it becomes a queued task.
- `approve_next`: sets `reviewed_at` on the task (default: the latest finished task) and, if
  the queue is held (idle, failed, lost, stopped) with queued tasks, starts the next one.
- `open_pr {title?, draft?, base?}`:
  - **Refused (rejected with a reason)** when the directory isn't a git repo, HEAD is detached,
    there is no `origin`, the branch is the default branch (or main/master), there are no
    commits beyond `origin/<default>`, a turn is running, a PR is already open, `gh` is
    missing, or `gh auth status` fails.
  - Otherwise the command returns `queued` and the rest runs in the background:
    `git push -u origin <branch>` (**never** `--force`), then
    `gh pr create --title … --body <summary> --head <branch> --base <default|base> [--draft]`
    with the owner's `gh`.
  - **Both commands go through the same policy and approval engine as agent actions.** The
    owner's `~/.agentgate/policy.yaml` is merged with the default policy and the stricter
    decision wins. A push is at least `ask`.
  - **The signed `open_pr` command does NOT approve the push.** The phone gets a separate
    approval request. For devices with keys, the phone's signed decision is verified
    (signature, action hash, approval id, session) before the push runs.
  - Progress shows up as `pr.status` events. The result is `pr.opened` (the PullRequestInfo
    is stored on the session and returned in `ChangeSet.pr`) with a `pr_ready` push, or
    `pr.failed` (denied, expired, push/gh error).
  - The action runs under an internal `agentgate`-type agent ("Control Center") and is
    recorded in the activity log like any action.

### Smart notifications
All pushes stay content-free and include `kind` in their data.

| kind | when | body |
|---|---|---|
| `stuck` | status `running` with no event for `AGENTGATE_STUCK_MINUTES` (default 10). Sent once per episode; a new event starts a new episode. | "… seems stuck" |
| `repeated_failure` | a failure that is the 3rd in a row or repeats the same error text. It replaces that failure's `task_failed` push and is not coalesced. | "… keeps failing" |
| `pr_ready` | after `pr.opened` | "…: pull request ready" |
| `budget_exceeded` | a limit was hit (Phase 4). Not coalesced: it may need an answer. | "… reached a limit" |

`stuck` and `pr_ready` use the normal 30 s per-session coalescing.

## 10. Phase 4: cost and resources (server side)

### Resources
Every ~5 s (the supervisor tick), one `ps -A -o pid=,ppid=,pgid=,%cpu=,rss=,lstart=` snapshot
is taken (macOS and Linux, no native deps). For each running turn, CPU% and RSS are summed
over its process group **plus every descendant found by a ppid walk**, which catches
children that left the group with setsid.

The supervisor keeps a 120-sample ring per session in memory. The current sample is
`SessionMetrics.resources` (null when nothing runs) and the ring is `history`.

### Retries
`retries` = failed tasks re-run (an instruct or answer that continues a failed task) plus
provider retry events (Claude stream-json `system/api_retry`).

### Limits
- **Scopes:** per session (`set_limits` on the session) and global defaults (`set_limits`
  with `session_id: "global"`, posted to `POST /v1/agent-sessions/global/commands`). Both are
  phone-signed like every command, or unsigned from a local agent via
  `agentgate limits set --global|--session`. The global response has `session: null`.
- **Effective limits:** field by field, a session value (including an explicit `null` = no
  limit) wins over the global one. `on_exceed` comes from the session if set, otherwise from
  the global limits (default `ask`).
- **Evaluation happens:**
  - at turn end (cost is only reported then), after the task is finished and before the queue
    advances;
  - on every resource sample (RSS, session/task minutes, only while a turn runs);
  - on provider retry events.
- **Missing cost:** when cost is null (Codex, and generic providers without cost), cost
  limits are skipped and `metrics.notes` says so.
- **Actions** (every hit is recorded in `exceeded`, newest first, and emitted as a
  `limit.exceeded` event):

  | on_exceed | while a turn runs | at turn end |
  |---|---|---|
  | notify | `budget_exceeded` push only | same |
  | ask | SIGSTOP the group, create a `budget` interaction, status `waiting_input`, `input.required {kind: "budget"}`, push | the queue is held with the same interaction |
  | pause | SIGSTOP, status `paused`, push (`resume` continues) | the queue is held (`waiting_input`), push; `approve_next`/`instruct` continue |
  | stop | stop (SIGINT, then TERM, then KILL) with reason "limit reached: …", push | status `stopped`, push |

- **Answering a budget question:** "continue" (or yes/ok/go on/resume) sends SIGCONT
  (running again) or continues the queue, and suppresses that limit for the rest of this
  task. Any other answer stops. A `stop` command also stops. While held, the turn can still
  be killed (`can.kill` stays true for a budget-held session).
- If the server restarts while a turn is budget-held, the orphan is terminated and the
  session becomes `lost`.

### Endpoints and CLI
- `GET /v1/agent-sessions/:id/metrics` returns `SessionMetrics` (usage, retries, resources,
  history, effective limits, exceeded, and notes).
- `GET /v1/usage?range=today|7d|30d` returns a `UsageReport` aggregated from sessions started
  in the range (UTC days):
  - `by_provider`: sessions, cost, tokens and duration;
  - `by_day`;
  - `total_cost_usd`, which is null if no cost was reported;
  - `global_limits`.
- CLI:
  - `agentgate limits set (--session ID | --global) [--max-cost-task USD] [--max-cost-session USD] [--max-session-minutes N] [--max-task-minutes N] [--max-retries N] [--max-rss-mb N] [--on-exceed notify|ask|pause|stop]`,
    where "none" clears a limit;
  - `agentgate limits show [--session ID]`;
  - `agentgate usage [--range today|7d|30d]`.

### Emergency kill
`kill` sends SIGKILL to the process group **and** to every process outside it that belongs to
the turn:
- descendants found by a ppid walk at kill time;
- any process the sampler saw in the turn's tree that still exists with the same start time
  (this guards against pid reuse and catches double-forked daemons whose parent already
  exited).

The count appears as `escaped_processes_killed` on the `control.applied` event.

Limitations:
- A process that escaped **and** was re-parented before any sample was taken cannot be
  attributed.
- *Later idea (not implemented):* revoke credentials on kill, e.g. short-lived per-session
  provider tokens or a per-session `CODEX_HOME`/`HERMES_HOME` whose copied `auth.json` is
  deleted on kill, so a surviving process loses API access.

## 11. Process trees and background commands

Claude Code runs Bash tool commands in their **own process group**. On a real device, the
shell and `sleep` had a different pgid from `claude -p`. Signals to the turn's group alone
therefore miss them.

- **pause / resume / stop / budget holds:** the supervisor takes a `ps` snapshot and signals
  the turn's whole descendant tree. The tree is:
  - a ppid walk from the turn's root, across process groups and sessions;
  - plus processes remembered from earlier snapshots that are still alive with the same start
    time;
  - plus the root's process group.

  Snapshots are taken on tool events (throttled), on every sampler tick, and before each
  signal. The order is:
  - SIGSTOP: children first, in reverse BFS order, then the root's group;
  - SIGCONT, SIGINT, SIGTERM, SIGKILL: the root's group first, then the children.
- **stop:** SIGINT to the tree, then SIGTERM, then SIGKILL (stop grace). When the turn ends
  after a stop, anything left in the tree is TERMed and then KILLed, and that includes
  background commands. **kill** sends SIGKILL to the whole tree right away (see §10).
- **Background commands** (e.g. Claude's `run_in_background`) that are still running when a
  turn ends are **not** killed. They are:
  - recorded on the session (`background_json`, capped at 50);
  - shown as `process.background {pid, command}` events and in
    `SessionMetrics.background_processes` (live ones only).

  `kill` on the session kills them, and `stop` terminates them, including on an idle session.
  They are attributed by the ppid walk while their parent is alive. A command started and
  re-parented between two snapshots can be missed.
- **Auto-continue** (`AGENTGATE_AUTO_CONTINUE_BACKGROUND`, default on; `0` disables): when all
  of a session's recorded background processes have exited (checked on each tick), the
  supervisor:
  - emits `process.background_finished {processes: [{pid, command, ran_ms, exit: null, outputs}]}`.
    The exit code is unknown because these processes aren't our children.
  - once the session is idle (waiting_input, no pending interaction, not running or parked),
    starts a `--resume` turn with this instruction:
    "[AgentGate] Background command(s) finished: `<cmd>` exited (ran 45s). Output file (if
    Claude reported one): <path>. Continue with what you were doing, and report the result to
    the user."

  The output path comes from the tool result ("…/tmp/claude-…"). The auto turn's
  `message.user` carries `origin: "agentgate"`. If a user turn is running when the background
  command finishes, the continuation runs when that turn ends, **before** the next queued
  task. There are at most 3 automatic continuations per user instruction or task; after that a
  `control.applied {command: "auto_continue", skipped}` event is emitted. Nothing is continued
  after stop or kill (the background list is cleared). Limits still apply to auto turns.

## 12. Real-device follow-ups (Phases 3 and 4)

- **Rejection codes:** every rejected command carries `SubmitCommandResponse.reason_code`.
  - open_pr: `default_branch`, `detached_head`, `no_origin`, `no_commits`, `turn_running`,
    `pr_exists`, `gh_missing`, `gh_unauthenticated`, `not_github`, `not_a_repo`,
    `invalid_branch`, `branch_exists`, `branch_create_failed`.
  - Other commands: `not_allowed_in_state`, `interaction_not_pending`, `task_not_queued`,
    `waiting_for_slot`, `no_queued_tasks`.
- **open_pr `create_branch`:** on the default branch, the name is validated:
  - it must match `^[A-Za-z0-9._/-]{1,100}$` and pass `git check-ref-format`;
  - it can't contain `..`, start with `-`, or equal the default branch;
  - it must not already exist locally or on origin.

  After **all** other checks pass, `git switch -c <name>` runs at HEAD. The local default
  branch is unchanged, and the session's branch becomes `<name>`. The rest is the normal flow:
  push with its own approval, then `gh pr create --base <default>`.
- **`not_github`:** the configured `remote.origin.url` (before any insteadOf rewriting) must
  point at github.com or a host `gh auth status` is logged in to. Local paths, `file://` URLs
  and other hosts are refused before anything is pushed or switched.
- **Cost kind:** detected per provider at server start and cached for 10 minutes.
  - Claude: `claude auth status` JSON. `authMethod: "claude.ai"` → `subscription_estimate`;
    an API key or console login → `api`.
  - Codex and generic providers: `unknown`.

  The kind appears in `SessionUsage.cost_kind` (sessions, tasks, metrics) and in
  `UsageReport.by_provider[].cost_kind`. Cost limits still apply to estimates.
- **Mid-turn cost limits:**
  - Each Claude `assistant` message carries `message.usage` and `message.model`. The adapter
    prices it with `adapters/claude-code/src/prices.ts`, a dated per-MTok table (estimate;
    cache writes by TTL, 1 h = 2× input; an unknown model is priced at the most expensive
    row).
  - The supervisor sums the estimate per message id for the current turn and evaluates cost
    limits at most once per second, adding the estimate to what earlier turns really cost.
    On a hit, `on_exceed` applies immediately: ask or pause SIGSTOPs the tree.
    `limit.exceeded` then carries `when: "mid_turn", estimated: true`.
  - At turn end the real `total_cost_usd` replaces the estimate. A limit already handled for
    the task isn't asked again.
  - Checked against the captured fixtures: the estimate matches the real total within about
    3%. Output tokens in streamed messages are partial, so the estimate runs slightly low.
- **Budget texts:** `input.required` and `limit.exceeded` carry `limit`, `value`,
  `limit_value`, `unit` (usd | minutes | count | mb), `estimated`, `cost_kind`, and
  `input.required` also carries `limits[]`. Example prompts:
  - "Estimated cost $0.87 exceeded your $0.10 per-task limit (included in your subscription — estimate)."
  - "Task has run 16 min, over your 15 min limit."
  - "4 retries, over your limit of 3."
  - "Memory use 612 MB, over your 512 MB limit."

  Each prompt ends with: Reply "continue" to go on, or "stop".
- **Approvals:** `approval.requested` session events always carry `approval_id`. A device can
  fetch (`GET /v1/approvals/:id`) and resolve the approval while the session shows
  `awaiting_approval`. This is tested for approvals linked through `agentgate_control_session`
  and through `claude_session_id`.
