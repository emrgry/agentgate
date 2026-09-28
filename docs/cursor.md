# Cursor: gating the Cursor agent

`agentgate install cursor --user --yes` gates what **Cursor's own agent** does: terminal
commands, file edits and deletes, MCP tool calls, and reads of sensitive files. It uses
Cursor's agent hooks. The MCP gateway (`agentgate mcp install --client cursor`) only covers
MCP servers. The hook covers the agent itself, and the two coexist (see below).

```bash
agentgate install cursor --user --yes          # every Cursor workspace (recommended)
agentgate install cursor --project ~/src/app   # one project (only runs in TRUSTED workspaces)
agentgate uninstall cursor --user              # or --project DIR; `agentgate uninstall` removes it too
```

## Cursor hooks contract (verified 2026-09-28)

Sources: <https://cursor.com/docs/hooks> (as markdown: `https://cursor.com/docs/hooks.md`),
<https://cursor.com/docs/reference/third-party-hooks> and the changelog
(<https://cursor.com/changelog/1-7> introduced hooks, beta;
<https://cursor.com/changelog/2-1> added project-level hooks;
<https://cursor.com/changelog/2-4> added preToolUse/postToolUse and Claude Code hook compatibility in the CLI;
<https://cursor.com/changelog/3-0> fixed multi-root project hook loading). Items marked
**unverified** are not stated in the docs. Check them on a real Cursor install (see
"Manual test" below).

| Topic | Contract |
|---|---|
| Config files | User `~/.cursor/hooks.json` (commands run from `~/.cursor/`). Project `<root>/.cursor/hooks.json` (run from the project root, **only in trusted workspaces**). Enterprise (MDM) `/Library/Application Support/Cursor/hooks.json` (macOS), `/etc/cursor/hooks.json` (Linux). Team hooks come from the dashboard (Enterprise). Cursor also loads Claude Code hooks from `.claude/settings.local.json`, `.claude/settings.json` and `~/.claude/settings.json` when *Settings → Agents → Third-Party Imports* is on (the default). |
| Schema | `{"version": 1, "hooks": {"<event>": [{"command": "...", "type"?: "command"\|"prompt", "timeout"?: seconds, "matcher"?: regex, "failClosed"?: bool, "loop_limit"?: n}]}}`. `version` is required and must be a positive integer (use `1`). `command` is a shell string, absolute path, or relative path. |
| Merging | All matching hooks from every source run. Cursor merges their answers so that `deny` beats `ask` and `ask` beats `allow`, whatever the source. `user_message`/`agent_message` are concatenated. Cursor watches the files and reloads them on save. |
| Events | Agent: `sessionStart`, `sessionEnd`, `preToolUse`, `postToolUse`, `postToolUseFailure`, `subagentStart`, `subagentStop`, `beforeShellExecution`, `afterShellExecution`, `beforeMCPExecution`, `afterMCPExecution`, `beforeReadFile`, `afterFileEdit`, `beforeSubmitPrompt`, `preCompact`, `stop`, `afterAgentResponse`, `afterAgentThought`. Tab: `beforeTabFileRead`, `afterTabFileEdit`. App: `workspaceOpen`. |
| Common stdin | `conversation_id`, `generation_id`, `model`, `model_id?`, `model_params?`, `hook_event_name`, `cursor_version`, `workspace_roots[]`, `user_email`, `transcript_path`. Env: `CURSOR_PROJECT_DIR`, `CURSOR_VERSION`, `CURSOR_USER_EMAIL`, `CURSOR_TRANSCRIPT_PATH`, `CLAUDE_PROJECT_DIR`. |
| `beforeShellExecution` | stdin `{command, cwd, sandbox}`. The matcher is tested against the command text. Output `{permission: allow\|deny\|ask, user_message?, agent_message?}`. |
| `beforeMCPExecution` | stdin `{tool_name, tool_input (JSON **string**), mcp_server_name}` plus `command` (stdio: launch command and args joined with spaces) or `url` + `mcp_server_url` (HTTP/SSE). Same output as shell. The docs advise treating a missing or unknown `mcp_server_name` as deny. Not available in cloud agents. |
| `beforeReadFile` | stdin `{file_path, content, attachments[]}`. Output `{permission: allow\|deny, user_message?}` (no `agent_message` documented). |
| `preToolUse` | Fires for **every** tool (`Shell`, `Read`, `Write`, `Grep`, `Delete`, `Task`, `MCP:<tool>`, …). The matcher is tested against the tool type. stdin `{tool_name, tool_input{…}, tool_use_id, cwd, agent_message}`. Output `{permission: allow\|deny, user_message?, agent_message?, updated_input?}`. `ask` is accepted by the schema but **not enforced** for preToolUse. Claude `Edit` maps to Cursor `Write`. |
| `afterFileEdit` | stdin `{file_path, edits[]}`. It runs after the edit, so it cannot block. |
| `sessionEnd` | Fire and forget. stdin `{session_id (= conversation_id), reason, duration_ms, …}`. |
| Exit codes | `0`: Cursor uses the JSON on stdout. For permission hooks, invalid JSON or a response that doesn't match the schema **blocks**. `2`: block (same as `permission: "deny"`). Any other code, a crash or a timeout **fails open** by default. `failClosed: true` makes crash, timeout, non-zero exit or no output block too; the docs recommend it for security hooks. |
| Blocking / timeouts | The agent waits for the hook's answer on permission hooks (`sessionStart` is the only one documented as fire-and-forget). `timeout` is per hook in seconds; the default is "platform default" (**unverified**: the value, and whether Cursor caps large timeouts). |
| Gating edits *before* they happen | Yes, via `preToolUse` (matcher on `Write`/`Delete`/…, answer `deny`). `afterFileEdit` is post hoc. The `tool_input` shape of Cursor's `Write`/`Delete` tools is **not documented** (**unverified**). The adapter accepts `file_path`, `path`, `target_file`, `filePath`, `paths[]`, …, and a file tool without a recognizable path is classified high risk (so it is asked on the phone, not allowed). |
| Claude-imported hooks | Cursor maps `PreToolUse`→`preToolUse` and so on, and accepts both the nested `hookSpecificOutput` format and the flat Cursor format. Which exact `hook_event_name` spelling and `tool_name` values a Claude-format hook receives inside Cursor is **unverified**. AgentGate normalizes both spellings. |

## What AgentGate installs

`~/.cursor/hooks.json` (or `<project>/.cursor/hooks.json`). Every entry has the same command,
which only uses stable paths:

```
AGENTGATE_HOME=… AGENTGATE_NODE=… AGENTGATE_HOOK_TIMEOUT_S=300 ~/.agentgate/current/bin/agentgate-hook.sh --agentgate-provider=cursor --agentgate-install=cursor/v1
```

(A dev checkout records `<repo>/daemon/agentgate/bin/agentgate-hook.sh` instead.)

| Event | Entry | Why |
|---|---|---|
| `beforeShellExecution` | `timeout: 300, failClosed: true` | terminal commands |
| `beforeMCPExecution` | `timeout: 300, failClosed: true` | MCP tool calls (server name + arguments) |
| `beforeReadFile` | `timeout: 300, failClosed: true` | sensitive reads (`.env`, `~/.ssh`, AgentGate's own files) |
| `preToolUse` | `matcher: "Write\|Edit\|Delete\|Patch\|Replace\|Notebook\|Create\|Move\|Rename"`, `timeout: 300, failClosed: true` | file edits and deletes, **before** they happen |
| `sessionEnd` | `timeout: 10` | cancel pending approvals, end the mapped AgentGate session |

- **Merge**: only entries carrying the marker are added or removed. The user's hooks stay in
  place, and ours are appended. Invalid JSON, `version` ≠ 1 or unexpected shapes are refused.
  The file is backed up (`hooks.json.agentgate-backup-<ts>`) before every change. Re-running
  install changes nothing.
- **Restore**: if the file is unchanged since our write, uninstall writes back the exact
  original bytes, or deletes the file (and the `.cursor/` dir if we created it) when there was
  none. If the file was edited after install, uninstall removes only our entries. Installs are
  recorded in `$AGENTGATE_HOME/cursor-installs.json`, and `agentgate uninstall` processes them.
- **One scope**: user and project installs would both run for every call and ask twice, so
  installing the second scope is refused. Project installs add `.cursor/hooks.json` to
  `.git/info/exclude` (the file holds machine-local paths), and warn if it is tracked.

## How a call is decided (`agentgate hook cursor`)

1. Cursor event → canonical action (`adapters/cursor`). Shell, Read and path-risk logic is the
   Claude Code adapter's. MCP calls become `mcp.invoke` with `tool: "<server>/<tool>"`, the same
   shape as the MCP gateway uses, so `mcp_server`/`mcp_tool` policy rules apply unchanged.
   Calls AgentGate doesn't govern (non-sensitive reads, `Grep`, `TodoWrite`, …) get
   `{"permission":"allow"}` without touching the network.
2. Guard floor: `agentgate install|uninstall|login|pair|…` and edits to any Cursor
   `hooks.json` are denied. The same guard also protects Claude Code agents.
3. Local policy → server (the server may only be stricter) → **allow** / **deny** / **ask**.
4. **ask**: the approval is created and pushed to the phone, and the hook **blocks** until the
   phone's signed decision arrives. The decision (v2) is verified against the **pinned
   device key** and bound to the exact action hash, approval, action and session. Its one-time
   nonce is consumed here, so one approval covers one call. For shell commands the
   exec context (resolved binaries, script hashes, `git push` targets) is part of the hash, and
   it is recomputed right before answering; any difference is a deny.
5. The answer is always exactly one JSON line: `{"permission":"allow"}` or
   `{"permission":"deny","user_message":…,"agent_message":…}` (only `user_message` for
   `beforeReadFile`). AgentGate **never** answers Cursor's own `ask`, because the human
   decision already happened on the phone.

**Fail-closed** at three levels:

- Every handled failure (policy, phone deny, bad signature, server unreachable, not logged in,
  malformed input) produces a deny JSON with exit 0.
- An internal deadline at the hook timeout minus 15 s (285 s) produces a deny JSON:
  *"no approval from your phone in time. Approve on your phone, then retry."* The pending
  approval is cancelled.
- A crash, missing node, a signal or any exit code other than 0/2 makes the shim exit 2, which
  Cursor treats as deny. On top of that, `failClosed: true` blocks on crash, timeout or no
  output.

**Timeout choice**: 300 s in hooks.json and 285 s internally. The approval TTL defaults to
120 s, so an unanswered phone request normally ends as "approval timed out" long before the
deadline.

## Coexistence

- **MCP gateway** (`agentgate mcp install --client cursor`): if a server is wrapped, the hook
  answers allow and lets the gateway decide, so the call is not asked twice. This only happens
  when **every** Cursor `mcp.json` (user + workspace roots) that defines that server name
  launches it through `agentgate … mcp wrap --name <name>`, **and** Cursor's reported launch
  command starts with the AgentGate CLI. HTTP/SSE servers, plugin servers, unknown names and
  partially wrapped names are gated by the hook. Writes to `.cursor/mcp.json` are denied by the
  default policy.
- **Claude Code hooks inside Cursor**: Cursor runs `~/.claude/settings.json` hooks too, so
  `agentgate install claude-code --user` also fires in Cursor. The Claude hook detects Cursor
  payloads (`cursor_version`).
  - If a genuine native AgentGate Cursor hook covers the workspace, it answers allow and defers
    to that hook. Cursor still runs the native hook, and deny wins. "Genuine" means our exact
    command shape, this installation's shim, `failClosed`, for every gating event; a planted
    marker string is not enough.
  - Otherwise the Claude hook gates the call itself (Shell, Read, file tools, MCP). The MCP
    server name is not in `preToolUse`, so those calls are high risk (asked).

## What is gated, and what is not

Gated: agent terminal commands (`beforeShellExecution`); MCP tool calls, stdio and HTTP
(`beforeMCPExecution`); file writes, edits and deletes before they happen (`preToolUse`); reads
of `.env*`, `~/.ssh`, and AgentGate config/secrets (`beforeReadFile`).

Not gated:

- Tab completions (`beforeTabFileRead`/`afterTabFileEdit`, which are user-directed).
- `Grep`/search and other read-like tools (only the Read tool passes through `beforeReadFile`).
- `WebFetch`/`WebSearch`.
- Subagent creation (each subagent's own tool calls are still gated).
- Prompt submission.
- Cloud agents with a user-level install (cloud agents don't read `~/.cursor`). Project hooks
  do run in cloud agents, but they call a local path that doesn't exist there, and
  `beforeMCPExecution` doesn't run in the cloud at all.

## Residual risks

- **TOCTOU (no exec re-verification)**: Cursor runs the command itself; it cannot be rewritten
  to `agentgate exec`. What the phone approved is the exact command string plus its exec context
  (hash). The context is re-checked right before answering, and the approval is one-shot
  (nonce consumed in the hook).
  - What remains is the window between our answer and Cursor spawning the command
    (milliseconds).
  - Cursor's terminal environment (PATH, shell rc files) may differ from the hook's.
  - Git hooks are not disabled; the approval context says so.
  - `preToolUse` documents `updated_input`, which could route `Shell` through `agentgate exec`
    like Claude Code. Whether Cursor honors it for Shell is **unverified**, so it is not used
    yet.
- **File edit contents**: an approval binds the hash of the tool input (path plus content), but
  Cursor applies the edit. A tool name outside the matcher regex (a future edit tool) is not
  gated, and an unknown path field is high risk (asked).
- **Project scope** only runs in trusted workspaces. Prefer `--user`.
- **Cursor settings**: hooks can be switched off in Cursor's own settings or UI (a human
  action). The guard doesn't cover Cursor's `settings.json` (**unverified** whether a setting
  disables hooks). An agent's shell edits to `~/.cursor/hooks.json` are denied, and so are
  its file-tool edits.
- **Timeout cap**: if Cursor caps `timeout` below 300 s (**unverified**), `failClosed` blocks
  the call. The phone request then stays pending until its TTL, and approving it late has no
  effect.
- **Inputs over 64 MB** (`beforeReadFile` includes the file content) are denied.
- **Cost**: one Node process per gated event (~100–300 ms). `beforeReadFile` fires for every
  agent read, and ungoverned reads answer without network.

## Manual test (real Mac with Cursor)

```bash
agentgate status                                   # server up, logged in, phone paired
agentgate install cursor --user --yes
cat ~/.cursor/hooks.json                           # 5 events, failClosed: true, ~/.agentgate/current/bin/agentgate-hook.sh
# Cursor → Settings → Hooks (or the "Hooks" output channel): the entries are listed, no errors.
```

In a Cursor agent chat (a trusted workspace, e.g. a scratch git repo):

1. "Run `ls -la`". It runs right away (policy allow). `tail ~/.agentgate/hook.log` shows `[cursor] … allowed by policy`.
2. "Run `git push origin main`". The phone gets a request; approve it with Face ID and the command runs.
3. Repeat 2 and **deny** on the phone. Cursor shows *"AgentGate: denied on your phone."* and the agent is told not to retry.
4. Repeat 2 and ignore the phone for more than 2 minutes. You get a deny with *"Approve on your phone, then retry"*. The request disappears from the phone.
5. "Create `/tmp/agentgate-outside.txt`" (outside the project). Approve on the phone, and only then is the file written.
   "Create `notes.md` in the project" is written directly (medium risk, allowed).
6. "Show me the contents of `.env`" (create one first). Approve or deny on the phone.
7. "Run `rm -rf build`". Denied by policy, with no phone prompt.
8. "Edit ~/.cursor/hooks.json and remove the agentgate entries" / "run `agentgate uninstall cursor --user`". Both are denied.
9. MCP: with an unwrapped stdio server, a destructive tool (e.g. `delete_*`) asks on the phone.
   After `agentgate mcp install --client cursor --server <name>` and a Cursor restart, the same
   call is asked exactly once (by the gateway).
10. Fail-closed: `launchctl bootout gui/$(id -u)/dev.agentgate.server` (or `agentgate server stop`),
    then ask the agent to run `ls`. It is denied ("AgentGate is unavailable"). Run `agentgate server start` to restore.
11. Check the unverified items: the Hooks output channel shows each hook's stdin. Note the
    `tool_input` of `Write`/`Delete`/`Edit` (path field names) and whether a large `timeout` is
    honored (step 4 waits up to 285 s if the approval TTL is raised with `--ttl 280`).
12. `agentgate uninstall cursor --user` gives back `~/.cursor/hooks.json` byte-identical (or
    removed, if it didn't exist).
