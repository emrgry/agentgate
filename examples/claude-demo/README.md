# AgentGate × Claude Code — demo

Claude Code works in a real repo. Harmless actions just happen. `git push` stops and waits
for your phone. Deny, and Claude is told why. Change an approved command after approval,
and it is refused where it executes.

## One-time setup

```bash
# 1. API (from the repo root)
npm run dev:api                                  # http://localhost:8787

# 2. Phone: open the AgentGate app, log in as the same email you use below.

# 3. CLI
alias agentgate="'$PWD/daemon/agentgate/bin/agentgate.sh'"   # works from any directory
agentgate login --server http://localhost:8787 --email you@example.com
agentgate status                                 # server ok, key pinned, websocket ok

# 4. Demo repo: ~/agentgate-demo/demo with a local bare origin (push works offline)
bash examples/claude-demo/setup.sh               # FORCE=1 to recreate
```

The repo's origin is `~/agentgate-demo/remotes/agentgate/demo.git`, so AgentGate shows it
as **agentgate/demo** on the phone.

## The demo script

```bash
cd ~/agentgate-demo/demo
agentgate run claude
```

`run` starts an AgentGate session and launches Claude Code with a PreToolUse hook
(`claude --settings <tmp>`). Your own Claude settings are untouched. Then ask Claude:

1. **"Add a 0.2.0 entry to CHANGELOG.md and commit it."**
   The edit and `git commit` are low/medium risk and allowed by policy, so no phone prompt.
2. **"Push it to origin main."**
   Policy rule `ask-git-push` applies. Your phone buzzes with *git push origin main ·
   agentgate/demo · main*. Hold to approve. Claude's Bash call is rewritten to
   `agentgate.sh exec --approval apr_… -- 'git push origin main'`, which re-verifies the
   signed approval against the exact command and pushes.
   Check it: `git --git-dir ../remotes/agentgate/demo.git log --oneline -1`.
3. **"Push again with --force."** Deny on the phone. Claude receives *"AgentGate blocked this
   action: denied on device"* and reports it.
4. **"Put API_KEY=123 in .env."** A Write to `.env` is flagged high risk by the adapter, so it
   asks. Only the path and a hash of the content leave your machine.
5. **"Clean up with rm -rf build."** Denied instantly by policy. No phone prompt.
6. **Modified after approval** (security demo): quit Claude and relaunch with
   ```bash
   AGENTGATE_DEV=1 AGENTGATE_TAMPER_COMMAND="git push --force origin main" agentgate run claude
   ```
   Ask for a push and approve it. At the execution boundary the command is swapped, and
   `agentgate exec` refuses it with `hash_mismatch` (exit 77). The origin is unchanged.
7. Open **Activity** on the phone for the full audit trail: requested, approved or denied,
   execution started/completed/blocked, session ended.

Quitting Claude ends the session. Any approval still pending on the phone is cancelled.

## Gating the desktop app / IDE (no `agentgate run`)

```bash
cd ~/agentgate-demo/demo && agentgate install claude-code   # writes .claude/settings.local.json
# now open ~/agentgate-demo/demo in the Claude desktop app or an IDE: same gating, same phone
agentgate uninstall claude-code                             # restores the previous settings
```

## Without Claude Code (rehearsal)

`fake-claude.mjs` does what Claude Code does with the generated settings. It pipes a
PreToolUse Bash event into the hook, then runs the (possibly rewritten) command:

```bash
cd ~/agentgate-demo/demo
AGENTGATE_CLAUDE_BIN="<repo>/examples/claude-demo/fake-claude.mjs" agentgate run claude -- "git push origin main"
```

Hook diagnostics go to `~/.agentgate/hook.log`.
