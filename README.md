# AgentGate

**One approval layer for every AI agent.** AgentGate sits between your coding agents
(Claude Code, Codex, MCP tools, …) and the real world. Risky actions such as `git push`,
deploys, deleting files or calling production APIs pause until you approve them on your
phone with Face ID. You can also watch, steer and stop agent sessions remotely.

This repository is everything that runs **on your computer**: the local server, the
`agentgate` CLI, the policy engine and the agent adapters. The iPhone/Android app is
distributed through the App Store and Google Play.

## How it works

```
 your computer                                            your phone
 ┌──────────────────────────────────────────┐
 │ Claude Code / Codex / MCP client         │
 │   └─ hook → agentgate policy engine ──┐  │   push    ┌────────────────────┐
 │                                        ├──┼─────────▶│ AgentGate app      │
 │ agentgate server (local, launchd)  ◀──┘  │◀─────────┤ approve · Face ID  │
 │   PGlite · audit log · session control   │  signed   └────────────────────┘
 └──────────────────────────────────────────┘  decision
```

- **Local-first.** The server runs on your own machine. There is no account and no cloud
  backend, and your code never leaves your computer.
- **Approvals are signed on the phone.** The phone holds an Ed25519 key in the Keychain
  behind Face ID. The executor on your computer verifies the phone's signature against a
  pinned key and re-checks the exact command hash before running it. A compromised server
  or network cannot forge an approval.
- **Fail-closed.** If AgentGate cannot decide, the action does not run.
- **Agent-agnostic.** A canonical action protocol with adapters for Claude Code (PreToolUse
  hooks), Cursor (agent hooks), Codex, generic hook-based agents and any MCP server (`agentgate mcp wrap`).

Design documents: [architecture](docs/architecture.md), [local-first trust model](docs/local-first.md),
[control center](docs/control-center.md).

## Install

macOS (Apple silicon or Intel). One line, no sudo, no Node.js/npm/git needed:

```bash
curl -fsSL https://github.com/emrgry/agentgate/releases/latest/download/install.sh | sh
```

The installer downloads the release for your Mac, verifies its SHA-256 checksum (and the
release signature when OpenSSL 3 is installed), installs it, and runs `agentgate setup`,
which starts the local server, offers to connect the agents it finds (Claude Code, Codex,
Cursor) and prints a QR code. Scan it with the AgentGate app to pair your phone. That's it.

To connect agents later, or non-interactively (`agentgate setup --connect all|none`):

```bash
agentgate install claude-code            # this project (or --user --yes for every session)
agentgate install cursor --user --yes    # Cursor's agent: terminal, file edits, MCP calls, sensitive reads
agentgate install codex --user --yes     # your normal Codex (terminal, codex exec, IDE): shell, apply_patch, MCP
agentgate mcp install --client cursor --all
```

**Cursor.** `agentgate install cursor --user --yes` adds fail-closed hooks to
`~/.cursor/hooks.json` (`--project DIR` for one trusted workspace). Cursor's agent then waits
for AgentGate before it runs a terminal command, edits or deletes a file, calls an MCP tool or
reads a secret. When a call needs approval, you approve it on your phone. MCP servers that are
already wrapped by `agentgate mcp install` are left to the gateway, so nothing is asked twice.
`agentgate uninstall cursor --user` restores the file. Details and residual risks:
[docs/cursor.md](docs/cursor.md).

**Codex.** `agentgate install codex --user --yes` adds a fail-closed PreToolUse hook to
`~/.codex/hooks.json` (`$CODEX_HOME` is honored; `--project DIR` for one project) and marks it
trusted in `~/.codex/config.toml`, because Codex silently skips untrusted hooks. Every shell
command, `apply_patch` edit and MCP call of your interactive Codex then goes through the
policy; when it needs approval, Codex waits until you approve or deny on your phone (up to
the approval TTL, then it's blocked and you approve when Codex retries). Restart running Codex
sessions afterwards; `agentgate status` shows whether the hook is trusted and when it last
ran. `agentgate uninstall codex --user` restores both files. Needs Codex ≥ 0.131. Details and
residual risks: [docs/control-center.md](docs/control-center.md#interactive-codex-agentgate-install-codex).

Options: `sh install.sh --dry-run` shows what it would do, `--no-setup` installs only,
`AGENTGATE_VERSION=0.2.0` pins a version. If `~/.local/bin` is not on your `PATH`, the
installer prints the line to add to `~/.zprofile`.

**Update**, **roll back**, **uninstall**:

```bash
agentgate update              # latest signed release; restarts the server only when no agent session runs
agentgate update --check      # just tell me
agentgate update --rollback   # back to the previous version (kept on disk)
agentgate version             # version, install type and path
agentgate uninstall           # removes hooks, MCP wraps, the launchd agent and the program files
agentgate uninstall --purge   # …and also your pairing, config and server data
```

`agentgate update` only installs releases whose `SHA256SUMS` carries a valid Ed25519
signature by the release key built into the CLI; anything else is refused. The first
install trusts GitHub's TLS (plus the checksum, and the signature if OpenSSL 3 is present).

**What goes where** (all inside your home directory):

| Path | What |
|---|---|
| `~/.agentgate/versions/<version>/` | the program: `bin/agentgate`, `bin/agentgate-hook.sh`, `libexec/node` (bundled Node.js), `lib/` |
| `~/.agentgate/current` | symlink to the active version; hooks, MCP wraps and launchd reference this path, so updates never break them |
| `~/.agentgate/previous` | the version `update --rollback` returns to (at most 2 old versions are kept) |
| `~/.local/bin/agentgate` | small shim that runs `~/.agentgate/current/bin/agentgate` |
| `~/.agentgate/config.json`, `~/.agentgate/server/` | your pairing, tokens, local server data (PGlite) and identity key; kept by `uninstall` unless `--purge` |
| `~/Library/LaunchAgents/dev.agentgate.server.plist` | the launchd agent that keeps the local server running |

Agents cannot run `agentgate update`, `uninstall`, `setup` or `restart`, and cannot modify
`~/.agentgate` (the hook guard blocks it).

Linux: release tarballs are published for `linux-x64` and `linux-arm64`, but the installer
and `agentgate setup` (launchd) are macOS-only for now; run `agentgate serve` under your own
service manager, or build from source.

### From source

Node.js ≥ 22:

```bash
git clone https://github.com/emrgry/agentgate && cd agentgate
npm ci
./daemon/agentgate/bin/agentgate.sh setup      # starts the local server, prints a QR code
./daemon/agentgate/bin/agentgate.sh install claude-code
```

## Development

```bash
npm run typecheck
npx vitest run                 # all workspaces
npm test -w @agentgate/api     # API integration tests
npm run build:release          # dist/release: self-contained tarballs (see docs/releasing.md)
npm run test:release-e2e       # macOS: build, install into a temp HOME, update, uninstall
```

| Path | What |
|---|---|
| `packages/protocol` | Zod contracts shared with the mobile app |
| `packages/signing` | Ed25519 signing and verification (pure JS, also used by the app) |
| `packages/core` | Canonical actions, hashing, approval tokens |
| `packages/policy-engine` | Allowlist-based risk policy |
| `apps/api` | Local server (Fastify, Drizzle, PGlite, WebSocket, push) |
| `daemon/agentgate` | `agentgate` CLI, hooks, `exec` re-verification, MCP gateway, session supervisor |
| `adapters/*` | Claude Code, Codex and generic agent adapters |

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[Functional Source License 1.1, ALv2 Future License](LICENSE.md) (FSL-1.1-ALv2). You can
read, run, modify and use AgentGate, including inside your company. You may not offer it
as a competing commercial product. Each release becomes Apache-2.0 two years after it is
published.

"AgentGate" and the AgentGate logo are trademarks and are not licensed under the FSL.
