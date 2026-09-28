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
  hooks), Codex, generic hook-based agents and any MCP server (`agentgate mcp wrap`).

Design documents: [architecture](docs/architecture.md), [local-first trust model](docs/local-first.md),
[control center](docs/control-center.md).

## Install

A one-line installer and Homebrew formula are coming soon. For now, build from source
(Node.js ≥ 22, macOS):

```bash
git clone https://github.com/emrgry/agentgate && cd agentgate
npm ci
./daemon/agentgate/bin/agentgate.sh setup      # starts the local server, prints a QR code
./daemon/agentgate/bin/agentgate.sh install claude-code
```

Scan the QR code with the AgentGate app to pair your phone.

## Development

```bash
npm run typecheck
npx vitest run                 # all workspaces
npm test -w @agentgate/api     # API integration tests
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
