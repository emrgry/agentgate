# AgentGate MCP gateway demo

`server.mjs` is a tiny zero-dependency stdio MCP server ("mail") with four tools:

| Tool | Annotations | AgentGate (built-in policy) |
|---|---|---|
| `list_inbox` | `readOnlyHint: true` | allowed, runs immediately |
| `send_email {to, subject, body}` | `destructiveHint: false, openWorldHint: true` | **ask**: interacts with the outside world |
| `delete_all_emails` | `destructiveHint: true` | **ask** |
| `transfer_funds {amount, to}` | `destructiveHint: true` | **ask** |

Every call that actually reaches the server appends a line to `$MCP_DEMO_LOG`, so you can
prove that a blocked call never ran.

## Try it with Claude Code without touching any global config

```bash
# once: API running, `agentgate login`, phone paired (`agentgate pair`)
REPO="$(git rev-parse --show-toplevel)"      # the AgentGate repo
sed "s#/ABSOLUTE/PATH/TO/AgentGate#$REPO#g" examples/mcp-demo/mcp-config.sample.json > /tmp/agentgate-mcp.json

claude -p --mcp-config /tmp/agentgate-mcp.json --allowedTools "mcp__mail" \
  "Check my inbox, then delete all emails."
tail -f /tmp/agentgate-mcp-demo.log          # list_inbox appears at once; delete_all_emails only after you approve
```

- `list_inbox` runs immediately.
- `delete_all_emails` makes your phone ask: *claude-code · mail → delete_all_emails*.
  Approve, and the gateway forwards the exact request. Deny, and Claude gets
  `Blocked by AgentGate: denied on device`, and nothing is written to the log.

The same config works for Claude Desktop, Cursor and Codex. The easy way is
`agentgate mcp install --client <claude-desktop|cursor|claude-code|codex> --server mail`,
which rewrites an existing server entry into exactly this form (and `agentgate mcp uninstall`
restores it). Restart the client afterwards.

## What the gateway does

`agentgate mcp wrap --name mail -- node server.mjs` sits between the client and the server
and relays every JSON-RPC message untouched, except `tools/call`:

1. It builds a canonical action (`mcp.invoke`, tool `mail/<tool>`, the arguments, and the
   tool's annotations from `tools/list`) and evaluates policy.
2. `allow` → forward. `ask` → phone approval; the signed token is verified and the nonce
   consumed, then the exact request is forwarded. `deny`, denied, expired, API unreachable
   or any gateway error → the client gets `{isError: true, content: "Blocked by AgentGate: …"}`
   and the server never sees the call.
3. The result (`isError` / JSON-RPC error → failed) is reported to the audit log.

While waiting, it sends `notifications/progress` every 5 s when the client supplied a
`progressToken`. `notifications/cancelled` cancels the pending approval.
