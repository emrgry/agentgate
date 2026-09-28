#!/bin/bash
# AgentGate Claude Code PreToolUse hook entry point — FAIL-CLOSED BY CONSTRUCTION.
#
# Claude Code treats exit 2 as "block" and ANY other non-zero exit / crash / timeout as
# fail-open. So this shim guarantees: exit 0 only if the node hook exited 0 (and then
# stdout carries its decision JSON); everything else — node missing, tsx failing to load,
# a crash, a signal, any unexpected code — becomes exit 2 with a reason on stderr.
set -u
# Never let the caller's environment inject code into AgentGate's own node process.
unset NODE_OPTIONS NODE_PATH NODE_REPL_EXTERNAL_MODULE BASH_ENV ENV
for __v in $(env | sed -nE 's/^((DYLD|LD)_[A-Za-z0-9_]*)=.*/\1/p'); do unset "$__v"; done

block() {
  printf 'AgentGate blocked this action: %s\n' "$1" >&2
  exit 2
}
trap 'block "hook interrupted"' INT TERM HUP

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || block "cannot locate the agentgate installation"
ENTRY="$DIR/agentgate.mjs"
[ -f "$ENTRY" ] || block "agentgate entry point missing ($ENTRY)"

NODE="${AGENTGATE_NODE:-}"
[ -n "$NODE" ] || NODE="$(command -v node 2>/dev/null || true)"
if [ -z "$NODE" ] || [ ! -x "$NODE" ]; then
  for __a in "$@"; do [ "$__a" = "--agentgate-observe" ] && exit 0; done
  block "node runtime not found (set AGENTGATE_NODE or put node on PATH)"
fi

# Observe-only events (SessionStart/UserPromptSubmit/Notification/Stop): reporting must
# never influence Claude — exit 0 and no stdout, whatever happens.
for __a in "$@"; do
  if [ "$__a" = "--agentgate-observe" ]; then
    "$NODE" "$ENTRY" hook claude-code >/dev/null 2>&1
    exit 0
  fi
done

# Control Center turns of other providers: `--agentgate-provider=<id>` selects the hook
# (same 0/2 contract). The id is validated; anything odd blocks.
AGENT="claude-code"
for __a in "$@"; do
  case "$__a" in
    --agentgate-provider=*)
      AGENT="${__a#--agentgate-provider=}"
      case "$AGENT" in
        ""|*[!a-z0-9_-]*) block "invalid provider id" ;;
      esac
      ;;
  esac
done

"$NODE" "$ENTRY" hook "$AGENT"
rc=$?
[ "$rc" -eq 0 ] && exit 0
[ "$rc" -eq 2 ] && exit 2
block "hook exited abnormally (code $rc)"
