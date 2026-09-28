#!/bin/sh
# AgentGate Claude Code PreToolUse hook entry point (release build) — FAIL-CLOSED BY
# CONSTRUCTION.
#
# Claude Code treats exit 2 as "block" and ANY other non-zero exit / crash / timeout as
# fail-open. So this shim guarantees: exit 0 only if the node hook exited 0 (and then
# stdout carries its decision JSON); everything else (runtime missing, a crash, a signal,
# any unexpected code) becomes exit 2 with a reason on stderr.
#
# The release always uses its bundled runtime (<root>/libexec/node); AGENTGATE_NODE is
# ignored here (it is still written into hook commands for health checks).
set -u
# Never let the caller's environment inject code into AgentGate's own node process.
unset NODE_OPTIONS NODE_PATH NODE_REPL_EXTERNAL_MODULE NODE_ENV BASH_ENV ENV CDPATH
for __v in $(/usr/bin/env | /usr/bin/sed -nE 's/^((DYLD|LD)_[A-Za-z0-9_]*)=.*/\1/p'); do unset "$__v"; done

block() {
  printf 'AgentGate blocked this action: %s\n' "$1" >&2
  exit 2
}
trap 'block "hook interrupted"' INT TERM HUP

OBSERVE=0
AGENT="claude-code"
for __a in "$@"; do
  case "$__a" in
    --agentgate-observe) OBSERVE=1 ;;
    # Control Center turns of other providers: `--agentgate-provider=<id>` selects the hook
    # (same 0/2 contract). The id is validated; anything odd blocks.
    --agentgate-provider=*)
      AGENT="${__a#--agentgate-provider=}"
      case "$AGENT" in
        "" | *[!a-z0-9_-]*) block "invalid provider id" ;;
      esac
      ;;
  esac
done

__self=$0
while [ -L "$__self" ]; do
  __link=$(/usr/bin/readlink "$__self") || block "cannot resolve the agentgate installation"
  case $__link in
    /*) __self=$__link ;;
    *) __self=$(/usr/bin/dirname "$__self")/$__link ;;
  esac
done
ROOT=$(cd "$(/usr/bin/dirname "$__self")/.." 2>/dev/null && pwd -P) || block "cannot locate the agentgate installation"
NODE="$ROOT/libexec/node"
ENTRY="$ROOT/lib/agentgate.mjs"

# Observe-only events (SessionStart/UserPromptSubmit/Notification/Stop): reporting must
# never influence Claude — exit 0 and no stdout, whatever happens.
if [ "$OBSERVE" = 1 ]; then
  [ -x "$NODE" ] && [ -f "$ENTRY" ] && "$NODE" "$ENTRY" hook claude-code >/dev/null 2>&1
  exit 0
fi

[ -f "$ENTRY" ] || block "agentgate entry point missing ($ENTRY)"
[ -x "$NODE" ] || block "bundled node runtime missing ($NODE)"

"$NODE" "$ENTRY" hook "$AGENT"
rc=$?
[ "$rc" -eq 0 ] && exit 0
[ "$rc" -eq 2 ] && exit 2
block "hook exited abnormally (code $rc)"
