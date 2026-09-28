#!/bin/bash
# POSIX entry point for agentgate (used in rewritten Claude Code Bash commands:
# `agentgate.sh exec --approval apr_… -- '<cmd>'`). Locates node without relying on the
# caller's PATH. If it cannot start, the wrapped command never runs (exit 77).
set -u
# Never let the caller's environment inject code into AgentGate's own node process.
unset NODE_OPTIONS NODE_PATH NODE_REPL_EXTERNAL_MODULE BASH_ENV ENV
for __v in $(env | sed -nE 's/^((DYLD|LD)_[A-Za-z0-9_]*)=.*/\1/p'); do unset "$__v"; done
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || { echo "agentgate: cannot locate installation" >&2; exit 77; }
NODE="${AGENTGATE_NODE:-}"
if [ -z "$NODE" ] || [ ! -x "$NODE" ]; then
  NODE="$(command -v node 2>/dev/null || true)"
fi
if [ -z "$NODE" ]; then
  for cand in "$HOME/.local/node/bin/node" /opt/homebrew/bin/node /usr/local/bin/node; do
    [ -x "$cand" ] && { NODE="$cand"; break; }
  done
fi
[ -n "$NODE" ] && [ -x "$NODE" ] || { echo "agentgate: node runtime not found — command not executed" >&2; exit 77; }
exec "$NODE" "$DIR/agentgate.mjs" "$@"
