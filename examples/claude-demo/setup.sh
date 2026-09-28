#!/usr/bin/env bash
# Creates the AgentGate × Claude Code demo repository.
#
#   <root>/demo                      working tree (branch main, one commit)
#   <root>/remotes/agentgate/demo.git  local bare "origin" → `git push origin main` works offline
#
# The origin path ends in agentgate/demo.git, so AgentGate reports the repo as "agentgate/demo".
# Usage: bash examples/claude-demo/setup.sh [root]   (default: ~/agentgate-demo; FORCE=1 to recreate)
set -euo pipefail

ROOT="${1:-${DEMO_ROOT:-$HOME/agentgate-demo}}"
WORK="$ROOT/demo"
ORIGIN="$ROOT/remotes/agentgate/demo.git"

if [ -e "$ROOT" ]; then
  if [ "${FORCE:-0}" = "1" ]; then rm -rf "$ROOT"; else
    echo "✖ $ROOT already exists (FORCE=1 to recreate)" >&2; exit 1
  fi
fi

mkdir -p "$(dirname "$ORIGIN")" "$WORK"
git init -q --bare -b main "$ORIGIN"

cd "$WORK"
git init -q -b main
git config user.name "AgentGate Demo"
git config user.email "demo@agentgate.local"
git remote add origin "$ORIGIN"

cat > README.md <<'MD'
# agentgate/demo

A tiny service used to demo AgentGate: every risky action Claude Code takes here
(pushes, secret files, destructive commands) needs a tap on your phone.
MD
mkdir -p src
cat > src/server.js <<'JS'
import { createServer } from "node:http";

const port = Number(process.env.PORT ?? 3000);
createServer((_req, res) => res.end("hello from agentgate/demo\n")).listen(port);
console.log(`listening on :${port}`);
JS
cat > CHANGELOG.md <<'MD'
# Changelog

## 0.1.0
- Initial release.
MD
printf 'node_modules/\n.env\n' > .gitignore
printf '{\n  "name": "agentgate-demo",\n  "version": "0.1.0",\n  "type": "module",\n  "scripts": { "start": "node src/server.js", "test": "node -e \\"process.exit(0)\\"" }\n}\n' > package.json

git add -A
git commit -q -m "Initial commit"
git push -q -u origin main

echo "✔ demo repo:   $WORK"
echo "✔ origin:      $ORIGIN  (bare, local)"
echo "  next: cd \"$WORK\" && <repo>/daemon/agentgate/bin/agentgate.sh run claude"
