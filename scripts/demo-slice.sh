#!/usr/bin/env bash
# Vertical slice: Fake CLI → API → (mobile, simulated with curl) → approve/deny → CLI resumes/blocks.
# Requires the API running on $SERVER. The "phone" here issues exactly the calls apps/mobile makes.
set -uo pipefail
export PATH="$HOME/.local/node/bin:$PATH"
cd "$(dirname "$0")/.."
SERVER="${SERVER:-http://localhost:8787}"
export AGENTGATE_HOME="${AGENTGATE_HOME:-$(mktemp -d)}"
WORK="$(mktemp -d)"
EMAIL="demo@agentgate.local"
j() { node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const o=JSON.parse(s);console.log(eval("o"+process.argv[1]))})' "$1"; }

npx agentgate login --server "$SERVER" --email "$EMAIL" >/dev/null || { echo "login failed"; exit 1; }
DEV_TOKEN=$(curl -s -XPOST "$SERVER/v1/auth/login" -H 'content-type: application/json' -d "{\"email\":\"$EMAIL\",\"client\":\"device\"}" | j .access_token)
DEVICE_ID=$(curl -s -XPOST "$SERVER/v1/devices" -H "authorization: Bearer $DEV_TOKEN" -H 'content-type: application/json' -d '{"name":"demo-phone","platform":"ios","push_token":null}' | j .id)

phone() { # phone <approve|deny>: wait for a pending approval, then decide
  for _ in $(seq 1 50); do
    ID=$(curl -s "$SERVER/v1/approvals?status=pending" -H "authorization: Bearer $DEV_TOKEN" | j '.items[0]?.approval.approval_id')
    if [ "$ID" != "undefined" ]; then
      sleep 1
      echo "📱 phone: $1 $ID"
      curl -s -o /dev/null -XPOST "$SERVER/v1/approvals/$ID/$1" -H "authorization: Bearer $DEV_TOKEN" -H 'content-type: application/json' -d "{\"device_id\":\"$DEVICE_ID\"}"
      return
    fi
    sleep 0.2
  done
  echo "📱 phone: no pending approval seen"
}

run_case() { # run_case <title> <phone-decision|-> <expect-file-exists yes|no> [env...]
  local title=$1 decision=$2 expect=$3; shift 3
  local target="$WORK/$(echo "$title" | tr ' ' _)"
  echo; echo "━━ $title"
  [ "$decision" != "-" ] && phone "$decision" &
  env "$@" npx agentgate request --env production -- "kubectl-sim delete deployment api-prod && touch $target" 2>&1 | sed 's/^/   cli │ /'
  local code=${PIPESTATUS[0]}; wait
  local got=no; [ -e "$target" ] && got=yes
  [ "$got" = "$expect" ] && echo "   ✅ executed=$got (exit $code)" || { echo "   ❌ executed=$got, expected $expect (exit $code)"; FAIL=1; }
}

FAIL=0
mkdir -p "$WORK/bin"; printf '#!/bin/sh\necho "kubectl-sim: $*"\n' > "$WORK/bin/kubectl-sim"; chmod +x "$WORK/bin/kubectl-sim"
export PATH="$WORK/bin:$PATH"
run_case "approve resumes execution" approve yes
run_case "deny blocks execution" deny no
run_case "modified after approval is rejected" approve no AGENTGATE_DEV=1 AGENTGATE_TAMPER_COMMAND="touch $WORK/tampered"
[ -e "$WORK/tampered" ] && { echo "   ❌ tampered command ran"; FAIL=1; }

echo; echo "━━ activity (audit log)"
curl -s "$SERVER/v1/activity?limit=14" -H "authorization: Bearer $DEV_TOKEN" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{for(const e of JSON.parse(s).items.reverse())console.log("   "+e.created_at.slice(11,19)+"  "+e.event.padEnd(20)+" "+e.summary)})'
exit $FAIL
