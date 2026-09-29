#!/usr/bin/env bash
# Narrated walkthrough of the demo against the deployed stack. Each step prints the request,
# runs it and shows the interesting part of the response. With SMOKE=1 it doesn't pause and
# fails on the first wrong answer (that's scripts/smoke.sh).
#
#   DEMO_PASSWORD=... scripts/demo.sh            # press enter between steps
#   DEMO_PASSWORD=... SMOKE=1 scripts/demo.sh | tee demo-transcript.txt   # no pauses
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
: "${DEMO_PASSWORD:?set DEMO_PASSWORD}"
SMOKE="${SMOKE:-0}"

bold=$'\033[1m'; dim=$'\033[2m'; green=$'\033[32m'; red=$'\033[31m'; reset=$'\033[0m'
[[ -t 1 ]] || { bold=; dim=; green=; red=; reset=; }

n=0
step() { n=$((n + 1)); printf '\n%s%2d. %s%s\n' "$bold" "$n" "$1" "$reset"; }
say() { printf '    %s%s%s\n' "$dim" "$1" "$reset"; }
pause() { [[ "$SMOKE" == 1 ]] || read -rp "    ${dim}(enter)${reset}" _ </dev/tty || true; }
fail() { printf '%sFAIL (step %d): %s%s\n' "$red" "$n" "$1" "$reset" >&2; exit 1; }
ok() { printf '    %s✔ %s%s\n' "$green" "$1" "$reset"; }

# api <user> <METHOD> <path> [curl args...]  → sets STATUS and BODY
api() {
  local user=$1 method=$2 path=$3 out; shift 3
  printf '    $ %s  %s %s\n' "$user" "$method" "$path"
  out=$(curl -sS -w '\n%{http_code}' -X "$method" "$API$path" -H "Authorization: Bearer ${TOKENS[$user]}" "$@")
  STATUS=${out##*$'\n'}; BODY=${out%$'\n'*}
}
show() { jq -r "${1:-.}" <<<"$BODY" | sed 's/^/      /'; printf '      %s→ HTTP %s%s\n' "$dim" "$STATUS" "$reset"; }
expect_status() { [[ "$STATUS" == "$1" ]] || fail "expected HTTP $1, got $STATUS: $BODY"; }
check() { jq -e "$1" <<<"$BODY" >/dev/null || fail "$2 ($1)"; ok "$2"; }

webhook() { # webhook <channel> <file>  → sets BODY
  printf '    $ webhook  POST /inbound/%s  (signed like the provider would)\n' "$1"
  BODY=$(API_URL="$API" scripts/sign-webhook.sh "$1" "$2" | sed 's/  \[[0-9]*\]$//')
  STATUS=200
}

load_outputs
declare -A TOKENS
for u in alice bob dave ops; do TOKENS[$u]=$(token_for "$u"); done
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
started_at=$(date -u +%Y-%m-%dT%H:%M:%S)
audit_day=$(date -u +%Y-%m-%d)   # audit partitions are per UTC day
printf '%sUnified Inbox demo%s  %s\n' "$bold" "$reset" "$API"
say "Signed in as alice (acme admin), bob (acme member), dave (globex admin) and ops (platform operator)."

step "alice lists her conversations"
api alice GET /conversations
show '.items[] | "\(.name)  (\(.conversation_id))  last: \(.last_message_at // "-")"'
expect_status 200; check '.items | length == 3' "3 conversations, most recent first"
pause

step "alice pages through #ops, 5 messages at a time"
api alice GET "/conversations/c_ops/messages?limit=5"
show '.items[] | "\(.sent_at[11:16])  \(.body_text)"'
expect_status 200
cursor=$(jq -r .next_cursor <<<"$BODY"); first=$(jq -r '.items[0].message_id' <<<"$BODY")
say "next_cursor = ${cursor:0:40}…  (opaque, bound to this conversation)"
api alice GET "/conversations/c_ops/messages?limit=5&cursor=$cursor"
show '.items[] | "\(.sent_at[11:16])  \(.body_text)"'
check ".items[0].message_id != \"$first\"" "page 2 continues where page 1 ended"
pause

step "A Slack message arrives (Events API JSON, HMAC-signed)"
event_id="Ev$(date +%s%N | tail -c 11)"
jq -cn --arg id "$event_id" --arg ts "$(date +%s).000100" \
  '{type: "event_callback", team_id: "T0ACME", event_id: $id, event: {type: "message", channel: "C0OPS",
    user: "U024BE7LH", text: "Region B dashboards all green after the fix.", ts: $ts}}' > "$work/slack.json"
webhook slack "$work/slack.json"; show
check '.outcome == "appended"' "stored"
api alice GET "/conversations/c_ops/messages?limit=1"
show '.items[] | "\(.channel): \(.body_text)  (sender: \(.sender.kind) \(.sender.user_id // .sender.address))"'
check '.items[0].channel == "slack" and .items[0].sender.kind == "user"' "routed to #ops and linked to bob's Slack identity"
latest=$(jq -r '.items[0].message_id' <<<"$BODY")
pause

step "Slack retries the same event"
webhook slack "$work/slack.json"; show
check '.outcome == "duplicate"' "recognised as a duplicate"
api alice GET "/conversations/c_ops/messages?limit=1"
check ".items[0].message_id == \"$latest\"" "no second copy was stored"
pause

step "An SMS arrives (Twilio-style form post, a different wire format)"
printf 'To=%%2B61400000001&From=%%2B61400000555&Body=Thanks+for+the+update+on+the+outage&MessageSid=SM%s' \
  "$(date +%s%N)" > "$work/sms.txt"
webhook sms "$work/sms.txt"; show
check '.outcome == "appended"' "stored"
api alice GET "/conversations/c_sms/messages?limit=1"
show '.items[] | "\(.channel) from \(.sender.address): \(.body_text)"'
check '.items[0].channel == "sms"' "same canonical message shape as Slack"
pause

step "People alice shares conversations with (a two-hop graph query)"
api alice GET /people
show '.items[] | "\(.display_name)  shared: \(.shared)"'
check '[.items[] | .shared] == [2, 1]' "Bob ×2, Carol ×1"
pause

step "alice searches her conversations for \"outage\""
api alice GET "/search?q=outage"
show '.items[] | "\(.conversation_id)  \(.body_text)"'
check '.items | length > 0 and all(.conversation_id | startswith("c_"))' "hits only from alice's conversations"
check '[.items[] | select(.conversation_id == "c_ward")] | length == 0' "nothing from globex, which also talks about an outage"
pause

step "alice asks for a globex conversation by id"
api alice GET /conversations/c_ward/messages
show
expect_status 404; ok "404, the same answer as for a conversation that doesn't exist"
pause

step "The isolation probe: alice's tenant credentials read globex directly, skipping app checks"
api alice GET "/debug/probe?tenant=globex"
show
check '.blocked_by == "iam" and .error == "AccessDeniedException"' "DynamoDB refused: IAM, not our code, is the boundary"
pause

step "dave (globex) sees none of acme's data"
api dave GET /conversations
show '.items[] | "\(.name)  (\(.conversation_id))"'
check '[.items[].conversation_id] == ["c_ward"]' "only globex conversations"
api dave GET "/search?q=outage"
show '.items[] | "\(.conversation_id)  \(.body_text)"'
check 'all(.items[]; .conversation_id == "c_ward")' "only globex messages"
pause

step "alice (admin) reads the audit trail for this run"
api alice GET "/audit?limit=100&date=$audit_day"
say "(only records from this terminal run: an open web client adds its own polling records)"
BODY=$(jq --arg since "$started_at" '.items |= map(select(.ts >= $since and ((.actor.user_agent // "") | startswith("curl"))))' <<<"$BODY")
show '.items[:14][] | "\(.ts[11:19])  \(.actor.username // .actor.type)  \(.action)  \(.outcome)\(if .reason then "  (" + .reason + ")" else "" end)"'
check 'any(.items[]; .outcome == "denied_by_iam")' "the probe is recorded as denied_by_iam"
check 'any(.items[]; .outcome == "duplicate")' "the Slack retry is recorded"
check 'any(.items[]; .outcome == "denied" and .reason == "not_member")' "the 404 is recorded as a denial"
pause

step "bob (member) tries to read the audit trail"
api bob GET /audit
show
expect_status 403; ok "403"
api alice GET "/audit?limit=50&date=$audit_day"
BODY=$(jq '.items |= [first(.[] | select(.actor.username == "bob@acme.test" and .action == "audit.read"))]' <<<"$BODY")
show '.items[] | "\(.ts[11:19])  \(.actor.username)  \(.action)  \(.outcome)  (\(.reason))"'
check '.items[0].outcome == "denied" and .items[0].reason == "requires_admin"' "and the attempt itself is audited"
pause

step "The one cross-tenant view: a platform operator sees counts, never content"
api ops GET "/platform/stats?days=1"
show '.days[] | .date as $d | .tenants[] | "\($d)  \(.tenant_id)  total \(.total)  \(.messages)"'
check '[.days[0].tenants[].tenant_id] | (index("acme") != null and index("globex") != null)' "counts for both tenants"
check '[.. | objects | keys[]] | all(. != "body_text" and . != "sender")' "no message content anywhere in the response"
api alice GET /platform/stats
expect_status 403; ok "a tenant admin isn't a platform operator: 403, audited"

printf '\n%sDone.%s\n' "$bold" "$reset"
