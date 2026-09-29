#!/usr/bin/env bash
# Signs a webhook payload the way the provider would, and POSTs it to the deployed API.
#
#   scripts/sign-webhook.sh slack fixtures/slack_message.json
#   echo 'To=...&From=...&Body=hi&MessageSid=SM1' | scripts/sign-webhook.sh sms -
#
# Needs AWS credentials that can read the webhook secret (your profile), plus jq and openssl.
set -euo pipefail

usage="usage: sign-webhook.sh <slack|sms> <payload-file|->"
channel="${1:?$usage}"
file="${2:?$usage}"
stack="${STACK:-CorroDemo}"

output() {
  aws cloudformation describe-stacks --stack-name "$stack" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text
}

case "$channel" in
  slack) ts_header=X-Slack-Request-Timestamp; sig_header=X-Slack-Signature; ctype=application/json ;;
  sms)   ts_header=X-Webhook-Timestamp;       sig_header=X-Webhook-Signature; ctype=application/x-www-form-urlencoded ;;
  *) echo "unknown channel: $channel" >&2; exit 2 ;;
esac

if [[ "$file" == "-" ]]; then
  tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
  cat > "$tmp"; file="$tmp"
fi

api="${API_URL:-$(output ApiUrl)}"
root=$(aws secretsmanager get-secret-value --secret-id "$(output WebhookSecretArn)" \
  --query SecretString --output text | jq -r .root)

# Per-channel key = HMAC-SHA256(root, "webhook/<channel>"), as in adapters::channel_key.
key_hex=$(printf 'webhook/%s' "$channel" | openssl dgst -sha256 -hmac "$root" -hex | awk '{print $NF}')
ts=$(date +%s)
sig="v0=$({ printf 'v0:%s:' "$ts"; cat "$file"; } \
  | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$key_hex" -hex | awk '{print $NF}')"

curl -sS -w '  [%{http_code}]\n' -X POST "${api%/}/inbound/$channel" \
  -H "Content-Type: $ctype" -H "$ts_header: $ts" -H "$sig_header: $sig" \
  --data-binary "@$file"
