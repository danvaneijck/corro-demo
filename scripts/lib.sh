# Shared helpers for the demo scripts. Source it; don't run it.
# Needs: aws CLI (your profile), jq, curl. DEMO_PASSWORD for sign-ins.

STACK="${STACK:-CorroDemo}"
export AWS_REGION="${AWS_REGION:-ap-southeast-2}"

stack_output() {
  aws cloudformation describe-stacks --stack-name "$STACK" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text
}

# Sets API, CLIENT_ID and SECRET_ARN from the stack outputs (one call).
load_outputs() {
  local outputs
  outputs=$(aws cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs" --output json)
  API=$(jq -r '.[] | select(.OutputKey=="ApiUrl") | .OutputValue' <<<"$outputs")
  API="${API%/}"
  CLIENT_ID=$(jq -r '.[] | select(.OutputKey=="UserPoolClientId") | .OutputValue' <<<"$outputs")
  SECRET_ARN=$(jq -r '.[] | select(.OutputKey=="WebhookSecretArn") | .OutputValue' <<<"$outputs")
  export API CLIENT_ID SECRET_ARN
}

# alice | bob | carol | dave | any seeded email
email_for() {
  case "$1" in
    alice|bob|carol) echo "$1@acme.test" ;;
    dave) echo "dave@globex.test" ;;
    ops) echo "ops@corro.test" ;;
    *) echo "$1" ;;
  esac
}

# Prints an ID token. The password goes to the CLI in a private temp file, not on the command
# line (where other processes could see it).
token_for() {
  : "${DEMO_PASSWORD:?set DEMO_PASSWORD}"
  local req rc=0
  req=$(mktemp) && chmod 600 "$req"
  jq -n --arg c "$CLIENT_ID" --arg u "$(email_for "$1")" --arg p "$DEMO_PASSWORD" \
    '{AuthFlow: "USER_PASSWORD_AUTH", ClientId: $c, AuthParameters: {USERNAME: $u, PASSWORD: $p}}' > "$req"
  aws cognito-idp initiate-auth --cli-input-json "file://$req" \
    --query AuthenticationResult.IdToken --output text || rc=$?
  rm -f "$req"
  return "$rc"
}
