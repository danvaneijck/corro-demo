#!/usr/bin/env bash
# Removes the demo and checks nothing is left behind.
#
#   scripts/teardown.sh              # the CorroDemo stack
#   scripts/teardown.sh --bootstrap  # also the CDKToolkit stack and its (versioned) asset bucket
#
# Exits non-zero and prints what's left if anything tagged project=corro-demo remains.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh

bootstrap=0
[[ "${1:-}" == "--bootstrap" ]] && bootstrap=1

account=$(aws sts get-caller-identity --query Account --output text)
read -rp "Destroy $STACK in $AWS_REGION, account $account$([[ $bootstrap == 1 ]] && echo ', plus CDKToolkit')? [y/N] " answer
[[ "$answer" == y ]] || { echo "aborted"; exit 1; }

(cd infra && npx cdk destroy --all --force)

# A deleted secret is kept for 7-30 days and its name can't be reused meanwhile, which would
# block the next deploy. The demo secret has nothing worth recovering.
aws secretsmanager delete-secret --secret-id corro-demo/webhook-keys \
  --force-delete-without-recovery >/dev/null 2>&1 || true

empty_versioned_bucket() {
  local bucket=$1 kind objects
  for kind in Versions DeleteMarkers; do
    while :; do
      objects=$(aws s3api list-object-versions --bucket "$bucket" --max-items 1000 \
        --query "{Objects: $kind[].{Key: Key, VersionId: VersionId}}" --output json)
      [[ $(jq '.Objects | length' <<<"$objects") -gt 0 ]] || break
      aws s3api delete-objects --bucket "$bucket" --delete "$objects" >/dev/null
    done
  done
}

if [[ $bootstrap == 1 ]]; then
  bucket=$(aws cloudformation describe-stacks --stack-name CDKToolkit \
    --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue" --output text)
  echo "emptying $bucket"
  empty_versioned_bucket "$bucket"
  aws cloudformation delete-stack --stack-name CDKToolkit
  aws cloudformation wait stack-delete-complete --stack-name CDKToolkit
fi

echo "checking for leftovers"
left=$(aws resourcegroupstaggingapi get-resources --tag-filters Key=project,Values=corro-demo \
  --query 'ResourceTagMappingList[].ResourceARN' --output text)
logs=$(aws logs describe-log-groups --log-group-name-prefix /aws/lambda/CorroDemo \
  --query 'logGroups[].logGroupName' --output text)
if [[ -n "$left$logs" ]]; then
  echo "left behind (the tagging API can lag a few minutes behind deletes; re-run to confirm):"
  printf '  %s\n' $left $logs
  exit 1
fi
echo "nothing tagged project=corro-demo remains"
