#!/usr/bin/env bash
# Signs in as a seeded user and prints `export` lines for TOKEN and API.
#
#   eval "$(scripts/login.sh alice)"
#   curl -H "Authorization: Bearer $TOKEN" "$API/me"
set -euo pipefail
source "$(dirname "$0")/lib.sh"
user="${1:?usage: login.sh <alice|bob|carol|dave|ops|email>}"
load_outputs
printf 'export API=%q\nexport TOKEN=%q\n' "$API" "$(token_for "$user")"
