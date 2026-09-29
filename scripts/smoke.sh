#!/usr/bin/env bash
# The demo without pauses, failing on the first wrong answer. Run it after every deploy.
set -euo pipefail
SMOKE=1 exec "$(dirname "$0")/demo.sh" "$@"
