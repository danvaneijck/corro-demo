#!/usr/bin/env bash
# Wipes the inbox table (messages, de-duplication records, everything) and re-seeds it.
# Cognito users are upserted with DEMO_PASSWORD. The audit table is append-only and untouched.
set -euo pipefail
: "${DEMO_PASSWORD:?set DEMO_PASSWORD}"
cd "$(dirname "$0")/../services"
cargo run -q -p seed --release
