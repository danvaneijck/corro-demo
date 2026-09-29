# Unified Inbox demo

A small multi-tenant messaging backend on AWS: Rust on Lambda, API Gateway HTTP API, DynamoDB
single-table design, Cognito and CDK (TypeScript). Messages arrive from different channels (Slack-
and SMS-shaped webhooks), are translated into one canonical format, routed to a tenant's
conversations, and read back through a JWT-protected API and a small web page.

The point of the demo is tenant isolation that holds even if the application code gets it wrong.
Every request runs with STS credentials tagged with the caller's `tenant_id`, and IAM only lets
those credentials touch DynamoDB keys under `T#<tenant>#`. Every action, including denials, goes to
an append-only audit table.

> This is a time-boxed interview demo, not production code.

**Status:** work in progress.

## Layout

```
services/   Rust workspace: domain, store, adapters, search crates; api, ingest, seed binaries
infra/      CDK app (stack `CorroDemo`)
scripts/    login, demo, smoke, reset, teardown, webhook signing
```

## Prerequisites

- Rust stable (pinned by `rust-toolchain.toml`) with the `aarch64-unknown-linux-gnu` target
- [cargo-lambda](https://www.cargo-lambda.info/) and Zig (for the arm64 cross-compile)
- Node.js 24, Docker (DynamoDB Local for the repository tests)
- An AWS account bootstrapped for CDK in `ap-southeast-2`

## Build and test

```bash
cd services
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Deploy

The alarm email and demo password come from your shell and are never committed.

```bash
export AWS_PROFILE=<your-profile> AWS_REGION=ap-southeast-2
export ALARM_EMAIL=<you@example.com>
cd infra && npm ci
npx cdk deploy CorroDemo -c alarmEmail="$ALARM_EMAIL"
```

AWS sends a confirmation email for the alarm topic. Confirm it, or alarms go nowhere.

## Tear down

```bash
./scripts/teardown.sh   # cdk destroy, then checks nothing tagged project=corro-demo is left
```

## CI

GitHub Actions runs fmt, clippy, tests, `cargo deny`, gitleaks and `cdk synth` on every push and
pull request, with no AWS credentials. Locally, `pre-commit install` adds the same gitleaks check
as a commit hook.
