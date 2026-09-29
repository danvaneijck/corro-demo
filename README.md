# Unified Inbox demo

A small multi-tenant messaging backend on AWS: Rust on Lambda, API Gateway HTTP API, DynamoDB
single-table design, Cognito and CDK (TypeScript). Messages arrive from different channels (Slack-
and SMS-shaped webhooks), are translated into one canonical format, routed to a tenant's
conversations, and read back through a JWT-protected API and a small web page.

The point of the demo is tenant isolation that holds even if the application code gets it wrong.
Every request runs with STS credentials tagged with the caller's `tenant_id`, and IAM only lets
those credentials touch DynamoDB keys under `T#<tenant>#`. Every action, including denials, goes to
an audit table the application can only append to.

> This is a time-boxed interview demo, not production code. **[ARCHITECTURE.md](ARCHITECTURE.md)**
> explains the design, the isolation model and the trade-offs, including what was designed but not
> built.

## Layout

```
services/   Rust workspace: domain, store, adapters, search crates; api, ingest, seed binaries
infra/      CDK app (stack `CorroDemo`)
scripts/    login, demo, smoke, reset, teardown, webhook signing
fixtures/   webhook payloads shared by tests and scripts
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

# Repository and request-pipeline tests need DynamoDB Local; without it they're skipped.
docker run -d --rm -p 8000:8000 amazon/dynamodb-local -jar DynamoDBLocal.jar -inMemory
DYNAMODB_ENDPOINT=http://localhost:8000 cargo test --workspace
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

## Seed and run the demo

```bash
export DEMO_PASSWORD='<12+ chars, upper, lower, digit, symbol>'   # never committed
scripts/reset.sh      # Cognito users + demo data (wipes the inbox table first)
scripts/demo.sh       # narrated walkthrough, press enter between steps
scripts/smoke.sh      # the same, unattended, failing on the first wrong answer
```

The web client is at the API URL (the `ApiUrl` stack output). Demo accounts: `alice@acme.test`
(admin), `bob@acme.test`, `carol@acme.test` in tenant `acme`, and `dave@globex.test` (admin) in
tenant `globex`, and `ops@corro.test`, a platform operator who can see content-free message counts
across tenants (the Platform stats tab) and nothing else. All use `DEMO_PASSWORD`.

To play a provider, `scripts/sign-webhook.sh slack fixtures/slack_message.json` signs a payload
with the webhook key and posts it. `eval "$(scripts/login.sh alice)"` sets `$TOKEN` and `$API` for
curl.

## Tear down

```bash
./scripts/teardown.sh   # cdk destroy, then checks nothing tagged project=corro-demo is left
```

## CI

GitHub Actions runs fmt, clippy, tests, `cargo deny`, gitleaks and `cdk synth` on every push and
pull request, with no AWS credentials. Locally, `pre-commit install` adds the same gitleaks check
as a commit hook.
