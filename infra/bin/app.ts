import { execSync } from 'node:child_process';
import * as cdk from 'aws-cdk-lib';
import { DemoStack } from '../lib/demo-stack';

// CI synthesises without compiling the Rust code (CDK_SKIP_BUNDLING=1); local deploys bundle normally.
const app = new cdk.App(
  process.env.CDK_SKIP_BUNDLING === '1' ? { postCliContext: { 'aws:cdk:bundling-stacks': [] } } : {},
);

function gitSha(): string {
  try {
    return execSync('git rev-parse --short HEAD', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
  } catch {
    return 'unknown';
  }
}

// The account comes from the caller's credentials (never hard-coded). The org SCP only allows
// ap-southeast-2, so the region is fixed.
new DemoStack(app, 'CorroDemo', {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: 'ap-southeast-2' },
  description: 'Unified Inbox interview demo (multi-tenant Rust on Lambda)',
  gitSha: gitSha(),
});

cdk.Tags.of(app).add('project', 'corro-demo');
