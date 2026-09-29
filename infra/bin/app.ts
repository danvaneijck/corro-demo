import * as cdk from 'aws-cdk-lib';
import { DemoStack } from '../lib/demo-stack';

const app = new cdk.App();

// The account comes from the caller's credentials (never hard-coded). The org SCP only allows
// ap-southeast-2, so the region is fixed.
new DemoStack(app, 'CorroDemo', {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: 'ap-southeast-2' },
  description: 'Unified Inbox interview demo (multi-tenant Rust on Lambda)',
});

cdk.Tags.of(app).add('project', 'corro-demo');
