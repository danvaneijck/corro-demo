import * as path from 'node:path';
import * as cdk from 'aws-cdk-lib';
import * as apigw from 'aws-cdk-lib/aws-apigateway';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import { HttpJwtAuthorizer } from 'aws-cdk-lib/aws-apigatewayv2-authorizers';
import { HttpLambdaIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subs from 'aws-cdk-lib/aws-sns-subscriptions';
import { RustFunction } from 'cargo-lambda-cdk';
import { Construct } from 'constructs';

export interface DemoStackProps extends cdk.StackProps {
  /** Short git SHA baked into the Lambdas' env, so audit records name the deployed version. */
  readonly gitSha: string;
}

/** Namespace for EMF metrics emitted by the Lambdas. Alarm metrics carry no dimensions. */
const METRICS_NAMESPACE = 'CorroDemo';

const DESTROY = cdk.RemovalPolicy.DESTROY;

export class DemoStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: DemoStackProps) {
    super(scope, id, props);

    // ---------------------------------------------------------------- 1. Tables

    const inbox = new dynamodb.Table(this, 'InboxTable', {
      partitionKey: { name: 'PK', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'SK', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      stream: dynamodb.StreamViewType.NEW_IMAGE,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      timeToLiveAttribute: 'expires_at',
      removalPolicy: DESTROY,
    });
    inbox.addGlobalSecondaryIndex({
      indexName: 'GSI1',
      partitionKey: { name: 'GSI1PK', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'GSI1SK', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Append-only: nobody, including admins and the stack's own roles, may change or delete a
    // record. BatchWriteItem and PartiQL writes are authorised as their own actions, so they're
    // denied too. PutItem stays allowed; the writer uses attribute_not_exists(PK) so it can't
    // overwrite. TTL expiry is done by the service and isn't affected.
    const audit = new dynamodb.Table(this, 'AuditTable', {
      partitionKey: { name: 'PK', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'SK', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      timeToLiveAttribute: 'expires_at',
      removalPolicy: DESTROY,
      resourcePolicy: new iam.PolicyDocument({
        statements: [
          new iam.PolicyStatement({
            sid: 'AuditIsAppendOnly',
            effect: iam.Effect.DENY,
            principals: [new iam.AnyPrincipal()],
            actions: [
              'dynamodb:UpdateItem',
              'dynamodb:DeleteItem',
              'dynamodb:BatchWriteItem',
              'dynamodb:PartiQLUpdate',
              'dynamodb:PartiQLDelete',
            ],
            resources: ['*'],
          }),
        ],
      }),
    });
    audit.addGlobalSecondaryIndex({
      indexName: 'GSI1',
      partitionKey: { name: 'GSI1PK', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'GSI1SK', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ---------------------------------------------------------------- 2. Cognito

    const userPool = new cognito.UserPool(this, 'UserPool', {
      featurePlan: cognito.FeaturePlan.LITE,
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      signInCaseSensitive: false,
      customAttributes: {
        tenant_id: new cognito.StringAttribute({ minLen: 3, maxLen: 32, mutable: false }),
        role: new cognito.StringAttribute({ minLen: 1, maxLen: 16, mutable: true }),
      },
      passwordPolicy: { minLength: 12 },
      accountRecovery: cognito.AccountRecovery.NONE,
      removalPolicy: DESTROY,
    });

    // Users can read their tenant and role but never write them: custom attributes are left out
    // of writeAttributes, so only admin APIs (the seed) can set them.
    const userPoolClient = userPool.addClient('WebClient', {
      authFlows: { userPassword: true },
      generateSecret: false,
      preventUserExistenceErrors: true,
      readAttributes: new cognito.ClientAttributes()
        .withStandardAttributes({ email: true, emailVerified: true })
        .withCustomAttributes('tenant_id', 'role'),
      writeAttributes: new cognito.ClientAttributes().withStandardAttributes({ email: true }),
      idTokenValidity: cdk.Duration.hours(1),
      accessTokenValidity: cdk.Duration.hours(1),
    });

    userPool.addGroup('PlatformAdminGroup', {
      groupName: 'platform-admin',
      description: 'Platform operators (content-free cross-tenant stats only)',
    });

    // ---------------------------------------------------------------- 3. Webhook signing keys

    // One generated root key. Per-channel HMAC keys are derived from it in code
    // (HMAC-SHA256(root, "webhook/<channel>")), because CloudFormation can only generate one value
    // per secret. In production this JSON would hold each provider's own signing secret.
    const webhookKeys = new secretsmanager.Secret(this, 'WebhookKeys', {
      secretName: 'corro-demo/webhook-keys',
      description: 'Root key for inbound webhook HMAC signatures (demo)',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({}),
        generateStringKey: 'root',
        excludePunctuation: true,
        passwordLength: 64,
      },
      removalPolicy: DESTROY,
    });

    // ---------------------------------------------------------------- 5. Roles (before the functions)

    const apiRole = this.lambdaRole('ApiFnRole');
    const ingestRole = this.lambdaRole('IngestFnRole');

    // Per-request credentials for tenant data. The functions assume this role with a
    // `tenant_id` session tag, and every allowed key must start with `T#<that tenant>#`.
    const tenantDataRole = new iam.Role(this, 'TenantDataRole', {
      description: 'Tenant-scoped data access, assumed per request with a tenant_id session tag',
      maxSessionDuration: cdk.Duration.hours(1),
      assumedBy: new iam.ArnPrincipal(apiRole.roleArn),
    });
    // One trust statement, written out so the condition covers AssumeRole as well as TagSession:
    // a session without a tenant_id tag (or with any other tag) can't be created at all.
    (tenantDataRole.node.defaultChild as iam.CfnRole).assumeRolePolicyDocument = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['sts:AssumeRole', 'sts:TagSession'],
          principals: [new iam.ArnPrincipal(apiRole.roleArn), new iam.ArnPrincipal(ingestRole.roleArn)],
          conditions: {
            StringLike: { 'aws:RequestTag/tenant_id': '?*' },
            'ForAllValues:StringEquals': { 'aws:TagKeys': ['tenant_id'] },
          },
        }),
      ],
    });
    const tenantKeys = {
      'ForAllValues:StringLike': { 'dynamodb:LeadingKeys': ['T#${aws:PrincipalTag/tenant_id}#*'] },
    };
    // Explicit allow-list. No Scan: ForAllValues passes when there are no leading keys, so a
    // wildcard action list with this condition would allow a cross-tenant Scan.
    tenantDataRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'TenantInbox',
        actions: [
          'dynamodb:GetItem',
          'dynamodb:BatchGetItem',
          'dynamodb:Query',
          'dynamodb:PutItem',
          'dynamodb:UpdateItem',
          'dynamodb:ConditionCheckItem',
        ],
        resources: [inbox.tableArn, `${inbox.tableArn}/index/GSI1`],
        conditions: tenantKeys,
      }),
    );
    tenantDataRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'TenantAuditRead',
        actions: ['dynamodb:Query'],
        resources: [audit.tableArn, `${audit.tableArn}/index/GSI1`],
        conditions: tenantKeys,
      }),
    );

    // ---------------------------------------------------------------- 6. Function-role grants

    for (const role of [apiRole, ingestRole]) {
      role.addToPolicy(
        new iam.PolicyStatement({
          sid: 'AssumeTenantDataRole',
          actions: ['sts:AssumeRole', 'sts:TagSession'],
          resources: [tenantDataRole.roleArn],
        }),
      );
      role.addToPolicy(
        new iam.PolicyStatement({
          sid: 'AuditAppend',
          actions: ['dynamodb:PutItem'],
          resources: [audit.tableArn],
        }),
      );
    }
    // The one deliberate cross-tenant read in the data path: route lookups, which are
    // read-only and content-free.
    ingestRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'RouteLookup',
        actions: ['dynamodb:GetItem'],
        resources: [inbox.tableArn],
        conditions: { 'ForAllValues:StringLike': { 'dynamodb:LeadingKeys': ['ROUTE#*'] } },
      }),
    );
    webhookKeys.grantRead(ingestRole);

    // ---------------------------------------------------------------- 4. Lambdas

    const commonEnv = {
      TABLE: inbox.tableName,
      AUDIT_TABLE: audit.tableName,
      TENANT_ROLE_ARN: tenantDataRole.roleArn,
      METRICS_NAMESPACE,
      GIT_SHA: props.gitSha,
    };

    const apiFn = this.rustFunction('api', apiRole, {
      ...commonEnv,
      SEARCH_BACKEND: 'ddb',
      ENABLE_ISOLATION_PROBE: 'true',
      // Public values the web page needs to sign in (served from GET /config.json).
      USER_POOL_ID: userPool.userPoolId,
      USER_POOL_CLIENT_ID: userPoolClient.userPoolClientId,
    });
    const ingestFn = this.rustFunction('ingest', ingestRole, {
      ...commonEnv,
      SECRET_ARN: webhookKeys.secretArn,
    });

    // ---------------------------------------------------------------- 7. HTTP API

    const httpApi = new apigwv2.HttpApi(this, 'HttpApi', {
      apiName: 'corro-demo',
      description: 'Unified Inbox demo API',
      createDefaultStage: false,
    });

    const accessLogs = new logs.LogGroup(this, 'ApiAccessLogs', {
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: DESTROY,
    });
    const stage = new apigwv2.HttpStage(this, 'DefaultStage', {
      httpApi,
      stageName: '$default',
      autoDeploy: true,
      throttle: { rateLimit: 50, burstLimit: 100 },
      accessLogSettings: {
        destination: new apigwv2.LogGroupLogDestination(accessLogs),
        format: apigw.AccessLogFormat.custom(
          JSON.stringify({
            requestId: '$context.requestId',
            ip: '$context.identity.sourceIp',
            requestTime: '$context.requestTime',
            routeKey: '$context.routeKey',
            status: '$context.status',
            responseLength: '$context.responseLength',
            latencyMs: '$context.responseLatency',
            integrationLatencyMs: '$context.integrationLatency',
            integrationError: '$context.integrationErrorMessage',
            authorizerError: '$context.authorizer.error',
            sub: '$context.authorizer.claims.sub',
            tenantId: '$context.authorizer.claims.custom:tenant_id',
            userAgent: '$context.identity.userAgent',
          }),
        ),
      },
    });

    const jwt = new HttpJwtAuthorizer(
      'CognitoJwt',
      `https://cognito-idp.${this.region}.amazonaws.com/${userPool.userPoolId}`,
      { jwtAudience: [userPoolClient.userPoolClientId] },
    );
    const apiIntegration = new HttpLambdaIntegration('ApiIntegration', apiFn);
    const ingestIntegration = new HttpLambdaIntegration('IngestIntegration', ingestFn);
    const { GET, POST } = apigwv2.HttpMethod;

    // Every route is listed explicitly; there's no catch-all, so an unknown path never reaches a
    // Lambda. Authorised routes:
    const authed: [apigwv2.HttpMethod, string][] = [
      [GET, '/me'],
      [GET, '/conversations'],
      [GET, '/conversations/{id}/messages'],
      [POST, '/conversations/{id}/messages'],
      [GET, '/people'],
      [GET, '/search'],
      [GET, '/audit'],
      [GET, '/debug/probe'],
    ];
    for (const [method, routePath] of authed) {
      httpApi.addRoutes({ path: routePath, methods: [method], integration: apiIntegration, authorizer: jwt });
    }
    // Public: the web page and its public config (Step 8).
    for (const routePath of ['/', '/app.js', '/style.css', '/config.json']) {
      httpApi.addRoutes({ path: routePath, methods: [GET], integration: apiIntegration });
    }
    // Public: inbound webhooks, authenticated by HMAC in ingest-fn.
    const [inboundRoute] = httpApi.addRoutes({
      path: '/inbound/{channel}', methods: [POST], integration: ingestIntegration,
    });

    // A tighter limit on the unauthenticated ingest route. The L2 has no per-route settings, and
    // this raw property is passed through as-is, so it uses CloudFormation (PascalCase) keys.
    (stage.node.defaultChild as apigwv2.CfnStage).routeSettings = {
      'POST /inbound/{channel}': { ThrottlingRateLimit: 20, ThrottlingBurstLimit: 40 },
    };
    // The stage must be created after the route its settings name.
    stage.node.addDependency(inboundRoute);

    // ---------------------------------------------------------------- 8. Ops: alarms and dashboard

    const topic = new sns.Topic(this, 'AlarmTopic', { displayName: 'corro-demo alarms' });
    const alarmEmail = this.node.tryGetContext('alarmEmail') as string | undefined;
    if (alarmEmail) {
      topic.addSubscription(new subs.EmailSubscription(alarmEmail));
    }
    const alarmAction = new cwActions.SnsAction(topic);

    const emf = (metricName: string) =>
      new cloudwatch.Metric({
        namespace: METRICS_NAMESPACE,
        metricName,
        statistic: 'Sum',
        period: cdk.Duration.minutes(1),
      });

    const alarms: cloudwatch.Alarm[] = [];
    const alarm = (id: string, description: string, metric: cloudwatch.IMetric, threshold: number, periods = 1) => {
      const a = new cloudwatch.Alarm(this, id, {
        alarmDescription: description,
        metric,
        threshold,
        evaluationPeriods: periods,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
      a.addAlarmAction(alarmAction);
      a.addOkAction(alarmAction);
      alarms.push(a);
      return a;
    };

    alarm('AuditWriteFailedAlarm', 'P1: an audit write failed, so a request failed closed', emf('AuditWriteFailed'), 0);
    for (const [name, fn] of [['Api', apiFn], ['Ingest', ingestFn]] as const) {
      alarm(`${name}ErrorsAlarm`, `${name} Lambda errors over 5 minutes`,
        fn.metricErrors({ period: cdk.Duration.minutes(5), statistic: 'Sum' }), 0);
    }
    alarm('LambdaThrottlesAlarm', 'Lambda throttles (the account concurrency quota is 10)',
      new cloudwatch.MathExpression({
        expression: 'api + ingest',
        usingMetrics: {
          api: apiFn.metricThrottles({ statistic: 'Sum' }),
          ingest: ingestFn.metricThrottles({ statistic: 'Sum' }),
        },
        period: cdk.Duration.minutes(1),
        label: 'Throttles',
      }), 0);
    alarm('Api5xxRateAlarm', 'API 5xx rate above 1% over 5 minutes',
      new cloudwatch.MathExpression({
        expression: 'IF(requests > 0, 100 * errors / requests, 0)',
        usingMetrics: {
          errors: httpApi.metricServerError({ statistic: 'Sum' }),
          requests: httpApi.metricCount({ statistic: 'Sum' }),
        },
        period: cdk.Duration.minutes(5),
        label: '5xx %',
      }), 1);
    alarm('InboxThrottleAlarm', 'DynamoDB throttling on the inbox table',
      inbox.metricThrottledRequestsForOperations({
        operations: [
          dynamodb.Operation.GET_ITEM, dynamodb.Operation.BATCH_GET_ITEM, dynamodb.Operation.QUERY,
          dynamodb.Operation.PUT_ITEM, dynamodb.Operation.UPDATE_ITEM, dynamodb.Operation.TRANSACT_WRITE_ITEMS,
        ],
        period: cdk.Duration.minutes(1),
      }), 0);
    alarm('AuditThrottleAlarm', 'DynamoDB throttling on the audit table',
      audit.metricThrottledRequestsForOperations({
        operations: [dynamodb.Operation.PUT_ITEM, dynamodb.Operation.QUERY],
        period: cdk.Duration.minutes(1),
      }), 0);
    alarm('AuthzDeniedSpikeAlarm', 'More than 20 authorisation denials in 5 minutes (possible probing)',
      new cloudwatch.Metric({
        namespace: METRICS_NAMESPACE, metricName: 'AuthzDenied', statistic: 'Sum', period: cdk.Duration.minutes(5),
      }), 20);

    const dashboard = new cloudwatch.Dashboard(this, 'Dashboard', { dashboardName: 'corro-demo' });
    dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'API requests and errors', width: 12,
        left: [httpApi.metricCount({ statistic: 'Sum' })],
        right: [httpApi.metricClientError({ statistic: 'Sum' }), httpApi.metricServerError({ statistic: 'Sum' })],
      }),
      new cloudwatch.GraphWidget({
        title: 'API latency (ms)', width: 12,
        left: [httpApi.metricLatency({ statistic: 'p50' }), httpApi.metricLatency({ statistic: 'p99' })],
      }),
    );
    dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Messages ingested by channel', width: 8,
        left: [new cloudwatch.MathExpression({
          expression: `SEARCH('{${METRICS_NAMESPACE},channel} MetricName="MessagesIngested"', 'Sum', 60)`,
          label: '',
        })],
      }),
      new cloudwatch.GraphWidget({
        title: 'Denials and audit', width: 8,
        left: [emf('AuthzDenied'), emf('AuditWritten')],
        right: [emf('AuditWriteFailed')],
      }),
      new cloudwatch.GraphWidget({
        title: 'Lambda duration p99 (ms)', width: 8,
        left: [apiFn.metricDuration({ statistic: 'p99' }), ingestFn.metricDuration({ statistic: 'p99' })],
      }),
    );
    dashboard.addWidgets(new cloudwatch.AlarmStatusWidget({ title: 'Alarms', width: 24, alarms }));

    // ---------------------------------------------------------------- Outputs

    const out = (id: string, value: string) => new cdk.CfnOutput(this, id, { value });
    out('ApiUrl', stage.url);
    out('UserPoolId', userPool.userPoolId);
    out('UserPoolClientId', userPoolClient.userPoolClientId);
    out('WebhookSecretArn', webhookKeys.secretArn);
    out('InboxTableName', inbox.tableName);
    out('AuditTableName', audit.tableName);
    out('TenantDataRoleArn', tenantDataRole.roleArn);
  }

  private lambdaRole(id: string): iam.Role {
    return new iam.Role(this, id, {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')],
    });
  }

  private rustFunction(bin: 'api' | 'ingest', role: iam.Role, environment: Record<string, string>): RustFunction {
    const functionName = `CorroDemo-${bin}`;
    const logGroup = new logs.LogGroup(this, `${bin}Logs`, {
      logGroupName: `/aws/lambda/${functionName}`,
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: DESTROY,
    });
    return new RustFunction(this, `${bin}Fn`, {
      functionName,
      manifestPath: path.join(__dirname, '..', '..', 'services', 'Cargo.toml'),
      binaryName: bin,
      architecture: lambda.Architecture.ARM_64,
      memorySize: 256,
      timeout: cdk.Duration.seconds(10),
      role,
      logGroup,
      loggingFormat: lambda.LoggingFormat.JSON,
      applicationLogLevelV2: lambda.ApplicationLogLevel.INFO,
      systemLogLevelV2: lambda.SystemLogLevel.WARN,
      tracing: lambda.Tracing.ACTIVE,
      environment,
    });
  }
}
