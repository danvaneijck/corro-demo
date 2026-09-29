//! The request pipeline: route policy → claims → role check → tenant-scoped client → handler →
//! audit (fail-closed) → response.

use std::time::Instant;

use domain::Principal;
use lambda_http::http::StatusCode;
use lambda_http::request::RequestContext;
use lambda_http::{Body, Error, Request, RequestExt, Response};
use search::DdbScanFallback;
use serde_json::{Map, Value};
use store::audit::hash_params;
use store::platform::PlatformCredsProvider;
use store::{
    Actor, AuditEvent, AuditWriter, InboxRepo, Outcome, RequestInfo, ServiceInfo, StoreError,
    TenantCredsProvider, metrics,
};
use tracing::{Instrument, field};

use crate::handlers::{self, Ctx};
use crate::reply::{self, ApiError, Success};
use crate::routes::{self, Access};
use crate::web;

/// Where tenant-scoped DynamoDB clients come from.
pub enum Clients {
    /// Production: STS AssumeRole with a `tenant_id` session tag.
    Sts(Box<TenantCredsProvider>),
    /// Tests against DynamoDB Local, which has no IAM. Not compiled into the Lambda.
    #[cfg(test)]
    Fixed(aws_sdk_dynamodb::Client),
}

impl Clients {
    async fn client_for(
        &self,
        scope: &domain::TenantScope,
    ) -> Result<aws_sdk_dynamodb::Client, StoreError> {
        match self {
            Clients::Sts(p) => p.client_for(scope).await,
            #[cfg(test)]
            Clients::Fixed(c) => Ok(c.clone()),
        }
    }
}

pub struct WebConfig {
    pub region: String,
    pub user_pool_id: String,
    pub client_id: String,
}

/// Where the platform-analytics client comes from.
pub enum Platform {
    /// Production: `PlatformReadRole`, which may only query `PLATFORM#*` keys.
    Sts(Box<PlatformCredsProvider>),
    #[cfg(test)]
    Fixed(aws_sdk_dynamodb::Client),
}

impl Platform {
    pub async fn client(&self) -> Result<aws_sdk_dynamodb::Client, StoreError> {
        match self {
            Platform::Sts(p) => p.client().await,
            #[cfg(test)]
            Platform::Fixed(c) => Ok(c.clone()),
        }
    }
}

pub struct State {
    pub clients: Clients,
    pub platform: Platform,
    /// The function's own role: PutItem on audit, UpdateItem on PLATFORM#STATS#* counters.
    pub own: aws_sdk_dynamodb::Client,
    pub audit: AuditWriter,
    pub table: String,
    pub audit_table: String,
    pub search: DdbScanFallback,
    pub probe_enabled: bool,
    pub web: WebConfig,
}

fn env(name: &str) -> Result<String, Error> {
    std::env::var(name).map_err(|_| format!("missing env var {name}").into())
}

impl State {
    pub async fn from_env() -> Result<Self, Error> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let audit_table = env("AUDIT_TABLE")?;
        Ok(Self {
            clients: Clients::Sts(Box::new(TenantCredsProvider::new(
                &config,
                env("TENANT_ROLE_ARN")?,
                "api",
            ))),
            platform: Platform::Sts(Box::new(PlatformCredsProvider::new(
                &config,
                env("PLATFORM_ROLE_ARN")?,
            ))),
            own: aws_sdk_dynamodb::Client::new(&config),
            // The function's own role: PutItem on the audit table, nothing else in DynamoDB.
            audit: AuditWriter::new(
                aws_sdk_dynamodb::Client::new(&config),
                &audit_table,
                ServiceInfo {
                    fn_name: "api-fn".into(),
                    version: env("GIT_SHA").unwrap_or_else(|_| "unknown".into()),
                },
            ),
            table: env("TABLE")?,
            audit_table,
            search: DdbScanFallback::default(),
            probe_enabled: env("ENABLE_ISOLATION_PROBE").is_ok_and(|v| v == "true"),
            web: WebConfig {
                region: env("AWS_REGION")?,
                user_pool_id: env("USER_POOL_ID")?,
                client_id: env("USER_POOL_CLIENT_ID")?,
            },
        })
    }
}

struct Meta {
    route_key: String,
    api_request_id: Option<String>,
    source_ip: Option<String>,
    user_agent: Option<String>,
    claims: Option<Value>,
}

fn meta(req: &Request) -> Meta {
    match req.request_context_ref() {
        Some(RequestContext::ApiGatewayV2(ctx)) => Meta {
            route_key: ctx.route_key.clone().unwrap_or_default(),
            api_request_id: ctx.request_id.clone(),
            source_ip: ctx.http.source_ip.clone(),
            user_agent: ctx.http.user_agent.clone(),
            claims: ctx
                .authorizer
                .as_ref()
                .and_then(|a| a.jwt.as_ref())
                .map(|jwt| {
                    Value::Object(
                        jwt.claims
                            .iter()
                            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                            .collect::<Map<_, _>>(),
                    )
                }),
        },
        _ => Meta {
            route_key: String::new(),
            api_request_id: None,
            source_ip: None,
            user_agent: None,
            claims: None,
        },
    }
}

pub async fn handle(state: &State, req: Request) -> Result<Response<Body>, Error> {
    let started = Instant::now();
    let m = meta(&req);
    let span = tracing::info_span!(
        "request",
        route = %m.route_key,
        api_request_id = m.api_request_id.as_deref().unwrap_or(""),
        tenant_id = field::Empty,
        outcome = field::Empty,
    );
    async move {
        let resp = pipeline(state, &req, &m).await;
        tracing::info!(
            status = resp.status().as_u16(),
            latency_ms = started.elapsed().as_millis() as u64,
            "request done"
        );
        Ok(resp)
    }
    .instrument(span)
    .await
}

async fn pipeline(state: &State, req: &Request, m: &Meta) -> Response<Body> {
    let Some(policy) = routes::lookup(&m.route_key) else {
        return reply::error(StatusCode::NOT_FOUND, "not_found");
    };
    if policy.access == Access::Public {
        return web::serve(state, policy.id);
    }

    // API Gateway has already verified the token; build the principal from its claims.
    let principal = match m.claims.as_ref().map(Principal::from_claims) {
        Some(Ok(p)) => p,
        _ => {
            metrics::count("AuthzDenied", &[("reason", "bad_claims")]);
            tracing::Span::current().record("outcome", "denied");
            return reply::error(StatusCode::UNAUTHORIZED, "unauthorized");
        }
    };
    tracing::Span::current().record("tenant_id", principal.tenant_id.as_str());

    let result: Result<Success, ApiError> =
        if policy.access == Access::Admin && !principal.is_admin() {
            Err(ApiError::forbidden("requires_admin"))
        } else if policy.access == Access::PlatformAdmin
            && !principal.groups.iter().any(|g| g == "platform-admin")
        {
            Err(ApiError::forbidden("requires_platform_admin"))
        } else {
            run_handler(state, req, &principal, policy.id).await
        };

    let (status, body, outcome, reason, resource, count) = match result {
        Ok(s) => (s.status, s.body, s.outcome, s.reason, s.resource, s.count),
        Err(e) => {
            if e.status.is_server_error() {
                tracing::error!(reason = %e.reason, "request failed");
            }
            let body = serde_json::json!({ "error": e.code });
            (e.status, body, e.outcome, Some(e.reason), e.resource, None)
        }
    };
    if matches!(outcome, Outcome::Denied | Outcome::DeniedByIam) {
        metrics::count(
            "AuthzDenied",
            &[("reason", reason.as_deref().unwrap_or("unknown"))],
        );
    }
    tracing::Span::current().record("outcome", field::debug(outcome));

    // Fail-closed: if the audit record can't be written, nothing is returned.
    let event = AuditEvent {
        tenant_id: principal.tenant_id.clone(),
        actor: Actor::user(&principal, m.source_ip.clone(), m.user_agent.clone()),
        action: policy.action.expect("non-public routes have an action"),
        resource,
        outcome,
        reason,
        result_count: count,
        request: RequestInfo {
            api_request_id: m.api_request_id.clone(),
            lambda_request_id: req.lambda_context_ref().map(|c| c.request_id.clone()),
            route: m.route_key.clone(),
            params_hash: req.uri().query().and_then(hash_params),
        },
    };
    if state.audit.write(&event).await.is_err() {
        return reply::error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    }
    reply::json(status, &body)
}

async fn run_handler(
    state: &State,
    req: &Request,
    principal: &Principal,
    id: routes::RouteId,
) -> Result<Success, ApiError> {
    let scope = principal.scope();
    let client = state.clients.client_for(&scope).await.map_err(|e| {
        tracing::error!(error = %e, "could not get tenant-scoped credentials");
        ApiError::internal(e.code())
    })?;
    let ctx = Ctx {
        principal,
        repo: InboxRepo::new(client.clone(), &state.table, scope),
        client,
        state,
        req,
    };
    handlers::dispatch(id, &ctx).await
}

#[cfg(test)]
mod tests;
