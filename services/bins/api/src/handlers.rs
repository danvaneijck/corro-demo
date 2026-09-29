//! Route handlers. Each gets a repo already bound to the caller's tenant scope and returns a
//! [`Success`] or an [`ApiError`]; the pipeline in `app` audits either one.

use domain::{Channel, ConvId, MAX_BODY_CHARS, Principal, Sender, TenantId};
use lambda_http::{Request, RequestExt};
use search::{MAX_QUERY_CHARS, MIN_QUERY_CHARS, MessageSearch};
use serde::Deserialize;
use serde_json::json;
use store::{AuditReader, InboxRepo, Outcome, Resource, StoreError, metrics, new_message};
use time::OffsetDateTime;
use time::macros::format_description;

use crate::app::State;
use crate::reply::{ApiError, Success};
use crate::routes::RouteId;

pub struct Ctx<'a> {
    pub principal: &'a Principal,
    pub repo: InboxRepo,
    pub client: aws_sdk_dynamodb::Client,
    pub state: &'a State,
    pub req: &'a Request,
}

type HandlerResult = Result<Success, ApiError>;

impl Ctx<'_> {
    fn path(&self, name: &str) -> Option<String> {
        self.req
            .path_parameters_ref()
            .and_then(|p| p.first(name))
            .map(str::to_owned)
    }

    fn query(&self, name: &str) -> Option<String> {
        self.req
            .query_string_parameters_ref()
            .and_then(|q| q.first(name))
            .map(str::to_owned)
    }

    fn limit(&self, default: i32) -> i32 {
        self.query("limit")
            .and_then(|l| l.parse().ok())
            .unwrap_or(default)
    }

    /// The conversation in the path, if the caller is a member. Otherwise 404, whether it
    /// doesn't exist, belongs to someone else, or belongs to another tenant.
    async fn member_conversation(&self) -> Result<ConvId, ApiError> {
        let raw = self.path("id").unwrap_or_default();
        let conv =
            ConvId::parse(&raw).map_err(|_| ApiError::bad_request("invalid_conversation_id"))?;
        let resource = Resource::new("conversation", conv.as_str());
        if !self.repo.is_member(&conv, &self.principal.sub).await? {
            return Err(ApiError::not_found("not_member").resource(resource));
        }
        Ok(conv)
    }
}

pub async fn dispatch(id: RouteId, ctx: &Ctx<'_>) -> HandlerResult {
    match id {
        RouteId::Me => me(ctx).await,
        RouteId::Conversations => conversations(ctx).await,
        RouteId::ListMessages => list_messages(ctx).await,
        RouteId::PostMessage => post_message(ctx).await,
        RouteId::People => people(ctx).await,
        RouteId::Search => search(ctx).await,
        RouteId::Audit => audit(ctx).await,
        RouteId::Probe => probe(ctx).await,
        RouteId::WebIndex | RouteId::WebJs | RouteId::WebCss | RouteId::WebConfig => Err(
            ApiError::internal("public route reached the authenticated pipeline"),
        ),
    }
}

async fn me(ctx: &Ctx<'_>) -> HandlerResult {
    let p = ctx.principal;
    let profile = ctx.repo.tenant_user(&p.sub).await?;
    Ok(Success::ok(json!({
        "user_id": p.sub,
        "tenant_id": p.tenant_id,
        "role": p.role,
        "username": p.username,
        "groups": p.groups,
        "display_name": profile.as_ref().map(|u| &u.display_name),
    }))
    .resource(Resource::new("user", p.sub.as_str())))
}

async fn conversations(ctx: &Ctx<'_>) -> HandlerResult {
    let convs = ctx.repo.list_user_conversations(&ctx.principal.sub).await?;
    let n = convs.len();
    Ok(Success::ok(json!({ "items": convs })).count(n))
}

async fn list_messages(ctx: &Ctx<'_>) -> HandlerResult {
    let conv = ctx.member_conversation().await?;
    let cursor = ctx.query("cursor");
    let page = ctx
        .repo
        .list_messages(&conv, ctx.limit(20), cursor.as_deref())
        .await
        .map_err(|e| ApiError::from(e).resource(Resource::new("conversation", conv.as_str())))?;
    let n = page.items.len();
    Ok(
        Success::ok(json!({ "items": page.items, "next_cursor": page.next_cursor }))
            .resource(Resource::new("conversation", conv.as_str()))
            .count(n),
    )
}

#[derive(Deserialize)]
struct NewMessage {
    text: String,
}

async fn post_message(ctx: &Ctx<'_>) -> HandlerResult {
    let conv = ctx.member_conversation().await?;
    let resource = Resource::new("conversation", conv.as_str());
    let body: NewMessage = serde_json::from_slice(ctx.req.body().as_ref())
        .map_err(|_| ApiError::bad_request("invalid_body"))?;
    let text = body.text.trim();
    if text.is_empty() || text.chars().count() > MAX_BODY_CHARS {
        return Err(ApiError::bad_request("text_length").resource(resource));
    }
    let msg = new_message(
        conv,
        Channel::Native,
        Sender::User {
            user_id: ctx.principal.sub.clone(),
        },
        text.to_owned(),
        None,
    );
    ctx.repo.append_message(&msg).await?;
    metrics::count("MessagesIngested", &[("channel", Channel::Native.as_str())]);
    Ok(Success::created(json!(msg)).resource(resource))
}

async fn people(ctx: &Ctx<'_>) -> HandlerResult {
    let (peers, users) = tokio::try_join!(
        ctx.repo.co_members(&ctx.principal.sub),
        ctx.repo.tenant_users()
    )?;
    let items: Vec<_> = peers
        .iter()
        .map(|p| {
            let u = users.iter().find(|u| u.user_id == p.user_id);
            json!({
                "user_id": p.user_id,
                "display_name": u.map(|u| &u.display_name),
                "email": u.map(|u| &u.email),
                "shared": p.shared,
            })
        })
        .collect();
    let n = items.len();
    Ok(Success::ok(json!({ "items": items })).count(n))
}

async fn search(ctx: &Ctx<'_>) -> HandlerResult {
    let q = ctx.query("q").unwrap_or_default();
    let len = q.trim().chars().count();
    if !(MIN_QUERY_CHARS..=MAX_QUERY_CHARS).contains(&len) {
        return Err(ApiError::bad_request("query_length"));
    }
    let hits = ctx
        .state
        .search
        .search(&ctx.repo, &ctx.principal.sub, q.trim())
        .await?;
    let n = hits.len();
    Ok(Success::ok(json!({ "items": hits, "backend": "ddb-fallback" })).count(n))
}

async fn audit(ctx: &Ctx<'_>) -> HandlerResult {
    let today = OffsetDateTime::now_utc().date();
    let date = match ctx.query("date") {
        Some(d) => time::Date::parse(&d, format_description!("[year]-[month]-[day]"))
            .map_err(|_| ApiError::bad_request("invalid_date"))?,
        None => today,
    };
    let day = date
        .format(format_description!("[year]-[month]-[day]"))
        .unwrap_or_default();
    let reader = AuditReader::new(
        ctx.client.clone(),
        &ctx.state.audit_table,
        ctx.repo.scope().clone(),
    );
    let cursor = ctx.query("cursor");
    let page = reader
        .list_day(&day, ctx.limit(50), cursor.as_deref())
        .await?;
    let n = page.items.len();
    Ok(
        Success::ok(json!({ "date": day, "items": page.items, "next_cursor": page.next_cursor }))
            .resource(Resource::new("audit_day", day))
            .count(n),
    )
}

/// Deliberately reads another tenant's data with the caller's tenant-scoped credentials and no
/// app-layer checks. IAM should refuse; if it doesn't, that's an isolation failure.
async fn probe(ctx: &Ctx<'_>) -> HandlerResult {
    if !ctx.state.probe_enabled {
        return Err(ApiError::not_found("probe_disabled"));
    }
    let raw = ctx.query("tenant").unwrap_or_default();
    let target = TenantId::parse(&raw).map_err(|_| ApiError::bad_request("invalid_tenant"))?;
    if &target == ctx.repo.scope().tenant_id() {
        return Err(ApiError::bad_request("probe_own_tenant"));
    }
    let resource = Resource::new("tenant", target.as_str());
    match ctx.repo.isolation_probe(&target).await {
        Err(StoreError::AccessDenied) => Ok(Success {
            outcome: Outcome::DeniedByIam,
            reason: Some("AccessDeniedException".into()),
            ..Success::ok(json!({
                "target_tenant": target,
                "blocked_by": "iam",
                "error": "AccessDeniedException",
            }))
            .resource(resource)
        }),
        Ok(()) => {
            metrics::count("IsolationBreach", &[]);
            tracing::error!(target_tenant = %target, "isolation probe was NOT blocked by IAM");
            Err(ApiError::internal("isolation_breach").resource(resource))
        }
        Err(e) => Err(ApiError::from(e).resource(resource)),
    }
}
