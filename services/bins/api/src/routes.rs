//! Every route, who may call it, and what it's audited as. One table, so a review can see the
//! whole authorisation policy at a glance. API Gateway only forwards route keys that exist in
//! the CDK stack; anything not listed here is a 404.

use store::Action;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// No token. Static web assets only; not audited.
    Public,
    /// Any signed-in user of the tenant.
    Member,
    /// A tenant admin (`custom:role = admin`).
    Admin,
    /// A platform operator (Cognito group `platform-admin`). Content-free cross-tenant counts only.
    PlatformAdmin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteId {
    Me,
    Conversations,
    ListMessages,
    PostMessage,
    People,
    Search,
    Audit,
    Probe,
    PlatformStats,
    WebIndex,
    WebJs,
    WebCss,
    WebConfig,
}

#[derive(Debug)]
pub struct RoutePolicy {
    pub key: &'static str,
    pub id: RouteId,
    pub access: Access,
    pub action: Option<Action>,
}

const fn route(
    key: &'static str,
    id: RouteId,
    access: Access,
    action: Option<Action>,
) -> RoutePolicy {
    RoutePolicy {
        key,
        id,
        access,
        action,
    }
}

use Access::*;
use RouteId::*;

pub const ROUTES: &[RoutePolicy] = &[
    route("GET /me", Me, Member, Some(Action::MeRead)),
    route(
        "GET /conversations",
        Conversations,
        Member,
        Some(Action::ConversationList),
    ),
    route(
        "GET /conversations/{id}/messages",
        ListMessages,
        Member,
        Some(Action::MessageList),
    ),
    route(
        "POST /conversations/{id}/messages",
        PostMessage,
        Member,
        Some(Action::MessageCreate),
    ),
    route("GET /people", People, Member, Some(Action::PeopleList)),
    route("GET /search", Search, Member, Some(Action::SearchQuery)),
    route("GET /audit", Audit, Admin, Some(Action::AuditRead)),
    route(
        "GET /debug/probe",
        Probe,
        Member,
        Some(Action::IsolationProbe),
    ),
    route(
        "GET /platform/stats",
        PlatformStats,
        PlatformAdmin,
        Some(Action::PlatformStats),
    ),
    route("GET /", WebIndex, Public, None),
    route("GET /app.js", WebJs, Public, None),
    route("GET /style.css", WebCss, Public, None),
    route("GET /config.json", WebConfig, Public, None),
];

pub fn lookup(route_key: &str) -> Option<&'static RoutePolicy> {
    ROUTES.iter().find(|r| r.key == route_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_non_public_route_is_audited() {
        for r in ROUTES {
            assert_eq!(r.access == Public, r.action.is_none(), "{}", r.key);
        }
    }

    #[test]
    fn audit_log_is_admin_only() {
        assert_eq!(lookup("GET /audit").unwrap().access, Admin);
    }

    #[test]
    fn platform_stats_needs_the_platform_group() {
        assert_eq!(lookup("GET /platform/stats").unwrap().access, PlatformAdmin);
    }

    #[test]
    fn unknown_routes_are_not_found() {
        assert!(lookup("DELETE /me").is_none());
        assert!(lookup("GET /conversations/{id}").is_none());
    }
}
