//! Who is calling, and the tenant scope that data access is limited to.

use serde::Serialize;
use serde_json::Value;

use crate::ids::{Channel, IdError, TenantId, UserId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Member,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Member => "member",
            Role::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClaimsError {
    #[error("missing claim {0}")]
    Missing(&'static str),
    #[error(transparent)]
    Invalid(#[from] IdError),
}

/// A signed-in user, built only from JWT claims that API Gateway has already verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub sub: UserId,
    pub tenant_id: TenantId,
    pub role: Role,
    pub username: String,
    pub groups: Vec<String>,
}

impl Principal {
    /// Builds a principal from the verified claims (`requestContext.authorizer.jwt.claims`).
    ///
    /// `sub` and `custom:tenant_id` are required. An unknown or missing `custom:role` means
    /// `member`, so a bad attribute can only ever reduce access.
    pub fn from_claims(claims: &Value) -> Result<Self, ClaimsError> {
        let get = |name: &'static str| claims.get(name).and_then(Value::as_str);
        let sub = UserId::parse(get("sub").ok_or(ClaimsError::Missing("sub"))?)?;
        let tenant_id = TenantId::parse(
            get("custom:tenant_id").ok_or(ClaimsError::Missing("custom:tenant_id"))?,
        )?;
        let role = match get("custom:role") {
            Some("admin") => Role::Admin,
            _ => Role::Member,
        };
        let username = get("email")
            .or_else(|| get("cognito:username"))
            .unwrap_or(sub.as_str())
            .to_owned();
        Ok(Self {
            sub,
            tenant_id,
            role,
            username,
            groups: parse_groups(claims.get("cognito:groups")),
        })
    }

    /// The only way for a user request to get a [`TenantScope`].
    pub fn scope(&self) -> TenantScope {
        TenantScope {
            tenant_id: self.tenant_id.clone(),
        }
    }

    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }
}

/// API Gateway HTTP APIs flatten array claims into a string like `"[a b]"`; a raw token has a
/// JSON array. Accept both.
fn parse_groups(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(Value::String(s)) => s
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split([' ', ','])
            .filter(|g| !g.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// An inbound integration (a verified webhook), acting for the tenant its route resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationPrincipal {
    pub channel: Channel,
    tenant_id: TenantId,
}

impl IntegrationPrincipal {
    /// `tenant_id` must come from a `ROUTE#` record looked up for a verified webhook, never from
    /// the request itself.
    pub fn from_route(channel: Channel, tenant_id: TenantId) -> Self {
        Self { channel, tenant_id }
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn scope(&self) -> TenantScope {
        TenantScope {
            tenant_id: self.tenant_id.clone(),
        }
    }
}

/// Proof that the caller is acting within one tenant. It has no public constructor: it comes
/// from a [`Principal`] or an [`IntegrationPrincipal`], and repository methods take it to build
/// keys, so handlers never format a key from request input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantScope {
    tenant_id: TenantId,
}

impl TenantScope {
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// For operator tooling (the seed binary) and tests only; behind the `operator` feature.
    #[cfg(feature = "operator")]
    pub fn for_operator(tenant_id: TenantId) -> Self {
        Self { tenant_id }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn builds_from_claims() {
        let p = Principal::from_claims(&json!({
            "sub": "3c1e-44",
            "custom:tenant_id": "acme",
            "custom:role": "admin",
            "email": "alice@acme.test",
            "cognito:groups": "[platform-admin]",
        }))
        .unwrap();
        assert_eq!(p.tenant_id.as_str(), "acme");
        assert!(p.is_admin());
        assert_eq!(p.username, "alice@acme.test");
        assert_eq!(p.groups, vec!["platform-admin"]);
        assert_eq!(p.scope().tenant_id().as_str(), "acme");
    }

    #[test]
    fn role_defaults_to_member() {
        for role in [None, Some("superuser"), Some("")] {
            let mut c = json!({ "sub": "u1", "custom:tenant_id": "acme" });
            if let Some(r) = role {
                c["custom:role"] = json!(r);
            }
            assert_eq!(Principal::from_claims(&c).unwrap().role, Role::Member);
        }
    }

    #[test]
    fn requires_sub_and_tenant() {
        assert_eq!(
            Principal::from_claims(&json!({ "custom:tenant_id": "acme" })),
            Err(ClaimsError::Missing("sub"))
        );
        assert_eq!(
            Principal::from_claims(&json!({ "sub": "u1" })),
            Err(ClaimsError::Missing("custom:tenant_id"))
        );
    }

    #[test]
    fn rejects_malformed_tenant_claim() {
        let r = Principal::from_claims(&json!({ "sub": "u1", "custom:tenant_id": "acme#*" }));
        assert!(matches!(r, Err(ClaimsError::Invalid(_))));
    }

    #[test]
    fn parses_group_array() {
        let p = Principal::from_claims(&json!({
            "sub": "u1", "custom:tenant_id": "acme", "cognito:groups": ["a", "b"],
        }))
        .unwrap();
        assert_eq!(p.groups, vec!["a", "b"]);
    }
}
