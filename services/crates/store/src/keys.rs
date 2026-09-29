//! The only place DynamoDB key strings are built.
//!
//! Every tenant-owned partition key starts with `T#<tenant>#`. The trailing `#` matters: it stops
//! tenant `acme` matching `acme2` in the IAM `LeadingKeys` condition `T#<tenant>#*`. The only
//! non-tenant keys are `ROUTE#…` (content-free inbound routing).

use domain::{Channel, ConvId, ExternalId, RouteAddress, TenantId, TenantScope, UserId};
use ulid::Ulid;

pub const META_SK: &str = "META";
pub const IDENT_SK: &str = "IDENT";
pub const DEDUP_SK: &str = "DEDUP";
pub const ROUTE_SK: &str = "ROUTE";
pub const MSG_PREFIX: &str = "MSG#";
pub const MEMBER_PREFIX: &str = "MEMBER#";
pub const USER_PREFIX: &str = "USER#";
pub const GSI1: &str = "GSI1";

fn tenant(t: &TenantId) -> String {
    format!("T#{t}#")
}

/// `T#<t>#TENANT`: tenant meta (`SK=META`) and users (`SK=USER#<u>`).
pub fn tenant_pk(s: &TenantScope) -> String {
    format!("{}TENANT", tenant(s.tenant_id()))
}

pub fn user_sk(u: &UserId) -> String {
    format!("{USER_PREFIX}{u}")
}

/// `T#<t>#CONV#<c>`: the conversation's META, MEMBER# and MSG# items share this partition.
pub fn conv_pk(s: &TenantScope, c: &ConvId) -> String {
    format!("{}CONV#{c}", tenant(s.tenant_id()))
}

pub fn member_sk(u: &UserId) -> String {
    format!("{MEMBER_PREFIX}{u}")
}

pub fn msg_sk(id: Ulid) -> String {
    format!("{MSG_PREFIX}{id}")
}

/// GSI1 on MEMBER items: a user's conversations.
pub fn user_gsi1pk(s: &TenantScope, u: &UserId) -> String {
    format!("{}USER#{u}", tenant(s.tenant_id()))
}

/// GSI1 on CONV META items: every conversation in the tenant.
pub fn convs_gsi1pk(s: &TenantScope) -> String {
    format!("{}CONVS", tenant(s.tenant_id()))
}

pub fn conv_gsi1sk(c: &ConvId) -> String {
    format!("CONV#{c}")
}

/// `T#<t>#IDENT#<ch>#<ext>`: maps an external identity to an internal user.
pub fn ident_pk(s: &TenantScope, ch: Channel, ext: &ExternalId) -> String {
    format!("{}IDENT#{ch}#{ext}", tenant(s.tenant_id()))
}

/// `T#<t>#DEDUP#<ch>#<ext>`: one per delivered provider event, for idempotent ingest.
pub fn dedup_pk(s: &TenantScope, ch: Channel, ext: &ExternalId) -> String {
    format!("{}DEDUP#{ch}#{ext}", tenant(s.tenant_id()))
}

/// `ROUTE#<ch>#<addr>`: which tenant and conversation an inbound address belongs to.
pub fn route_pk(ch: Channel, addr: &RouteAddress) -> String {
    format!("ROUTE#{ch}#{}", addr.as_str())
}

/// Audit keys take a tenant id, not a scope: the audit writer uses the function's own role and
/// records denials for principals that never got a scope.
pub fn audit_pk(t: &TenantId, day: &str) -> String {
    format!("{}AUDIT#{day}", tenant(t))
}

pub fn actor_gsi1pk(t: &TenantId, actor: &str) -> String {
    format!("{}ACTOR#{actor}", tenant(t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::Principal;
    use serde_json::json;

    fn scope(t: &str) -> TenantScope {
        Principal::from_claims(&json!({ "sub": "u1", "custom:tenant_id": t }))
            .unwrap()
            .scope()
    }

    #[test]
    fn every_tenant_key_starts_with_the_tenant_prefix() {
        let s = scope("acme");
        let t = TenantId::parse("acme").unwrap();
        let u = UserId::parse("u1").unwrap();
        let c = ConvId::parse("c_ops").unwrap();
        let e = ExternalId::parse("Ev1").unwrap();
        let keys = [
            tenant_pk(&s),
            conv_pk(&s, &c),
            user_gsi1pk(&s, &u),
            convs_gsi1pk(&s),
            ident_pk(&s, Channel::Slack, &e),
            dedup_pk(&s, Channel::Slack, &e),
            audit_pk(&t, "2026-09-30"),
            actor_gsi1pk(&t, "u1"),
        ];
        for k in keys {
            assert!(k.starts_with("T#acme#"), "{k}");
            assert!(!k.starts_with("T#acme2#"));
        }
    }

    #[test]
    fn prefix_does_not_match_a_longer_tenant() {
        // IAM allows `T#acme#*` for acme. acme2's keys must not match that pattern.
        let k = conv_pk(&scope("acme2"), &ConvId::parse("c1").unwrap());
        assert!(!k.starts_with("T#acme#"));
    }

    #[test]
    fn examples_match_the_design() {
        let s = scope("acme");
        let c = ConvId::parse("c_ops").unwrap();
        assert_eq!(conv_pk(&s, &c), "T#acme#CONV#c_ops");
        assert_eq!(member_sk(&UserId::parse("u_bob").unwrap()), "MEMBER#u_bob");
        let addr = RouteAddress::new(&[
            &ExternalId::parse("T0ACME").unwrap(),
            &ExternalId::parse("C0OPS").unwrap(),
        ]);
        assert_eq!(route_pk(Channel::Slack, &addr), "ROUTE#slack#T0ACME#C0OPS");
    }
}
