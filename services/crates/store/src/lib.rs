//! DynamoDB key builders, tenant-scoped credentials, the inbox repository and the audit writer.

#[cfg(feature = "admin")]
pub mod admin;
pub mod audit;
pub mod creds;
pub mod cursor;
mod error;
pub mod keys;
pub mod metrics;
pub mod platform;
pub mod repo;
pub mod routes;
pub mod time_fmt;

pub use audit::{
    Action, Actor, AuditEvent, AuditReader, AuditWriter, Outcome, RequestInfo, Resource,
    ServiceInfo,
};
pub use creds::TenantCredsProvider;
pub use error::StoreError;
pub use repo::{
    AppendOutcome, ConversationSummary, InboxRepo, Member, Page, Peer, TenantUser, new_message,
};
pub use routes::{Route, RouteRepo};
