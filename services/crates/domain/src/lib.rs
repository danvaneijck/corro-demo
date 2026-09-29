//! Tenant ids, principals, tenant scope and the canonical message model.

pub mod ids;
pub mod message;
pub mod principal;

pub use ids::{Channel, ConvId, ExternalId, IdError, RouteAddress, TenantId, UserId};
pub use message::{CanonicalMessage, MAX_BODY_CHARS, Sender};
pub use principal::{ClaimsError, IntegrationPrincipal, Principal, Role, TenantScope};
