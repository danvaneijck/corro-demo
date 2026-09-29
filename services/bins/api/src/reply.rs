//! Handler results and how they become HTTP responses. Error bodies carry a short code and
//! never any internal detail; the detail goes to the audit record and the logs.

use lambda_http::http::StatusCode;
use lambda_http::{Body, Response};
use serde_json::{Value, json};
use store::{Outcome, Resource, StoreError};

pub struct Success {
    pub status: StatusCode,
    pub body: Value,
    pub resource: Option<Resource>,
    pub count: Option<u32>,
    pub outcome: Outcome,
    pub reason: Option<String>,
}

impl Success {
    pub fn ok(body: Value) -> Self {
        Self {
            status: StatusCode::OK,
            body,
            resource: None,
            count: None,
            outcome: Outcome::Allowed,
            reason: None,
        }
    }

    pub fn created(body: Value) -> Self {
        Self {
            status: StatusCode::CREATED,
            ..Self::ok(body)
        }
    }

    pub fn resource(mut self, r: Resource) -> Self {
        self.resource = Some(r);
        self
    }

    pub fn count(mut self, n: usize) -> Self {
        self.count = Some(u32::try_from(n).unwrap_or(u32::MAX));
        self
    }
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub outcome: Outcome,
    pub reason: String,
    pub resource: Option<Resource>,
}

impl ApiError {
    fn new(
        status: StatusCode,
        code: &'static str,
        outcome: Outcome,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code,
            outcome,
            reason: reason.into(),
            resource: None,
        }
    }

    pub fn bad_request(reason: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            Outcome::Denied,
            reason,
        )
    }

    pub fn forbidden(reason: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", Outcome::Denied, reason)
    }

    /// Not found, or not allowed to know it exists: the response is the same either way.
    pub fn not_found(reason: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", Outcome::Denied, reason)
    }

    pub fn internal(reason: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            Outcome::Error,
            reason,
        )
    }

    pub fn resource(mut self, r: Resource) -> Self {
        self.resource = Some(r);
        self
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            // With tenant-scoped credentials, IAM only denies keys outside the caller's tenant.
            // Answer like any other not-found.
            StoreError::AccessDenied => Self::new(
                StatusCode::NOT_FOUND,
                "not_found",
                Outcome::DeniedByIam,
                "iam_access_denied",
            ),
            StoreError::NotFound => Self::not_found("not_found"),
            StoreError::InvalidCursor => Self::bad_request("invalid_cursor"),
            other => {
                tracing::error!(error = %other, "store error");
                Self::internal(other.code())
            }
        }
    }
}

pub fn json(status: StatusCode, body: &Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(body.to_string()))
        .expect("static headers are valid")
}

pub fn error(status: StatusCode, code: &str) -> Response<Body> {
    json(status, &json!({ "error": code }))
}
