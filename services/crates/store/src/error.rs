use aws_sdk_dynamodb::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};

#[derive(Debug, Clone, thiserror::Error)]
pub enum StoreError {
    /// IAM refused the call. With tenant-scoped credentials this means a key outside the
    /// caller's tenant was requested.
    #[error("access denied by IAM")]
    AccessDenied,
    #[error("not found")]
    NotFound,
    #[error("invalid cursor")]
    InvalidCursor,
    #[error("dynamodb error: {0}")]
    Dynamo(String),
    #[error("sts error: {0}")]
    Sts(String),
    #[error("item mapping error: {0}")]
    Item(String),
}

impl StoreError {
    /// A short, stable code for audit records and responses. The detail (which can include ARNs)
    /// belongs in logs only: tenant admins can read the audit trail.
    pub fn code(&self) -> &'static str {
        match self {
            StoreError::AccessDenied => "iam_access_denied",
            StoreError::NotFound => "not_found",
            StoreError::InvalidCursor => "invalid_cursor",
            StoreError::Dynamo(_) => "dynamodb_error",
            StoreError::Sts(_) => "sts_error",
            StoreError::Item(_) => "item_mapping_error",
        }
    }

    pub fn from_sdk<E, R>(err: SdkError<E, R>) -> Self
    where
        E: ProvideErrorMetadata + std::error::Error + 'static,
        R: std::fmt::Debug,
    {
        if is_access_denied(&err) {
            return StoreError::AccessDenied;
        }
        StoreError::Dynamo(DisplayErrorContext(&err).to_string())
    }
}

pub(crate) fn is_access_denied<E: ProvideErrorMetadata, R>(err: &SdkError<E, R>) -> bool {
    matches!(err.code(), Some("AccessDeniedException"))
}

impl From<serde_dynamo::Error> for StoreError {
    fn from(e: serde_dynamo::Error) -> Self {
        StoreError::Item(e.to_string())
    }
}

impl From<aws_sdk_dynamodb::error::BuildError> for StoreError {
    fn from(e: aws_sdk_dynamodb::error::BuildError) -> Self {
        StoreError::Dynamo(e.to_string())
    }
}
