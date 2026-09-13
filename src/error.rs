use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Authentication failed: {0}")]
    Auth(String),

    /// A configuration-changing connection operation needs macOS admin
    /// authentication before it can proceed (see `privileged::authz`).
    /// Distinct from `Auth`: this is not a denial, it's a prompt-and-retry
    /// signal the client is expected to act on.
    #[error("Admin authentication required: {0}")]
    AuthRequired(String),

    #[error("WireGuard error: {0}")]
    WireGuard(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, AppError>;
