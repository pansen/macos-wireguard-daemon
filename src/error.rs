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

    /// The daemon refused a connection-store mutation because the record is
    /// either active or locked by another in-flight operation on it. Like
    /// `AuthRequired`, this is a retry signal, not a denial: the caller is
    /// expected to resolve the condition (or just wait) and try again.
    #[error("{0}")]
    Busy(String),

    /// The daemon has no record for the id/interface asked about. A
    /// distinct variant (rather than folding into `Other`, as before) so a
    /// caller racing a concurrent remove of the same record can treat it as
    /// "already gone" instead of a failure.
    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, AppError>;
