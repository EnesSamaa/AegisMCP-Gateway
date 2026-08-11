//! Proxy error types.

use thiserror::Error;

/// Errors emitted by the `aegis-proxy` subsystem.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProxyError {
    /// Hyper HTTP engine error.
    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    /// HTTP header or status error.
    #[error("HTTP error: {0}")]
    Http(#[from] hyper::http::Error),

    /// Legacy hyper-util client error.
    #[error("Upstream client error: {0}")]
    Client(#[from] hyper_util::client::legacy::Error),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Core protocol error.
    #[error("Core protocol error: {0}")]
    Core(#[from] aegis_core::AegisError),

    /// Upstream error description.
    #[error("Upstream error: {0}")]
    Upstream(String),
}
