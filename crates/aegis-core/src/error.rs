//! Unified error type hierarchy for AegisMCP-Gateway.
//!
//! All public-facing errors are expressed as variants of [`AegisError`].
//! Internal subsystems map their errors into this type before surfacing them
//! through the public API.

use thiserror::Error;

/// The canonical result type for operations in the AegisMCP-Gateway.
pub type Result<T, E = AegisError> = std::result::Result<T, E>;

/// Top-level error type for the AegisMCP-Gateway.
///
/// Every subsystem error maps into a variant here so that callers can handle
/// all gateway errors from a single match expression.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AegisError {
    // -----------------------------------------------------------------------
    // Protocol errors
    // -----------------------------------------------------------------------
    /// The incoming message is not valid JSON.
    #[error("invalid JSON payload: {0}")]
    InvalidJson(#[from] serde_json::Error),

    /// The JSON-RPC envelope is structurally invalid (missing required fields, wrong types, etc.).
    #[error("malformed JSON-RPC message: {reason}")]
    MalformedJsonRpc {
        /// Human-readable explanation of what was wrong.
        reason: String,
    },

    /// The requested JSON-RPC method is not registered on this gateway.
    #[error("unknown JSON-RPC method: '{method}'")]
    UnknownMethod {
        /// The unrecognised method name.
        method: String,
    },

    // -----------------------------------------------------------------------
    // Security / guardrail errors
    // -----------------------------------------------------------------------
    /// A guardrail rule blocked the request.
    #[error("request blocked by guardrail rule '{rule}': {detail}")]
    GuardrailViolation {
        /// Name of the rule that triggered.
        rule: String,
        /// Additional context about the violation.
        detail: String,
    },

    /// Authentication or authorisation failure.
    #[error("authorization denied: {0}")]
    Unauthorized(String),

    // -----------------------------------------------------------------------
    // WASM runtime errors
    // -----------------------------------------------------------------------
    /// An error from the Wasmtime / WASI runtime.
    #[error("WASM runtime error: {0}")]
    WasmRuntime(String),

    // -----------------------------------------------------------------------
    // Infrastructure errors
    // -----------------------------------------------------------------------
    /// An upstream / downstream I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic catch-all for errors from third-party crates.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl AegisError {
    /// Returns the corresponding JSON-RPC error code for this error variant.
    ///
    /// See <https://www.jsonrpc.org/specification#error_object> for the reserved code ranges.
    #[must_use]
    pub fn json_rpc_code(&self) -> i64 {
        match self {
            Self::InvalidJson(_) | Self::MalformedJsonRpc { .. } => -32_700, // Parse error
            Self::UnknownMethod { .. } => -32_601,                            // Method not found
            Self::GuardrailViolation { .. } | Self::Unauthorized(_) => -32_003, // Custom: blocked
            Self::WasmRuntime(_) => -32_004,                                  // Custom: WASM error
            Self::Io(_) | Self::Other(_) => -32_603,                          // Internal error
        }
    }

    /// Returns `true` if this error should be reported to the client as a structured JSON-RPC
    /// error response rather than closing the connection abruptly.
    #[must_use]
    pub fn is_protocol_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidJson(_)
                | Self::MalformedJsonRpc { .. }
                | Self::UnknownMethod { .. }
                | Self::GuardrailViolation { .. }
                | Self::Unauthorized(_)
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_method_code() {
        let err = AegisError::UnknownMethod {
            method: "tools/foobar".into(),
        };
        assert_eq!(err.json_rpc_code(), -32_601);
        assert!(err.is_protocol_error());
    }

    #[test]
    fn io_error_not_protocol() {
        let err = AegisError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe"));
        assert_eq!(err.json_rpc_code(), -32_603);
        assert!(!err.is_protocol_error());
    }
}
