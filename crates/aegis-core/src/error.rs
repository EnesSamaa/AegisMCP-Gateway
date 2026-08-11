//! Extensible domain error hierarchy for AegisMCP-Gateway.
//!
//! Provides [`McpError`] (also aliased as [`AegisError`] and [`AegisCoreError`])
//! which covers protocol violations, MCP security violations, proxy/transport
//! failures, and internal system errors, with automated conversion into
//! standard JSON-RPC error objects [`JsonRpcError`].

use crate::jsonrpc::{
    JsonRpcError, JSONRPC_INTERNAL_ERROR, JSONRPC_INVALID_PARAMS, JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND, JSONRPC_PARSE_ERROR,
};
use thiserror::Error;

/// The canonical Result type for `aegis-core` operations.
pub type Result<T, E = McpError> = std::result::Result<T, E>;

/// Alias for [`McpError`] for backward compatibility and domain ergonomics.
pub type AegisError = McpError;

/// Alias for [`McpError`] for core domain operations.
pub type AegisCoreError = McpError;

/// Extensible error enum for the AegisMCP-Gateway ecosystem.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum McpError {
    // -----------------------------------------------------------------------
    // JSON-RPC 2.0 Protocol Violations (-32700 .. -32603)
    // -----------------------------------------------------------------------
    /// Invalid JSON payload received by server (-32700).
    #[error("Parse error: {0}")]
    ParseError(String),

    /// The JSON sent is not a valid Request object (-32600).
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// The method does not exist or is not available (-32601).
    #[error("Method not found: '{0}'")]
    MethodNotFound(String),

    /// Invalid method parameter(s) (-32602).
    #[error("Invalid params: {0}")]
    InvalidParams(String),

    /// Internal JSON-RPC error (-32603).
    #[error("Internal error: {0}")]
    InternalError(String),

    // -----------------------------------------------------------------------
    // MCP Security Errors (-32001 .. -32009)
    // -----------------------------------------------------------------------
    /// Unauthorized tool call attempt (-32001).
    #[error("Unauthorized tool call to '{tool_name}': {reason}")]
    UnauthorizedToolCall {
        /// Name of the unauthorized tool.
        tool_name: String,
        /// Reason for denial.
        reason: String,
    },

    /// PII data violation detected in payload (-32002).
    #[error("PII violation triggered by rule '{rule}': {detail}")]
    PiiViolation {
        /// Rule name that triggered.
        rule: String,
        /// Explanation details.
        detail: String,
    },

    /// Prompt injection or malicious pattern detected (-32003).
    #[error("Injection detected ({threat_type}): {detail}")]
    InjectionDetected {
        /// Category of threat detected.
        threat_type: String,
        /// Threat detail.
        detail: String,
    },

    /// Rate limit exceeded for caller (-32004).
    #[error("Rate limit of {limit} req/s exceeded; retry in {reset_seconds}s")]
    RateLimitExceeded {
        /// Permitted request rate limit.
        limit: u32,
        /// Seconds until limit reset.
        reset_seconds: u32,
    },

    // -----------------------------------------------------------------------
    // Upstream Proxy & Transport Failures (-32010 .. -32019)
    // -----------------------------------------------------------------------
    /// Upstream target server is unreachable (-32010).
    #[error("Upstream server unreachable at '{uri}': {detail}")]
    UpstreamUnreachable {
        /// Target URI.
        uri: String,
        /// Cause details.
        detail: String,
    },

    /// Upstream request timed out (-32011).
    #[error("Upstream request to '{uri}' timed out after {timeout_ms}ms")]
    UpstreamTimeout {
        /// Target URI.
        uri: String,
        /// Timeout duration in milliseconds.
        timeout_ms: u64,
    },

    /// Bad Gateway / invalid response from upstream (-32012).
    #[error("Bad gateway: {message}")]
    BadGateway {
        /// Error description.
        message: String,
    },

    // -----------------------------------------------------------------------
    // Conversion & Infrastructure Wrappers
    // -----------------------------------------------------------------------
    /// Serde JSON error wrapper.
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    /// I/O error wrapper.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Transparent fallback for third-party anyhow errors.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl McpError {
    /// Returns the JSON-RPC error code associated with this error variant.
    #[must_use]
    pub const fn code(&self) -> i64 {
        match self {
            Self::ParseError(_) | Self::Json(_) => JSONRPC_PARSE_ERROR,
            Self::InvalidRequest(_) => JSONRPC_INVALID_REQUEST,
            Self::MethodNotFound(_) => JSONRPC_METHOD_NOT_FOUND,
            Self::InvalidParams(_) => JSONRPC_INVALID_PARAMS,
            Self::InternalError(_) | Self::Io(_) | Self::Other(_) => JSONRPC_INTERNAL_ERROR,

            Self::UnauthorizedToolCall { .. } => -32_001,
            Self::PiiViolation { .. } => -32_002,
            Self::InjectionDetected { .. } => -32_003,
            Self::RateLimitExceeded { .. } => -32_004,

            Self::UpstreamUnreachable { .. } => -32_010,
            Self::UpstreamTimeout { .. } => -32_011,
            Self::BadGateway { .. } => -32_012,
        }
    }

    /// Converts this domain error into a standard [`JsonRpcError`] object.
    #[must_use]
    pub fn to_json_rpc_error(&self) -> JsonRpcError {
        JsonRpcError::new(self.code(), self.to_string())
    }

    /// Returns `true` if this error represents a protocol-level violation.
    #[must_use]
    pub const fn is_protocol_error(&self) -> bool {
        matches!(
            self,
            Self::ParseError(_)
                | Self::InvalidRequest(_)
                | Self::MethodNotFound(_)
                | Self::InvalidParams(_)
                | Self::InternalError(_)
                | Self::Json(_)
        )
    }

    /// Returns `true` if this error represents a security enforcement policy block.
    #[must_use]
    pub const fn is_security_error(&self) -> bool {
        matches!(
            self,
            Self::UnauthorizedToolCall { .. }
                | Self::PiiViolation { .. }
                | Self::InjectionDetected { .. }
                | Self::RateLimitExceeded { .. }
        )
    }

    /// Returns `true` if this error represents an upstream proxy transport failure.
    #[must_use]
    pub const fn is_upstream_error(&self) -> bool {
        matches!(
            self,
            Self::UpstreamUnreachable { .. }
                | Self::UpstreamTimeout { .. }
                | Self::BadGateway { .. }
        )
    }
}

impl From<McpError> for JsonRpcError {
    fn from(err: McpError) -> Self {
        err.to_json_rpc_error()
    }
}

impl From<&McpError> for JsonRpcError {
    fn from(err: &McpError) -> Self {
        err.to_json_rpc_error()
    }
}
