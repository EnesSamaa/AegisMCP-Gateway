//! Error types for the `aegis-guardrails` crate.

use thiserror::Error;

/// Errors emitted by the guardrail inspection engine and identity translator.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GuardrailError {
    /// A rule pattern failed to compile as a valid regex.
    #[error("invalid regex pattern: {0}")]
    InvalidPattern(String),

    /// The rule registry contains a duplicate rule ID.
    #[error("duplicate rule ID '{0}' — rule IDs must be unique")]
    DuplicateRuleId(String),

    /// The engine received a payload that could not be deserialised.
    #[error("payload deserialisation failed: {0}")]
    InvalidPayload(String),

    /// Authentication header extraction or JWT validation failed.
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Token translation mapping failed or token expired.
    #[error("Token translation failed: {0}")]
    TokenTranslationFailed(String),
}
