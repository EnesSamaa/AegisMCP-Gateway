//! # aegis-guardrails
//!
//! Content-inspection engine for AegisMCP-Gateway.
//!
//! This crate provides the rule-evaluation pipeline that sits on the hot path
//! for every proxied request and response. Rules are composable, cheap to
//! clone, and evaluated in priority order.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic, clippy::nursery)]
#![warn(missing_docs)]

pub mod engine;
pub mod error;
pub mod identity;
pub mod matcher;
pub mod rule;
pub mod token_translation;

pub use engine::GuardrailEngine;
pub use error::GuardrailError;
pub use identity::{AgentJwtClaims, IdentityContext, IdentityExtractor};
pub use rule::{Action, Rule, RuleId};
pub use token_translation::{TokenTranslator, UpstreamCredential};
