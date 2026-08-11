//! # aegis-guardrails
//!
//! Content-inspection engine for AegisMCP-Gateway.
//!
//! This crate provides the rule-evaluation pipeline that sits on the hot path
//! for every proxied request and response.  Rules are composable, cheap to
//! clone, and evaluated in priority order.
//!
//! ## Module organisation
//!
//! ```text
//! aegis-guardrails
//! ├── engine  — rule registry and evaluation loop
//! ├── error   — guardrail-specific error types
//! ├── matcher — regex-based and structural matchers
//! └── rule    — rule definitions and action types
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic, clippy::nursery)]
#![warn(missing_docs)]

pub mod engine;
pub mod error;
pub mod matcher;
pub mod rule;

pub use engine::GuardrailEngine;
pub use error::GuardrailError;
pub use rule::{Action, Rule, RuleId};
