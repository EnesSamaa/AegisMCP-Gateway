//! # aegis-wasm
//!
//! Wasmtime 47 + WASI 0.2 runtime integration for AegisMCP-Gateway.
//!
//! This crate provides the execution sandbox for WASM-compiled policy plugins
//! and host bindings for the `aegis:guardrail@0.1.0` WIT contract.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic, clippy::nursery)]
#![warn(missing_docs)]

pub mod bindings;
pub mod engine;
pub mod error;
pub mod mapping;
pub mod store;

pub use bindings::aegis::guardrail::types as wit_types;
pub use engine::WasmEngine;
pub use error::WasmError;
pub use mapping::{
    build_inspection_context, parse_guardrail_result, HostDecision, HostPolicySummary,
    HostRiskRating,
};
pub use store::{AegisStoreCtx, DEFAULT_MAX_MEMORY_BYTES};
