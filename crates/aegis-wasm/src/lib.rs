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
pub mod hotswap;
pub mod linker;
pub mod loader;
pub mod mapping;
pub mod metadata;
pub mod pool;
pub mod runner;
pub mod security;
pub mod store;

pub use bindings::aegis::guardrail::types as wit_types;
pub use engine::WasmEngine;
pub use error::WasmError;
pub use hotswap::PluginHotSwapper;
pub use linker::WasmLinker;
pub use loader::ComponentLoader;
pub use mapping::{
    build_inspection_context, parse_guardrail_result, HostDecision, HostPolicySummary,
    HostRiskRating,
};
pub use metadata::PluginMetadata;
pub use pool::{PoolConfig, PooledInstance, PooledInstanceGuard, WasmInstancePool};
pub use runner::PluginRunner;
pub use security::verify_plugin_signature;
pub use store::{AegisStoreCtx, DEFAULT_MAX_MEMORY_BYTES};
