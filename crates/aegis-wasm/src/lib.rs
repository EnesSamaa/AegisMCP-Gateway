//! # aegis-wasm
//!
//! Wasmtime 47 + WASI 0.2 runtime integration for AegisMCP-Gateway.
//!
//! This crate provides the execution sandbox for WASM-compiled policy plugins.
//! Each plugin is a `.wasm` component that implements the `aegis:policy/inspect`
//! WIT interface (to be defined in a later milestone).
//!
//! ## Status — Day 1 Stub
//!
//! The public API surface is declared here so that other workspace crates can
//! depend on `aegis-wasm` without causing compile errors.  The actual
//! Wasmtime engine instantiation and component linking will be implemented on
//! Day 4 of the roadmap.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic, clippy::nursery)]
#![warn(missing_docs)]

pub mod engine;
pub mod error;

pub use engine::WasmEngine;
pub use error::WasmError;
