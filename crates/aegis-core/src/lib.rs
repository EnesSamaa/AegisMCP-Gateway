//! # aegis-core
//!
//! Core data structures, types, and error definitions for the AegisMCP-Gateway.
//!
//! This crate defines the canonical JSON-RPC 2.0 / MCP protocol primitives that every
//! other crate in the workspace depends on.  It purposefully has **no I/O**, **no async
//! runtime**, and **no network** dependencies — it is a pure data-model library.
//!
//! ## Module organisation
//!
//! ```text
//! aegis-core
//! ├── error   — unified error type hierarchy via `thiserror`
//! ├── jsonrpc — JSON-RPC 2.0 request / response / notification types
//! ├── mcp     — Model Context Protocol message extensions
//! └── types   — shared primitive type aliases and newtypes
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic, clippy::nursery)]
#![warn(missing_docs)]

pub mod error;
pub mod jsonrpc;
pub mod mcp;
pub mod types;

// ---------------------------------------------------------------------------
// Re-export the most-used items at crate root for ergonomics
// ---------------------------------------------------------------------------
pub use error::{AegisError, Result};
pub use jsonrpc::{JsonRpcId, JsonRpcRequest, JsonRpcResponse};
pub use types::{RequestId, SessionId};
