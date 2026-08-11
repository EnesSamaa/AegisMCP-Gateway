//! # aegis-core
//!
//! Core data structures, types, error definitions, and JSON-RPC / MCP protocol primitives
//! for the AegisMCP-Gateway.
//!
//! This crate defines the canonical JSON-RPC 2.0 and Model Context Protocol (MCP) data models
//! used throughout the workspace. It is pure data-model library with no async or network runtime.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic, clippy::nursery)]
#![warn(missing_docs)]

pub mod error;
pub mod jsonrpc;
pub mod mcp;
pub mod types;

// Re-exports for top-level ergonomics
pub use error::{AegisCoreError, AegisError, McpError, Result};
pub use jsonrpc::{
    JsonRpcError, JsonRpcId, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse,
    JSONRPC_INTERNAL_ERROR, JSONRPC_INVALID_PARAMS, JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND, JSONRPC_PARSE_ERROR,
};
pub use mcp::{
    ClientCapabilities, ClientInfo, InitializeParams, InitializeResult, McpCapabilities,
    ServerCapabilities, ServerInfo, ToolCall, ToolContent, ToolDefinition, ToolInputSchema,
    ToolResult, MCP_PROTOCOL_VERSION,
};
pub use types::{AgentIdentity, McpSessionContext, RequestId, SessionId};
