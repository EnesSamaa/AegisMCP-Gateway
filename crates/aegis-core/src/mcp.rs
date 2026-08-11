//! Model Context Protocol (MCP) message extensions.
//!
//! The MCP spec layers additional message types on top of JSON-RPC 2.0.
//! This module provides the typed representations of those extensions.
//!
//! Reference: <https://modelcontextprotocol.io/specification>

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// MCP protocol version
// ---------------------------------------------------------------------------

/// The MCP protocol version string advertised by this gateway implementation.
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/// Capabilities that the server (gateway) advertises to clients.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
    /// `tools` capability — present if the server supports tool invocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,

    /// `resources` capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,

    /// `prompts` capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptsCapability>,

    /// `logging` capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging: Option<Value>,
}

/// Server-side tools capability descriptor.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    /// Whether the server supports `notifications/tools/list_changed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// Server-side resources capability descriptor.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesCapability {
    /// Whether resource subscriptions are supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscribe: Option<bool>,

    /// Whether list-change notifications are supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// Server-side prompts capability descriptor.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptsCapability {
    /// Whether list-change notifications are supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

// ---------------------------------------------------------------------------
// Initialize handshake
// ---------------------------------------------------------------------------

/// Parameters for the `initialize` request sent by the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    /// The MCP protocol version the client supports.
    pub protocol_version: String,

    /// Human-readable client information.
    pub client_info: ClientInfo,

    /// Capabilities the client advertises.
    #[serde(default)]
    pub capabilities: ClientCapabilities,
}

/// Client identification metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Client application name.
    pub name: String,

    /// Client application version string.
    pub version: String,
}

/// Capabilities the client advertises during `initialize`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientCapabilities {
    /// Experimental capability extensions (opaque).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Value>,

    /// Sampling capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling: Option<Value>,
}

/// The server's response to an `initialize` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    /// The MCP protocol version this server implements.
    pub protocol_version: String,

    /// Human-readable server information.
    pub server_info: ServerInfo,

    /// Server capability advertisement.
    pub capabilities: ServerCapabilities,

    /// Optional human-readable instructions sent to the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

/// Gateway server identification metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    /// Server name — always `"AegisMCP-Gateway"`.
    pub name: String,

    /// Crate version, set from `CARGO_PKG_VERSION`.
    pub version: String,
}

impl Default for ServerInfo {
    fn default() -> Self {
        Self {
            name: "AegisMCP-Gateway".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}
