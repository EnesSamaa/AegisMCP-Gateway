//! Model Context Protocol (MCP) data structures and protocol primitives.
//!
//! Provides typed definitions for tool calls, tool results, tool definitions,
//! schemas, capabilities, and initialize handshake messages.
//!
//! Reference: <https://modelcontextprotocol.io/specification>

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The MCP protocol version string advertised by this gateway implementation.
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

// ---------------------------------------------------------------------------
// Tool Primitives
// ---------------------------------------------------------------------------

/// A tool call invocation requested by an agent/client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    /// Name of the target tool to execute.
    pub name: String,

    /// Key-value arguments passed to the tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
}

impl ToolCall {
    /// Creates a new `ToolCall`.
    #[must_use]
    pub fn new(name: impl Into<String>, arguments: Option<Value>) -> Self {
        Self {
            name: name.into(),
            arguments,
        }
    }
}

/// Content items contained within a [`ToolResult`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToolContent {
    /// Plain text output from a tool execution.
    Text {
        /// Text string payload.
        text: String,
    },
    /// Base64 encoded image content from a tool execution.
    Image {
        /// Base64-encoded image data.
        data: String,
        /// MIME type (e.g. `"image/png"`).
        mime_type: String,
    },
    /// Embedded resource content.
    Resource {
        /// URI of the resource.
        uri: String,
        /// Optional MIME type.
        #[serde(skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
        /// Optional textual content of the resource.
        #[serde(skip_serializing_if = "Option::is_none")]
        text: Option<String>,
    },
}

impl ToolContent {
    /// Helper to construct a text content item.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text { text: text.into() }
    }

    /// Helper to construct an image content item.
    #[must_use]
    pub fn image(data: impl Into<String>, mime_type: impl Into<String>) -> Self {
        Self::Image {
            data: data.into(),
            mime_type: mime_type.into(),
        }
    }
}

/// Result returned from a tool execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolResult {
    /// Vector of content items returned by the tool.
    pub content: Vec<ToolContent>,

    /// Set to `true` if the tool execution resulted in an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

impl ToolResult {
    /// Constructs a successful tool result with a single text item.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent::text(text)],
            is_error: None,
        }
    }

    /// Constructs an error tool result with a text error description.
    #[must_use]
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent::text(message)],
            is_error: Some(true),
        }
    }
}

/// JSON Schema representation for tool input parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInputSchema {
    /// Schema type, typically `"object"`.
    #[serde(rename = "type")]
    pub schema_type: String,

    /// Property definitions object mapping field names to field schemas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<Value>,

    /// List of required property names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
}

impl Default for ToolInputSchema {
    fn default() -> Self {
        Self {
            schema_type: "object".into(),
            properties: None,
            required: None,
        }
    }
}

/// Metadata definition of an MCP tool advertised by a server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Name of the tool.
    pub name: String,

    /// Description of tool capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// JSON schema describing expected input arguments.
    pub input_schema: ToolInputSchema,
}

impl ToolDefinition {
    /// Creates a new `ToolDefinition`.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: Option<String>,
        input_schema: ToolInputSchema,
    ) -> Self {
        Self {
            name: name.into(),
            description,
            input_schema,
        }
    }
}

// ---------------------------------------------------------------------------
// Capabilities & Handshake
// ---------------------------------------------------------------------------

/// Combined capabilities container representing both client and server capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpCapabilities {
    /// Server capability options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<ServerCapabilities>,

    /// Client capability options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientCapabilities>,
}

/// Server capability descriptors.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
    /// Tools capability options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,

    /// Resources capability options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,

    /// Prompts capability options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptsCapability>,

    /// Logging capability options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging: Option<Value>,
}

/// Tools capability parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    /// Whether notifications for tool list changes are supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// Resources capability parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesCapability {
    /// Whether resource subscriptions are supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscribe: Option<bool>,

    /// Whether resource list change notifications are supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// Prompts capability parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptsCapability {
    /// Whether prompt list change notifications are supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// Client capability descriptors sent during `initialize`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientCapabilities {
    /// Experimental capabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Value>,

    /// Sampling capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling: Option<Value>,
}

/// Client information sent in the `initialize` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Client application name.
    pub name: String,

    /// Client application version.
    pub version: String,
}

/// Parameters for the `initialize` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    /// Protocol version supported by client.
    pub protocol_version: String,

    /// Client metadata info.
    pub client_info: ClientInfo,

    /// Client capability options.
    #[serde(default)]
    pub capabilities: ClientCapabilities,
}

/// Server information returned in `initialize` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    /// Server name — defaults to `"AegisMCP-Gateway"`.
    pub name: String,

    /// Server version string.
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

/// Result returned from an `initialize` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    /// Protocol version used by server.
    pub protocol_version: String,

    /// Server identity info.
    pub server_info: ServerInfo,

    /// Capabilities offered by server.
    pub capabilities: ServerCapabilities,

    /// Optional instructions for the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}
