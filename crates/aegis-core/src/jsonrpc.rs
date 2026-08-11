//! JSON-RPC 2.0 message types and standard constants.
//!
//! Reference: <https://modelcontextprotocol.io> and <https://www.jsonrpc.org/specification>

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Standard JSON-RPC Error Codes
// ---------------------------------------------------------------------------

/// Invalid JSON was received by the server (-32700).
pub const JSONRPC_PARSE_ERROR: i64 = -32_700;

/// The JSON sent is not a valid Request object (-32600).
pub const JSONRPC_INVALID_REQUEST: i64 = -32_600;

/// The method does not exist / is not available (-32601).
pub const JSONRPC_METHOD_NOT_FOUND: i64 = -32_601;

/// Invalid method parameter(s) (-32602).
pub const JSONRPC_INVALID_PARAMS: i64 = -32_602;

/// Internal JSON-RPC error (-32603).
pub const JSONRPC_INTERNAL_ERROR: i64 = -32_603;

// ---------------------------------------------------------------------------
// ID
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 request identifier.
///
/// Per the JSON-RPC 2.0 spec, an ID may be a String, an Integer (i64), or `Null`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcId {
    /// Numeric identifier.
    Number(i64),
    /// String identifier.
    String(String),
    /// Null — used when request ID cannot be determined or for notifications.
    Null,
}

impl JsonRpcId {
    /// Returns `true` if the ID is `Null`.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Returns the ID as a string slice if it is [`JsonRpcId::String`].
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Returns the ID as `i64` if it is [`JsonRpcId::Number`].
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }
}

impl From<i64> for JsonRpcId {
    fn from(val: i64) -> Self {
        Self::Number(val)
    }
}

impl From<String> for JsonRpcId {
    fn from(val: String) -> Self {
        Self::String(val)
    }
}

impl From<&str> for JsonRpcId {
    fn from(val: &str) -> Self {
        Self::String(val.to_owned())
    }
}

impl std::fmt::Display for JsonRpcId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Number(n) => write!(f, "{n}"),
            Self::String(s) => write!(f, "{s}"),
            Self::Null => write!(f, "null"),
        }
    }
}

// ---------------------------------------------------------------------------
// Request & Notification
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 request object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Protocol version — must be `"2.0"`.
    pub jsonrpc: String,

    /// The name of the method to be invoked.
    pub method: String,

    /// Parameter values to pass during method invocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,

    /// An identifier established by the client.
    /// If omitted or `None`, this request is a notification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<JsonRpcId>,
}

impl JsonRpcRequest {
    /// Creates a new `JsonRpcRequest` with `"2.0"` protocol version.
    #[must_use]
    pub fn new(method: impl Into<String>, params: Option<Value>, id: Option<JsonRpcId>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
            id,
        }
    }

    /// Creates a new `JsonRpcRequest` representing a notification (no `id`).
    #[must_use]
    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        Self::new(method, params, None)
    }

    /// Returns `true` if this request is a notification (i.e. `id` is `None`).
    #[must_use]
    pub const fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    /// Returns `true` if `jsonrpc == "2.0"`.
    #[must_use]
    pub fn is_valid_version(&self) -> bool {
        self.jsonrpc == "2.0"
    }
}

/// A dedicated JSON-RPC 2.0 notification object (strictly without an `id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    /// Protocol version — must be `"2.0"`.
    pub jsonrpc: String,

    /// The method name.
    pub method: String,

    /// Optional notification parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcNotification {
    /// Creates a new `JsonRpcNotification`.
    #[must_use]
    pub fn new(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
        }
    }
}

// ---------------------------------------------------------------------------
// Response & Error Object
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 response object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Protocol version — must be `"2.0"`.
    pub jsonrpc: String,

    /// Result payload if call succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,

    /// Error object if call failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,

    /// The request ID that this response corresponds to.
    pub id: JsonRpcId,
}

impl JsonRpcResponse {
    /// Constructs a successful JSON-RPC response.
    #[must_use]
    pub fn success(id: JsonRpcId, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Constructs an error JSON-RPC response.
    #[must_use]
    pub fn error(id: JsonRpcId, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(error),
            id,
        }
    }

    /// Returns `true` if this response contains an error.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

/// A JSON-RPC 2.0 error object embedded within a [`JsonRpcResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code integer.
    pub code: i64,

    /// Short human-readable error message.
    pub message: String,

    /// Additional structured error data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// Creates a new `JsonRpcError`.
    #[must_use]
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Attaches additional structured data to the error.
    #[must_use]
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trip_request() {
        let raw = json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 42
        });
        let req: JsonRpcRequest = serde_json::from_value(raw).expect("deserialise request");
        assert_eq!(req.method, "tools/list");
        assert!(req.is_valid_version());
        assert!(!req.is_notification());
    }

    #[test]
    fn notification_has_no_id() {
        let raw = json!({
            "jsonrpc": "2.0",
            "method": "$/progress",
        });
        let req: JsonRpcRequest = serde_json::from_value(raw).expect("deserialise notification");
        assert!(req.is_notification());
    }

    #[test]
    fn success_response_serialises() {
        let resp = JsonRpcResponse::success(JsonRpcId::Number(1), json!({"status": "ok"}));
        let val = serde_json::to_value(&resp).expect("serialise");
        assert_eq!(val["jsonrpc"], "2.0");
        assert_eq!(val["result"]["status"], "ok");
        assert!(val.get("error").is_none());
    }
}
