//! JSON-RPC 2.0 message types.
//!
//! Reference: <https://www.jsonrpc.org/specification>

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// ID
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 request identifier.
///
/// Per the spec an ID may be a string, a number, or `null` (for notifications).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcId {
    /// Numeric identifier.
    Number(i64),
    /// String identifier.
    String(String),
    /// Null — used for notifications where no response is expected.
    Null,
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 request object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Must always be `"2.0"`.
    pub jsonrpc: String,

    /// The method to be invoked.
    pub method: String,

    /// Optional structured or unstructured parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,

    /// An identifier established by the client.
    ///
    /// If `None`, the request is treated as a notification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<JsonRpcId>,
}

impl JsonRpcRequest {
    /// Returns `true` if this request is a notification (i.e., no `id`).
    #[must_use]
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    /// Validates the `jsonrpc` version field.
    #[must_use]
    pub fn is_valid_version(&self) -> bool {
        self.jsonrpc == "2.0"
    }
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 response object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Must always be `"2.0"`.
    pub jsonrpc: String,

    /// The result value if the call succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,

    /// The error object if the call failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,

    /// Must mirror the `id` from the corresponding request.
    pub id: JsonRpcId,
}

impl JsonRpcResponse {
    /// Construct a successful response.
    #[must_use]
    pub fn success(id: JsonRpcId, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Construct an error response.
    #[must_use]
    pub fn error(id: JsonRpcId, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

// ---------------------------------------------------------------------------
// Error object
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 error object embedded in a [`JsonRpcResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// A number that indicates the error type.
    pub code: i64,

    /// A short description of the error.
    pub message: String,

    /// Additional data about the error (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// Create a new `JsonRpcError`.
    #[must_use]
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Attach extra `data` to this error.
    #[must_use]
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
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
