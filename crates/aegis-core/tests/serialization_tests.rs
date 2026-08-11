#![allow(missing_docs)]

use aegis_core::{
    AgentIdentity, InitializeParams, InitializeResult, JsonRpcId, JsonRpcNotification,
    JsonRpcRequest, JsonRpcResponse, McpSessionContext, SessionId, ToolCall,
    ToolContent, ToolDefinition, ToolInputSchema, ToolResult,
};
use serde_json::json;

#[test]
fn test_jsonrpc_request_serialization_string_id() {
    let req = JsonRpcRequest::new(
        "tools/call",
        Some(json!({
            "name": "fetch_weather",
            "arguments": { "city": "London" }
        })),
        Some(JsonRpcId::String("req-123".into())),
    );

    let json_str = serde_json::to_string(&req).expect("serialize request");
    assert!(json_str.contains(r#""jsonrpc":"2.0""#));
    assert!(json_str.contains(r#""method":"tools/call""#));
    assert!(json_str.contains(r#""id":"req-123""#));

    let parsed: JsonRpcRequest = serde_json::from_str(&json_str).expect("deserialize request");
    assert_eq!(parsed.id, Some(JsonRpcId::String("req-123".into())));
    assert_eq!(parsed.method, "tools/call");
}

#[test]
fn test_jsonrpc_request_serialization_number_id() {
    let raw = r#"{"jsonrpc":"2.0","method":"tools/list","id":42}"#;
    let parsed: JsonRpcRequest = serde_json::from_str(raw).expect("parse numeric id request");
    assert_eq!(parsed.id, Some(JsonRpcId::Number(42)));
    assert!(!parsed.is_notification());
}

#[test]
fn test_jsonrpc_notification_has_no_id() {
    let notif = JsonRpcNotification::new(
        "notifications/tools/list_changed",
        Some(json!({"reason": "updated"})),
    );
    let json_str = serde_json::to_string(&notif).expect("serialize notification");
    assert!(!json_str.contains(r#""id""#));

    let req_parsed: JsonRpcRequest =
        serde_json::from_str(&json_str).expect("parse notification as request");
    assert!(req_parsed.is_notification());
}

#[test]
fn test_jsonrpc_response_success_and_error() {
    let success = JsonRpcResponse::success(JsonRpcId::Number(1), json!({"status": "ok"}));
    assert!(!success.is_error());

    let json_success = serde_json::to_string(&success).expect("serialize success response");
    assert!(json_success.contains(r#""result":{"status":"ok"}"#));

    let error_resp = JsonRpcResponse::error(
        JsonRpcId::String("err-id".into()),
        aegis_core::JsonRpcError::new(-32601, "Method not found"),
    );
    assert!(error_resp.is_error());

    let json_error = serde_json::to_string(&error_resp).expect("serialize error response");
    assert!(json_error.contains(r#""code":-32601"#));
}

#[test]
fn test_mcp_tool_call_and_result_roundtrip() {
    let tool_call = ToolCall::new("query_database", Some(json!({"sql": "SELECT 1"})));
    let json_val = serde_json::to_value(&tool_call).expect("to_value");
    assert_eq!(json_val["name"], "query_database");

    let result = ToolResult::text("Execution successful");
    let res_json = serde_json::to_string(&result).expect("serialize ToolResult");
    assert!(res_json.contains(r#""type":"text""#));
    assert!(res_json.contains("Execution successful"));

    let res_parsed: ToolResult = serde_json::from_str(&res_json).expect("deserialize ToolResult");
    assert_eq!(res_parsed.content.len(), 1);
    assert_eq!(res_parsed.is_error, None);
}

#[test]
fn test_mcp_tool_error_result() {
    let err_result = ToolResult::error("Access denied");
    let json_str = serde_json::to_string(&err_result).expect("serialize error result");
    assert!(json_str.contains(r#""is_error":true"#));

    let parsed: ToolResult = serde_json::from_str(&json_str).expect("deserialize error result");
    assert_eq!(parsed.is_error, Some(true));
}

#[test]
fn test_mcp_tool_content_variants() {
    let text = ToolContent::text("hello world");
    let img = ToolContent::image("aW1hZ2VkYXRh", "image/png");

    let text_json = serde_json::to_string(&text).expect("serialize text");
    assert!(text_json.contains(r#""type":"text""#));

    let img_json = serde_json::to_string(&img).expect("serialize img");
    assert!(img_json.contains(r#""mime_type":"image/png""#));
}

#[test]
fn test_tool_definition_serialization() {
    let schema = ToolInputSchema {
        schema_type: "object".into(),
        properties: Some(json!({
            "location": { "type": "string", "description": "City name" }
        })),
        required: Some(vec!["location".into()]),
    };

    let def = ToolDefinition::new("weather", Some("Get current weather".into()), schema);
    let serialized = serde_json::to_string(&def).expect("serialize ToolDefinition");
    let parsed: ToolDefinition = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(parsed.name, "weather");
    assert_eq!(parsed.input_schema.required.unwrap(), vec!["location"]);
}

#[test]
fn test_agent_identity_and_session_context() {
    let identity = AgentIdentity::new("client-007", "SecAgent", "auditor")
        .with_tenant_id("tenant-42")
        .with_permission("tools:read")
        .with_permission("tools:execute");

    assert!(identity.has_permission("tools:read"));
    assert!(!identity.has_permission("admin:all"));

    let session = McpSessionContext::new(SessionId::new(), identity, 1_700_000_000_000);
    let serialized = serde_json::to_string(&session).expect("serialize session");
    let parsed: McpSessionContext =
        serde_json::from_str(&serialized).expect("deserialize session");

    assert_eq!(parsed.identity.client_id, "client-007");
    assert_eq!(parsed.identity.tenant_id, Some("tenant-42".into()));
}

#[test]
fn test_initialize_handshake_roundtrip() {
    let init_params_json = json!({
        "protocolVersion": "2024-11-05",
        "clientInfo": {
            "name": "TestClient",
            "version": "1.0.0"
        },
        "capabilities": {}
    });

    let params: InitializeParams = serde_json::from_value(init_params_json).expect("parse params");
    assert_eq!(params.client_info.name, "TestClient");

    let result_json = json!({
        "protocolVersion": "2024-11-05",
        "serverInfo": {
            "name": "AegisMCP-Gateway",
            "version": "0.1.0"
        },
        "capabilities": {
            "tools": { "listChanged": true }
        }
    });

    let result: InitializeResult = serde_json::from_value(result_json).expect("parse result");
    assert_eq!(result.server_info.name, "AegisMCP-Gateway");
    assert_eq!(
        result.capabilities.tools.as_ref().unwrap().list_changed,
        Some(true)
    );
}
