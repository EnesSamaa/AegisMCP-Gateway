#![allow(missing_docs)]

use aegis_core::{AgentIdentity, McpSessionContext, RequestId, SessionId, ToolCall};
use aegis_wasm::{
    build_inspection_context, parse_guardrail_result, wit_types, HostDecision, HostRiskRating,
    WasmEngine,
};

#[test]
fn test_wasm_engine_component_configuration() {
    let engine = WasmEngine::new().expect("WasmEngine initialization");
    assert!(engine.inner().precompile_module(&[]).is_err());
}

#[test]
fn test_wit_context_building_and_parsing() {
    let identity = AgentIdentity::new("agent-100", "SecBot", "analyst");
    let session = McpSessionContext::new(SessionId::new(), identity, 1_700_000_000_000);
    let req_id = RequestId::new();
    let tool_call = ToolCall::new(
        "file_read",
        Some(serde_json::json!({"path": "/etc/passwd"})),
    );

    let wit_ctx = build_inspection_context(&session, req_id, &tool_call);
    assert_eq!(wit_ctx.tool_name, "file_read");
    assert_eq!(wit_ctx.agent_role, "analyst");
    assert!(wit_ctx.arguments_json.contains("/etc/passwd"));

    // Simulate mock WASM guest result
    let mock_guest_result = wit_types::GuardrailResult {
        decision: wit_types::PolicyDecision::Deny("Access to sensitive system file blocked".into()),
        risk: wit_types::ViolationRisk::High,
        execution_time_us: 42,
        metadata: vec![("rule_id".into(), "sensitive-file-read".into())],
    };

    let summary = parse_guardrail_result(&mock_guest_result);
    assert_eq!(
        summary.decision,
        HostDecision::Deny("Access to sensitive system file blocked".into())
    );
    assert_eq!(summary.risk, HostRiskRating::High);
    assert_eq!(summary.execution_time_us, 42);
}
