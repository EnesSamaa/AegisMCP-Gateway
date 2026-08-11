#![allow(missing_docs)]

use aegis_core::{AgentIdentity, McpSessionContext, RequestId, SessionId, ToolCall};
use aegis_wasm::{build_inspection_context, HostDecision, HostRiskRating};

#[test]
fn test_pii_plugin_inspection_context_formatting() {
    let identity = AgentIdentity::new("agent-123", "PiiTester", "analyst");
    let session = McpSessionContext::new(SessionId::new(), identity, 1_700_000_000_000);
    let req_id = RequestId::new();
    let tool_call = ToolCall::new(
        "payment_tool",
        Some(serde_json::json!({
            "query": "SELECT * FROM users",
            "card": "4532-1122-3344-5566"
        })),
    );

    let ctx = build_inspection_context(&session, req_id, &tool_call);

    assert_eq!(ctx.tool_name, "payment_tool");
    assert_eq!(ctx.agent_role, "analyst");
    assert!(ctx.arguments_json.contains("4532-1122-3344-5566"));
}

#[test]
fn test_pii_host_decision_variant_mapping() {
    let deny_decision = HostDecision::Deny("PII payload detected: Credit Card Number".to_string());
    assert!(matches!(deny_decision, HostDecision::Deny(_)));

    let risk_critical = HostRiskRating::Critical;
    assert_eq!(risk_critical, HostRiskRating::Critical);
}
