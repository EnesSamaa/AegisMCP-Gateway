#![allow(missing_docs)]

use aegis_core::ToolCall;
use aegis_guardrails::{ApprovalDecision, HitlApprovalEngine};
use std::time::Duration;

#[tokio::test]
async fn test_hitl_approval_granted_resumes_execution() {
    let hitl = HitlApprovalEngine::new();
    hitl.register_high_risk_pattern("db.drop_*").await;

    assert!(hitl.is_high_risk("db.drop_table").await);
    assert!(!hitl.is_high_risk("db.select").await);

    let tool_call = ToolCall::new("db.drop_table", None);

    let (req_id, rx) = hitl.submit_for_approval(&tool_call).await;

    let hitl_clone = hitl.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        hitl_clone
            .resolve_approval(req_id, ApprovalDecision::Approved)
            .await
            .expect("Resolution succeeded");
    });

    let decision = rx.await.expect("Received decision");
    assert_eq!(decision, ApprovalDecision::Approved);
}

#[tokio::test]
async fn test_hitl_approval_rejected_returns_reason() {
    let hitl = HitlApprovalEngine::new();
    let tool_call = ToolCall::new("cloud.delete_instance", None);

    let (req_id, rx) = hitl.submit_for_approval(&tool_call).await;

    let hitl_clone = hitl.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        hitl_clone
            .resolve_approval(
                req_id,
                ApprovalDecision::Rejected("High Risk Operation".to_string()),
            )
            .await
            .expect("Resolution succeeded");
    });

    let decision = rx.await.expect("Received decision");
    assert_eq!(
        decision,
        ApprovalDecision::Rejected("High Risk Operation".to_string())
    );
}

#[tokio::test]
async fn test_hitl_approval_timeout_auto_rejects() {
    let hitl = HitlApprovalEngine::new();
    let tool_call = ToolCall::new("cloud.delete_instance", None);

    let (_, decision) = hitl
        .request_approval(&tool_call, Some(Duration::from_millis(50)))
        .await
        .expect("Approval task succeeded");

    assert!(matches!(
        decision,
        ApprovalDecision::Rejected(reason) if reason.contains("Timed Out")
    ));
}
