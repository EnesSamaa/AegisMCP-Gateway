#![allow(missing_docs)]

use aegis_core::{AgentIdentity, ToolCall};
use aegis_guardrails::{IdentityContext, PolicyDecision, ToolAuthorizationEngine, ToolParamPolicy};

fn make_ctx(role: &str) -> IdentityContext {
    IdentityContext {
        identity: AgentIdentity::new("agent-123", "TestAgent", role),
        tenant_id: "tenant-a".to_string(),
        permissions: vec![],
        session_scope: "session".to_string(),
        expires_at: 2_000_000_000,
    }
}

#[tokio::test]
async fn test_tool_rbac_allowed_and_denied_roles() {
    let authz = ToolAuthorizationEngine::new();

    authz.add_role_policy("admin", vec!["*".to_string()]).await;
    authz
        .add_role_policy(
            "developer",
            vec!["github.read_*".to_string(), "read_file".to_string()],
        )
        .await;

    let admin_ctx = make_ctx("admin");
    let dev_ctx = make_ctx("developer");

    let read_pr_tool = ToolCall::new("github.read_pull_request", None);
    let delete_branch_tool = ToolCall::new("github.delete_branch", None);

    // Admin allowed both
    assert_eq!(
        authz.check_authorization(&admin_ctx, &read_pr_tool).await,
        PolicyDecision::Allow
    );
    assert_eq!(
        authz
            .check_authorization(&admin_ctx, &delete_branch_tool)
            .await,
        PolicyDecision::Allow
    );

    // Developer allowed read_pr, denied delete_branch
    assert_eq!(
        authz.check_authorization(&dev_ctx, &read_pr_tool).await,
        PolicyDecision::Allow
    );
    assert!(matches!(
        authz
            .check_authorization(&dev_ctx, &delete_branch_tool)
            .await,
        PolicyDecision::Deny(_)
    ));
}

#[tokio::test]
async fn test_tool_abac_parameter_restrictions() {
    let authz = ToolAuthorizationEngine::new();

    authz
        .add_role_policy("analyst", vec!["db_query".to_string()])
        .await;

    authz
        .add_param_policy(ToolParamPolicy {
            tool_name: "db_query".to_string(),
            denied_patterns: vec![
                "DROP".to_string(),
                "DELETE".to_string(),
                "TRUNCATE".to_string(),
            ],
            required_patterns: vec!["SELECT".to_string()],
        })
        .await;

    let ctx = make_ctx("analyst");

    let safe_query = ToolCall::new(
        "db_query",
        Some(serde_json::json!({"query": "SELECT * FROM orders WHERE id = 100"})),
    );

    let malicious_query = ToolCall::new(
        "db_query",
        Some(serde_json::json!({"query": "DROP TABLE users;--"})),
    );

    assert_eq!(
        authz.check_authorization(&ctx, &safe_query).await,
        PolicyDecision::Allow
    );

    let res = authz.check_authorization(&ctx, &malicious_query).await;
    assert!(matches!(res, PolicyDecision::Deny(_)));
}
