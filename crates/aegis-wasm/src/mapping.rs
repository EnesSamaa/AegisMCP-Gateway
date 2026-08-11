//! Domain type mapping between `aegis-core` and WIT host bindings.

use crate::bindings::aegis::guardrail::types as wit_types;
use aegis_core::{McpSessionContext, RequestId, ToolCall};
use std::collections::HashMap;

/// Convert `aegis-core` session context and tool invocation into a WIT [`wit_types::InspectionContext`].
#[must_use]
pub fn build_inspection_context(
    session: &McpSessionContext,
    request_id: RequestId,
    tool_call: &ToolCall,
) -> wit_types::InspectionContext {
    let arguments_json = tool_call
        .arguments
        .as_ref()
        .map_or_else(|| "{}".to_string(), ToString::to_string);

    let metadata = session
        .metadata
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    wit_types::InspectionContext {
        request_id: request_id.to_string(),
        session_id: session.session_id.to_string(),
        agent_role: session.identity.role.clone(),
        tool_name: tool_call.name.clone(),
        arguments_json,
        metadata,
    }
}

/// Host-side summary of an evaluated WASM policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPolicySummary {
    /// Decision outcome (allowed, denied with reason, modified with new JSON).
    pub decision: HostDecision,
    /// Assessed risk rating.
    pub risk: HostRiskRating,
    /// Plugin execution time in microseconds.
    pub execution_time_us: u64,
    /// Key-value metadata returned by plugin.
    pub metadata: HashMap<String, String>,
}

/// Decision outcome mapped to host domain types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostDecision {
    /// Request passed inspection.
    Allow,
    /// Request blocked with denial explanation.
    Deny(String),
    /// Request allowed with sanitized/modified JSON payload string.
    Modify(String),
}

/// Risk level rating mapped to host domain types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRiskRating {
    /// Low risk.
    Low,
    /// Medium risk.
    Medium,
    /// High risk.
    High,
    /// Critical risk.
    Critical,
}

impl From<&wit_types::PolicyDecision> for HostDecision {
    fn from(val: &wit_types::PolicyDecision) -> Self {
        match val {
            wit_types::PolicyDecision::Allow => Self::Allow,
            wit_types::PolicyDecision::Deny(reason) => Self::Deny(reason.clone()),
            wit_types::PolicyDecision::Modify(new_payload) => Self::Modify(new_payload.clone()),
        }
    }
}

impl From<wit_types::ViolationRisk> for HostRiskRating {
    fn from(val: wit_types::ViolationRisk) -> Self {
        match val {
            wit_types::ViolationRisk::Low => Self::Low,
            wit_types::ViolationRisk::Medium => Self::Medium,
            wit_types::ViolationRisk::High => Self::High,
            wit_types::ViolationRisk::Critical => Self::Critical,
        }
    }
}

/// Convert a WIT [`wit_types::GuardrailResult`] into a [`HostPolicySummary`].
#[must_use]
pub fn parse_guardrail_result(result: &wit_types::GuardrailResult) -> HostPolicySummary {
    let metadata = result.metadata.iter().cloned().collect();

    HostPolicySummary {
        decision: HostDecision::from(&result.decision),
        risk: HostRiskRating::from(result.risk),
        execution_time_us: result.execution_time_us,
        metadata,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{AgentIdentity, SessionId};

    #[test]
    fn test_build_inspection_context() {
        let identity = AgentIdentity::new("client-1", "AgentAlpha", "admin");
        let session = McpSessionContext::new(SessionId::new(), identity, 1_700_000_000_000);
        let req_id = RequestId::new();
        let tool_call = ToolCall::new("sql_query", Some(serde_json::json!({"query": "SELECT 1"})));

        let ctx = build_inspection_context(&session, req_id, &tool_call);
        assert_eq!(ctx.tool_name, "sql_query");
        assert_eq!(ctx.agent_role, "admin");
        assert!(ctx.arguments_json.contains("SELECT 1"));
    }

    #[test]
    fn test_parse_guardrail_result() {
        let wit_result = wit_types::GuardrailResult {
            decision: wit_types::PolicyDecision::Deny("SQL Injection attempt".into()),
            risk: wit_types::ViolationRisk::Critical,
            execution_time_us: 150,
            metadata: vec![("rule_id".into(), "sql-inject-block".into())],
        };

        let host_summary = parse_guardrail_result(&wit_result);
        assert_eq!(
            host_summary.decision,
            HostDecision::Deny("SQL Injection attempt".into())
        );
        assert_eq!(host_summary.risk, HostRiskRating::Critical);
        assert_eq!(host_summary.execution_time_us, 150);
        assert_eq!(
            host_summary.metadata.get("rule_id").map(String::as_str),
            Some("sql-inject-block")
        );
    }
}
