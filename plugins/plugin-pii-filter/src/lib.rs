//! WASI 0.2 PII (Personally Identifiable Information) Guardrail Plugin.

#![allow(clippy::all, clippy::pedantic, clippy::nursery, unsafe_code, missing_docs)]

wit_bindgen::generate!({
    world: "guardrail-policy",
    path: "../../wit",
});

use aegis::guardrail::types::{PolicyDecision, ViolationRisk};
use exports::aegis::guardrail::inspector::{GuardrailResult, Guest, InspectionContext};

pub struct PiiFilterPlugin;

impl Guest for PiiFilterPlugin {
    fn inspect(ctx: InspectionContext) -> GuardrailResult {
        let start = std::time::Instant::now();
        let payload = &ctx.arguments_json;

        let cc_pattern = r"\b(?:\d[ -]*?){13,16}\b";
        let email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b";
        let api_key_pattern = r"(sk_test_[0-9a-zA-Z]{24,}|ghp_[0-9a-zA-Z]{36}|Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*)";

        let cc_regex = regex::Regex::new(cc_pattern).expect("Valid CC regex");
        let email_regex = regex::Regex::new(email_pattern).expect("Valid email regex");
        let api_key_regex = regex::Regex::new(api_key_pattern).expect("Valid API key regex");

        let mut matched_pii = Vec::new();

        if cc_regex.is_match(payload) {
            matched_pii.push("Credit Card Number");
        }
        if email_regex.is_match(payload) {
            matched_pii.push("Email Address");
        }
        if api_key_regex.is_match(payload) {
            matched_pii.push("API Key / Secret Token");
        }

        let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);

        if matched_pii.is_empty() {
            GuardrailResult {
                decision: PolicyDecision::Allow,
                risk: ViolationRisk::Low,
                execution_time_us: elapsed_us,
                metadata: vec![("pii_status".to_string(), "clean".to_string())],
            }
        } else {
            let reason = format!("PII payload detected: {}", matched_pii.join(", "));
            let is_critical = matched_pii.contains(&"Credit Card Number")
                || matched_pii.contains(&"API Key / Secret Token");

            GuardrailResult {
                decision: PolicyDecision::Deny(reason),
                risk: if is_critical {
                    ViolationRisk::Critical
                } else {
                    ViolationRisk::High
                },
                execution_time_us: elapsed_us,
                metadata: vec![
                    ("pii_status".to_string(), "detected".to_string()),
                    ("pii_matches".to_string(), matched_pii.join(", ")),
                ],
            }
        }
    }
}

export!(PiiFilterPlugin);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pii_detection_clean_payload() {
        let ctx = InspectionContext {
            request_id: "req-1".to_string(),
            session_id: "sess-1".to_string(),
            agent_role: "analyst".to_string(),
            tool_name: "sql_query".to_string(),
            arguments_json: r#"{"query":"SELECT * FROM users WHERE active = true"}"#.to_string(),
            metadata: vec![],
        };

        let res = PiiFilterPlugin::inspect(ctx);
        assert!(matches!(res.decision, PolicyDecision::Allow));
        assert!(matches!(res.risk, ViolationRisk::Low));
    }

    #[test]
    fn test_pii_detection_credit_card() {
        let ctx = InspectionContext {
            request_id: "req-2".to_string(),
            session_id: "sess-2".to_string(),
            agent_role: "billing".to_string(),
            tool_name: "payment_process".to_string(),
            arguments_json: r#"{"card":"4532-1122-3344-5566"}"#.to_string(),
            metadata: vec![],
        };

        let res = PiiFilterPlugin::inspect(ctx);
        assert!(matches!(res.decision, PolicyDecision::Deny(_)));
        assert!(matches!(res.risk, ViolationRisk::Critical));
    }

    #[test]
    fn test_pii_detection_api_key() {
        let ctx = InspectionContext {
            request_id: "req-3".to_string(),
            session_id: "sess-3".to_string(),
            agent_role: "devops".to_string(),
            tool_name: "deploy_service".to_string(),
            arguments_json: r#"{"token":"sk_test_mock_token_000000000000000000000000"}"#.to_string(),
            metadata: vec![],
        };

        let res = PiiFilterPlugin::inspect(ctx);
        assert!(matches!(res.decision, PolicyDecision::Deny(_)));
        assert!(matches!(res.risk, ViolationRisk::Critical));
    }
}
