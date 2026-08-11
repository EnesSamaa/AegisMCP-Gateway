//! Rule definitions and action types for the guardrail engine.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Rule identifier
// ---------------------------------------------------------------------------

/// A unique identifier for a guardrail rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleId(String);

impl RuleId {
    /// Create a new `RuleId` from a string slug.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Return the rule ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Action
// ---------------------------------------------------------------------------

/// The action a guardrail engine takes when a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Forward the request unchanged.
    Allow,
    /// Drop the request and return an error to the client.
    Block,
    /// Redact matched content and forward the sanitised request.
    Redact,
    /// Log the event but take no other action.
    Audit,
}

// ---------------------------------------------------------------------------
// Rule
// ---------------------------------------------------------------------------

/// A single guardrail rule evaluated against inbound/outbound payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique identifier for this rule.
    pub id: RuleId,

    /// Human-readable description of what this rule detects.
    pub description: String,

    /// Evaluation priority — lower values are evaluated first.
    pub priority: u32,

    /// Whether this rule is currently active.
    pub enabled: bool,

    /// The action to take when this rule matches.
    pub action: Action,

    /// The regex pattern to match against the serialised payload.
    ///
    /// `None` means this rule always matches (catch-all).
    pub pattern: Option<String>,
}

impl Rule {
    /// Create a simple blocking rule with a regex pattern.
    #[must_use]
    pub fn block(id: impl Into<String>, description: impl Into<String>, pattern: &str) -> Self {
        Self {
            id: RuleId::new(id),
            description: description.into(),
            priority: 100,
            enabled: true,
            action: Action::Block,
            pattern: Some(pattern.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_id_display() {
        let id = RuleId::new("pii-ssn-block");
        assert_eq!(id.to_string(), "pii-ssn-block");
    }

    #[test]
    fn block_rule_default_priority() {
        let rule = Rule::block("test", "test rule", r"\bpassword\b");
        assert_eq!(rule.priority, 100);
        assert_eq!(rule.action, Action::Block);
        assert!(rule.enabled);
    }
}
