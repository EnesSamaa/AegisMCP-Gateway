//! Rule registry and evaluation loop.

use crate::{
    error::GuardrailError,
    matcher::RegexMatcher,
    rule::{Action, Rule},
};
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// The outcome produced by the guardrail engine for a single payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The action the engine recommends.
    pub action: Action,

    /// The ID of the rule that triggered this verdict, if any.
    pub triggered_rule: Option<String>,
}

impl Verdict {
    /// A verdict that allows the request through with no rule match.
    #[must_use]
    pub const fn allow() -> Self {
        Self {
            action: Action::Allow,
            triggered_rule: None,
        }
    }

    /// Returns `true` if the action is [`Action::Block`].
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.action == Action::Block
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// The guardrail inspection engine.
///
/// Holds a sorted, compiled set of rules and evaluates them against each
/// payload in priority order.  The first rule that matches produces a
/// [`Verdict`]; if no rule matches, the payload is allowed through.
#[derive(Debug)]
pub struct GuardrailEngine {
    /// Compiled (rule metadata, regex) pairs sorted by priority ascending.
    compiled: Vec<(Rule, Option<RegexMatcher>)>,
}

impl GuardrailEngine {
    /// Construct a new engine from a vector of [`Rule`]s.
    ///
    /// Rules are sorted by `priority` (ascending) and compiled eagerly so
    /// that `inspect` is allocation-free on the hot path.
    ///
    /// # Errors
    ///
    /// Returns [`GuardrailError`] if any rule's pattern is an invalid regex
    /// or if duplicate rule IDs are detected.
    pub fn new(mut rules: Vec<Rule>) -> Result<Self, GuardrailError> {
        let mut seen = std::collections::HashSet::new();
        for rule in &rules {
            if !seen.insert(rule.id.as_str().to_owned()) {
                return Err(GuardrailError::DuplicateRuleId(rule.id.as_str().to_owned()));
            }
        }

        rules.sort_by_key(|r| r.priority);

        let compiled = rules
            .into_iter()
            .map(|rule| {
                let matcher = rule.pattern.as_deref().map(RegexMatcher::new).transpose()?;
                Ok((rule, matcher))
            })
            .collect::<Result<Vec<_>, GuardrailError>>()?;

        Ok(Self { compiled })
    }

    /// Inspect a raw payload string and return a [`Verdict`].
    ///
    /// Only enabled rules are evaluated.  The first matching rule wins.
    #[must_use]
    pub fn inspect(&self, payload: &str) -> Verdict {
        for (rule, matcher) in &self.compiled {
            if !rule.enabled {
                continue;
            }

            let matched = matcher.as_ref().is_none_or(|m| m.is_match(payload));

            if matched {
                debug!(rule_id = %rule.id, action = ?rule.action, "guardrail rule matched");
                if rule.action == Action::Block {
                    warn!(rule_id = %rule.id, "request blocked by guardrail");
                }
                return Verdict {
                    action: rule.action.clone(),
                    triggered_rule: Some(rule.id.as_str().to_owned()),
                };
            }
        }

        Verdict::allow()
    }

    /// Returns the number of rules currently registered.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.compiled.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::Rule;

    fn make_engine() -> GuardrailEngine {
        let rules = vec![Rule::block(
            "block-password",
            "Block password keyword",
            r"(?i)\bpassword\b",
        )];
        GuardrailEngine::new(rules).expect("valid engine")
    }

    #[test]
    fn clean_payload_is_allowed() {
        let engine = make_engine();
        let verdict = engine.inspect(r#"{"method":"tools/list"}"#);
        assert!(!verdict.is_blocked());
        assert_eq!(verdict.action, Action::Allow);
    }

    #[test]
    fn payload_with_password_is_blocked() {
        let engine = make_engine();
        let verdict = engine.inspect(r#"{"params":{"text":"enter password here"}}"#);
        assert!(verdict.is_blocked());
        assert_eq!(verdict.triggered_rule.as_deref(), Some("block-password"));
    }

    #[test]
    fn duplicate_rule_id_is_rejected() {
        let rules = vec![
            Rule::block("dup-id", "first", r"\bfoo\b"),
            Rule::block("dup-id", "second", r"\bbar\b"),
        ];
        assert!(GuardrailEngine::new(rules).is_err());
    }
}
