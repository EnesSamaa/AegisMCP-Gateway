//! Inline Data Loss Prevention (DLP) & Real-Time PII Masking Engine.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Report returned after performing DLP masking on a payload text.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DlpScanReport {
    /// Total count of PII/PHI/credential items masked.
    pub items_masked_count: usize,
    /// List of masked category names (e.g. `Credit Card`, `Email Address`).
    pub masked_categories: Vec<String>,
}

/// Compiled regex matchers for a single DLP rule category.
#[derive(Clone)]
struct DlpRule {
    category_name: &'static str,
    regex: Regex,
    replacement_token: &'static str,
}

/// Inline Data Loss Prevention (DLP) engine for real-time response masking.
#[derive(Clone)]
pub struct DlpMaskingEngine {
    rules: Arc<Vec<DlpRule>>,
}

impl DlpMaskingEngine {
    /// Creates a new `DlpMaskingEngine` with default PII/PHI and credential detection rules.
    ///
    /// # Panics
    ///
    /// Panics if static regex patterns fail to compile.
    #[must_use]
    pub fn new() -> Self {
        let rules = vec![
            DlpRule {
                category_name: "Credit Card",
                regex: Regex::new(r"\b(?:\d[ -]*?){13,16}\b").expect("Valid CC regex"),
                replacement_token: "[REDACTED_CREDIT_CARD]",
            },
            DlpRule {
                category_name: "Email Address",
                regex: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
                    .expect("Valid Email regex"),
                replacement_token: "[REDACTED_EMAIL]",
            },
            DlpRule {
                category_name: "API Key / Secret Token",
                regex: Regex::new(
                    r"(sk_live_[0-9a-zA-Z_]{24,}|sk_test_[0-9a-zA-Z_]{24,}|ghp_[0-9a-zA-Z_]{36}|Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*)",
                )
                .expect("Valid API Key regex"),
                replacement_token: "[REDACTED_API_KEY]",
            },
            DlpRule {
                category_name: "Social Security Number",
                regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("Valid SSN regex"),
                replacement_token: "[REDACTED_SSN]",
            },
        ];

        Self {
            rules: Arc::new(rules),
        }
    }

    /// Sanitizes input text by redacting detected sensitive PII, credentials, or SSNs.
    #[must_use]
    pub fn mask_payload(&self, text: &str) -> (String, DlpScanReport) {
        let mut current_text = text.to_string();
        let mut report = DlpScanReport::default();

        for rule in self.rules.iter() {
            let matches_count = rule.regex.find_iter(&current_text).count();
            if matches_count > 0 {
                report.items_masked_count += matches_count;
                if !report
                    .masked_categories
                    .contains(&rule.category_name.to_string())
                {
                    report
                        .masked_categories
                        .push(rule.category_name.to_string());
                }
                current_text = rule
                    .regex
                    .replace_all(&current_text, rule.replacement_token)
                    .to_string();
            }
        }

        (current_text, report)
    }
}

impl Default for DlpMaskingEngine {
    fn default() -> Self {
        Self::new()
    }
}
