//! Indirect Prompt Injection and Context Hijacking Detector.

use regex::RegexSet;
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Severity classification of a prompt injection scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InjectionSeverity {
    /// No prompt injection or context hijacking patterns detected.
    Safe,
    /// Low/medium risk prompt manipulation or delimiter anomaly.
    Suspicious,
    /// Critical prompt override or system instruction evasion attempt.
    CriticalInjection,
}

/// Result of scanning a payload for prompt injection attacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InjectionScanResult {
    /// Overall severity rating.
    pub severity: InjectionSeverity,
    /// Matched attack pattern signature names.
    pub matched_signatures: Vec<String>,
}

/// High-throughput regex-based prompt injection detector.
#[derive(Clone)]
pub struct PromptInjectionDetector {
    critical_set: RegexSet,
    critical_signatures: Vec<&'static str>,
    suspicious_set: RegexSet,
    suspicious_signatures: Vec<&'static str>,
}

impl PromptInjectionDetector {
    /// Creates a new default `PromptInjectionDetector` compiled with built-in attack signatures.
    ///
    /// # Panics
    ///
    /// Panics if static regex patterns fail to compile.
    #[must_use]
    pub fn new() -> Self {
        let critical_patterns = vec![
            r"(?i)\bignore\s+(?:all\s+)?(?:previous|earlier)\s+(?:instructions|directives|rules)\b",
            r"(?i)\bdisregard\s+(?:all\s+)?(?:previous|earlier)\s+(?:instructions|directives|rules)\b",
            r"(?i)\byou\s+are\s+now\s+in\s+(?:developer|DAN|jailbreak|unrestricted)\s+mode\b",
            r"(?i)system\s+prompt\s+override",
            r"(?i)<\|im_start\|>|<\|im_end\|>|<\|system\|>|```system",
            r"(?i)\[SYSTEM\s+DIRECTIVE\]",
        ];

        let critical_signatures = vec![
            "System Prompt Override",
            "Instruction Disregard",
            "Jailbreak Persona Shift",
            "System Override Keyword",
            "ChatML Template Hijacking",
            "System Directive Injection",
        ];

        let suspicious_patterns = vec![
            r"(?i)\bnew\s+rule:",
            r"(?i)\bdo\s+not\s+follow\b",
            r"(?i)<script[\s>]|javascript:",
        ];

        let suspicious_signatures = vec![
            "New Rule Injection",
            "Rule Evasion Phrase",
            "Script Payload Ingestion",
        ];

        let critical_set = RegexSet::new(&critical_patterns).expect("Valid critical regex set");
        let suspicious_set =
            RegexSet::new(&suspicious_patterns).expect("Valid suspicious regex set");

        Self {
            critical_set,
            critical_signatures,
            suspicious_set,
            suspicious_signatures,
        }
    }

    /// Scans a text payload for prompt injection and context hijacking patterns.
    #[must_use]
    pub fn scan_payload(&self, text: &str) -> InjectionScanResult {
        let mut matched_signatures = Vec::new();

        // 1. Check Critical Signatures
        let crit_matches = self.critical_set.matches(text);
        if crit_matches.matched_any() {
            for index in crit_matches {
                if let Some(sig) = self.critical_signatures.get(index) {
                    matched_signatures.push((*sig).to_string());
                }
            }
            warn!(signatures = ?matched_signatures, "Critical Prompt Injection Detected");
            return InjectionScanResult {
                severity: InjectionSeverity::CriticalInjection,
                matched_signatures,
            };
        }

        // 2. Check Suspicious Signatures
        let susp_matches = self.suspicious_set.matches(text);
        if susp_matches.matched_any() {
            for index in susp_matches {
                if let Some(sig) = self.suspicious_signatures.get(index) {
                    matched_signatures.push((*sig).to_string());
                }
            }
            return InjectionScanResult {
                severity: InjectionSeverity::Suspicious,
                matched_signatures,
            };
        }

        InjectionScanResult {
            severity: InjectionSeverity::Safe,
            matched_signatures: Vec::new(),
        }
    }
}

impl Default for PromptInjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}
