//! Regex-based and structural content matchers.

use crate::error::GuardrailError;
use regex::Regex;

/// A compiled regex matcher used by guardrail rules.
#[derive(Debug)]
pub struct RegexMatcher {
    pattern: String,
    regex: Regex,
}

impl RegexMatcher {
    /// Compile a new `RegexMatcher` from a pattern string.
    ///
    /// # Errors
    ///
    /// Returns [`GuardrailError::InvalidPattern`] if the regex fails to compile.
    pub fn new(pattern: &str) -> Result<Self, GuardrailError> {
        let regex =
            Regex::new(pattern).map_err(|e| GuardrailError::InvalidPattern(e.to_string()))?;
        Ok(Self {
            pattern: pattern.into(),
            regex,
        })
    }

    /// Returns `true` if `haystack` contains a match for this pattern.
    #[must_use]
    pub fn is_match(&self, haystack: &str) -> bool {
        self.regex.is_match(haystack)
    }

    /// Returns the original pattern string.
    #[must_use]
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_password_keyword() {
        let m = RegexMatcher::new(r"(?i)\bpassword\b").expect("valid pattern");
        assert!(m.is_match("Please enter your password here"));
        assert!(!m.is_match("This text is clean"));
    }

    #[test]
    fn invalid_pattern_returns_error() {
        let result = RegexMatcher::new(r"[invalid");
        assert!(result.is_err());
    }
}
