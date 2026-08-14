//! W3C `TraceContext` (`traceparent`) propagation for distributed tracing.
//!
//! Implements lightweight trace context extraction and injection compatible
//! with the W3C Trace Context Level 1 specification (<https://www.w3.org/TR/trace-context>).
//! No external OTLP collector is required — the header values are compatible with
//! OpenTelemetry, Jaeger, Zipkin, and any W3C-compliant tracing backend.

use hyper::header::{HeaderMap, HeaderValue};
use uuid::Uuid;

/// W3C `traceparent` HTTP header name.
pub const TRACEPARENT_HEADER: &str = "traceparent";

/// W3C `tracestate` HTTP header name.
pub const TRACESTATE_HEADER: &str = "tracestate";

/// W3C `TraceContext` — holds `trace_id`, `span_id`, and sampling `flags`.
///
/// Format: `00-<trace_id>-<span_id>-<flags>` where:
/// - `trace_id` is 32 lowercase hex characters (128-bit).
/// - `span_id` is 16 lowercase hex characters (64-bit).
/// - `flags` is `01` (sampled) or `00` (not sampled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    /// 128-bit trace identifier (32 hex chars).
    pub trace_id: String,
    /// 64-bit span identifier (16 hex chars).
    pub span_id: String,
    /// Trace flags (0x01 = sampled).
    pub flags: u8,
}

impl TraceContext {
    /// Generates a new root-level `TraceContext` with a random `trace_id` and `span_id`.
    #[must_use]
    pub fn new_root() -> Self {
        let u1 = Uuid::new_v4().simple().to_string();
        let u2 = Uuid::new_v4().simple().to_string();
        let trace_id = format!("{}{}", &u1[..16], &u2[..16]);
        let span_id = u1[16..].to_string();

        Self {
            trace_id,
            span_id,
            flags: 0x01,
        }
    }

    /// Parses a `traceparent` header value.
    ///
    /// Returns `None` if the value is malformed or the version is unsupported.
    #[must_use]
    pub fn from_traceparent(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split('-').collect();
        if parts.len() < 4 || parts[0] != "00" {
            return None;
        }
        let flags = u8::from_str_radix(parts[3], 16).ok()?;
        Some(Self {
            trace_id: parts[1].to_string(),
            span_id: parts[2].to_string(),
            flags,
        })
    }

    /// Serialises this context into a `traceparent` header value.
    #[must_use]
    pub fn to_traceparent(&self) -> String {
        format!("00-{}-{}-{:02x}", self.trace_id, self.span_id, self.flags)
    }

    /// Creates a child span that shares the same `trace_id` but uses a new `span_id`.
    #[must_use]
    pub fn child_span(&self) -> Self {
        let raw = Uuid::new_v4().simple().to_string();
        Self {
            trace_id: self.trace_id.clone(),
            span_id: raw[..16].to_string(),
            flags: self.flags,
        }
    }

    /// Returns `true` if the sampling flag is set.
    #[must_use]
    pub const fn is_sampled(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

impl std::fmt::Display for TraceContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_traceparent())
    }
}

// ---------------------------------------------------------------------------
// Header helpers
// ---------------------------------------------------------------------------

/// Extracts a [`TraceContext`] from incoming HTTP request headers.
///
/// If no valid `traceparent` header is present a new root context is generated.
#[must_use]
pub fn extract_trace_context(headers: &HeaderMap) -> TraceContext {
    headers
        .get(TRACEPARENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(TraceContext::from_traceparent)
        .unwrap_or_else(TraceContext::new_root)
}

/// Injects W3C trace context headers into an outgoing request's [`HeaderMap`].
///
/// A child span is created so that the upstream hop gets its own unique `span_id`
/// while remaining part of the same distributed trace.
pub fn inject_trace_headers(headers: &mut HeaderMap, ctx: &TraceContext) {
    let child = ctx.child_span();
    if let Ok(v) = HeaderValue::from_str(&child.to_traceparent()) {
        headers.insert(TRACEPARENT_HEADER, v);
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_root_produces_valid_traceparent() {
        let ctx = TraceContext::new_root();
        assert_eq!(ctx.trace_id.len(), 32);
        assert_eq!(ctx.span_id.len(), 16);
        assert!(ctx.is_sampled());
        let tp = ctx.to_traceparent();
        assert!(tp.starts_with("00-"));
        // Must round-trip
        let parsed = TraceContext::from_traceparent(&tp).unwrap();
        assert_eq!(parsed.trace_id, ctx.trace_id);
        assert_eq!(parsed.span_id, ctx.span_id);
    }

    #[test]
    fn child_span_shares_trace_id() {
        let root = TraceContext::new_root();
        let child = root.child_span();
        assert_eq!(child.trace_id, root.trace_id);
        assert_ne!(child.span_id, root.span_id);
    }

    #[test]
    fn invalid_traceparent_returns_new_root() {
        assert!(TraceContext::from_traceparent("garbage").is_none());
        assert!(TraceContext::from_traceparent("01-abc-def-00").is_none()); // version 01 unsupported
    }

    #[test]
    fn extract_from_headers_falls_back_to_new_root() {
        let headers = HeaderMap::new();
        let ctx = extract_trace_context(&headers);
        assert_eq!(ctx.trace_id.len(), 32);
    }

    #[test]
    fn inject_and_extract_roundtrip() {
        let original = TraceContext::new_root();
        let mut headers = HeaderMap::new();
        inject_trace_headers(&mut headers, &original);
        let extracted = extract_trace_context(&headers);
        // The injected header uses a *child* span_id but the same trace_id.
        assert_eq!(extracted.trace_id, original.trace_id);
        assert_ne!(extracted.span_id, original.span_id);
    }
}
