//! Server-Sent Events (SSE) streaming helpers.

use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderValue, ACCEPT, CACHE_CONTROL, CONNECTION, CONTENT_TYPE};
use hyper::Request;

/// MIME type for Server-Sent Events (`text/event-stream`).
pub const SSE_CONTENT_TYPE: &str = "text/event-stream";

/// Returns `true` if the request advertises an SSE stream.
#[must_use]
pub fn is_sse_request(req: &Request<Incoming>) -> bool {
    if let Some(accept) = req.headers().get(ACCEPT) {
        if let Ok(str_val) = accept.to_str() {
            if str_val.contains(SSE_CONTENT_TYPE) {
                return true;
            }
        }
    }
    if let Some(content_type) = req.headers().get(CONTENT_TYPE) {
        if let Ok(str_val) = content_type.to_str() {
            if str_val.contains(SSE_CONTENT_TYPE) {
                return true;
            }
        }
    }
    false
}

/// Applies required SSE headers (`text/event-stream`, `no-cache`, `keep-alive`) to a [`HeaderMap`].
pub fn apply_sse_headers(headers: &mut HeaderMap) {
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(SSE_CONTENT_TYPE));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
}

/// Formats a Server-Sent Event string block according to the SSE spec.
#[must_use]
pub fn format_sse_event(event_name: &str, data: &str) -> String {
    format!("event: {event_name}\ndata: {data}\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_sse_event() {
        let formatted = format_sse_event("message", "{\"jsonrpc\":\"2.0\"}");
        assert_eq!(formatted, "event: message\ndata: {\"jsonrpc\":\"2.0\"}\n\n");
    }

    #[test]
    fn test_apply_sse_headers() {
        let mut headers = HeaderMap::new();
        apply_sse_headers(&mut headers);
        assert_eq!(headers.get(CONTENT_TYPE).unwrap(), SSE_CONTENT_TYPE);
        assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-cache");
    }
}
