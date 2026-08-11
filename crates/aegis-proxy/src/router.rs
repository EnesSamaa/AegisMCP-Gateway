//! Core request routing and forwarding pipeline.

use crate::{
    error::ProxyError,
    sse::{apply_sse_headers, is_sse_request},
};
use aegis_core::JsonRpcRequest;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{
    body::Incoming,
    header::{HeaderValue, HOST},
    Request, Response, StatusCode,
};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use tracing::{debug, info, warn};

/// High-performance router and forwarding pipeline for MCP requests.
pub struct ProxyRouter {
    client: Client<HttpConnector, BoxBody<Bytes, hyper::Error>>,
    upstream_url: String,
}

impl ProxyRouter {
    /// Creates a new `ProxyRouter` with an initialized HTTP client pool.
    #[must_use]
    pub fn new(upstream_url: impl Into<String>) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Self {
            client,
            upstream_url: upstream_url.into(),
        }
    }

    /// Handles an incoming request, routing `/health` or forwarding to upstream.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] if forwarding or buffering fails.
    pub async fn handle_request(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
        // Route /health
        if req.uri().path() == "/health" {
            let body = Full::new(Bytes::from(
                r#"{"status":"ok","gateway":"AegisMCP-Gateway"}"#,
            ))
            .map_err(|_| -> hyper::Error { unreachable!() })
            .boxed();

            let resp = Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(body)?;
            return Ok(resp);
        }

        // Check SSE
        let is_sse = is_sse_request(&req);

        // Extract parts and body
        let (parts, incoming_body) = req.into_parts();

        // Collect body for inspection
        let body_bytes = incoming_body.collect().await?.to_bytes();

        // Inspect JSON-RPC if present
        if !body_bytes.is_empty() {
            if let Ok(rpc_req) = serde_json::from_slice::<JsonRpcRequest>(&body_bytes) {
                info!(
                    method = %rpc_req.method,
                    id = ?rpc_req.id,
                    "Intercepted MCP JSON-RPC Request"
                );
            } else {
                debug!("Request body present but not a valid JsonRpcRequest");
            }
        }

        // Construct target URI
        let path_and_query = parts
            .uri
            .path_and_query()
            .map_or("", hyper::http::uri::PathAndQuery::as_str);
        let target_uri = format!("{}{path_and_query}", self.upstream_url);

        debug!(target = %target_uri, is_sse = is_sse, "Forwarding request to upstream");

        let mut fwd_req = Request::builder()
            .method(parts.method)
            .uri(&target_uri);

        // Copy headers
        if let Some(headers_mut) = fwd_req.headers_mut() {
            for (key, value) in &parts.headers {
                if key != HOST {
                    headers_mut.insert(key, value.clone());
                }
            }
            if let Ok(uri_parsed) = target_uri.parse::<hyper::Uri>() {
                if let Some(host_str) = uri_parsed.host() {
                    if let Ok(host_header) = HeaderValue::from_str(host_str) {
                        headers_mut.insert(HOST, host_header);
                    }
                }
            }
        }

        let boxed_fwd_body = Full::new(body_bytes)
            .map_err(|_| -> hyper::Error { unreachable!() })
            .boxed();

        let fwd_req = fwd_req.body(boxed_fwd_body)?;

        // Forward to upstream
        let upstream_resp = match self.client.request(fwd_req).await {
            Ok(resp) => resp,
            Err(err) => {
                warn!(error = %err, target = %target_uri, "Upstream connection failed");
                let err_body = Full::new(Bytes::from(
                    r#"{"jsonrpc":"2.0","error":{"code":-32010,"message":"Upstream server unreachable"},"id":null}"#,
                ))
                .map_err(|_| -> hyper::Error { unreachable!() })
                .boxed();

                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .header(hyper::header::CONTENT_TYPE, "application/json")
                    .body(err_body)?);
            }
        };

        // Construct client response
        let (resp_parts, resp_body) = upstream_resp.into_parts();
        let mut client_resp = Response::builder().status(resp_parts.status);

        if let Some(headers_mut) = client_resp.headers_mut() {
            for (k, v) in &resp_parts.headers {
                headers_mut.insert(k, v.clone());
            }
            if is_sse {
                apply_sse_headers(headers_mut);
            }
        }

        let boxed_resp_body = resp_body.map_err(hyper::Error::from).boxed();

        Ok(client_resp.body(boxed_resp_body)?)
    }
}
