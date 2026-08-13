//! Core request routing and forwarding pipeline with dynamic route table evaluation.

use crate::{
    config::schema::GatewayConfig,
    error::ProxyError,
    sse::{apply_sse_headers, is_sse_request},
};
use aegis_core::{AgentIdentity, JsonRpcRequest, McpSessionContext, RequestId, SessionId, ToolCall};
use aegis_guardrails::{
    IdentityContext, IdentityExtractor, PolicyDecision as AuthzDecision, TokenTranslator,
    ToolAuthorizationEngine,
};
use aegis_wasm::{build_inspection_context, HostDecision, PluginRunner};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{
    body::Incoming,
    header::{HeaderValue, AUTHORIZATION, HOST},
    Request, Response, StatusCode,
};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// High-performance router and forwarding pipeline for MCP requests.
#[derive(Clone)]
pub struct ProxyRouter {
    client: Client<HttpConnector, BoxBody<Bytes, hyper::Error>>,
    config_rx: watch::Receiver<GatewayConfig>,
    fallback_upstream_url: String,
    wasm_runner: Option<Arc<PluginRunner>>,
    identity_extractor: Option<Arc<IdentityExtractor>>,
    token_translator: Option<Arc<TokenTranslator>>,
    tool_authz_engine: Option<Arc<ToolAuthorizationEngine>>,
}

impl ProxyRouter {
    /// Creates a new `ProxyRouter` with an initialized HTTP client pool and default static upstream.
    #[must_use]
    pub fn new(upstream_url: impl Into<String>) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        let fallback_upstream = upstream_url.into();
        let mut default_cfg = GatewayConfig::default();
        default_cfg.routes[0].upstream_url.clone_from(&fallback_upstream);
        let (_, config_rx) = watch::channel(default_cfg);

        Self {
            client,
            config_rx,
            fallback_upstream_url: fallback_upstream,
            wasm_runner: None,
            identity_extractor: None,
            token_translator: None,
            tool_authz_engine: None,
        }
    }

    /// Creates a `ProxyRouter` with dynamic [`GatewayConfig`] subscription.
    #[must_use]
    pub fn with_config_receiver(
        upstream_url: impl Into<String>,
        config_rx: watch::Receiver<GatewayConfig>,
    ) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Self {
            client,
            config_rx,
            fallback_upstream_url: upstream_url.into(),
            wasm_runner: None,
            identity_extractor: None,
            token_translator: None,
            tool_authz_engine: None,
        }
    }

    /// Attaches an optional WASM plugin runner for real-time guardrail policy evaluation.
    #[must_use]
    pub fn with_wasm_runner(mut self, runner: Arc<PluginRunner>) -> Self {
        self.wasm_runner = Some(runner);
        self
    }

    /// Attaches an Agent Identity Extractor for authentication.
    #[must_use]
    pub fn with_identity_extractor(mut self, extractor: Arc<IdentityExtractor>) -> Self {
        self.identity_extractor = Some(extractor);
        self
    }

    /// Attaches an Enterprise Token Translator for credential mapping.
    #[must_use]
    pub fn with_token_translator(mut self, translator: Arc<TokenTranslator>) -> Self {
        self.token_translator = Some(translator);
        self
    }

    /// Attaches a Granular Tool Authorization Engine for RBAC/ABAC checks.
    #[must_use]
    pub fn with_tool_authz_engine(mut self, engine: Arc<ToolAuthorizationEngine>) -> Self {
        self.tool_authz_engine = Some(engine);
        self
    }

    /// Evaluates WASM policy guardrails for an incoming JSON-RPC request.
    async fn evaluate_wasm_guardrail(
        &self,
        rpc_req: &JsonRpcRequest,
        identity_ctx: Option<&IdentityContext>,
    ) -> Option<Response<BoxBody<Bytes, hyper::Error>>> {
        let runner = self.wasm_runner.as_ref()?;

        let agent = identity_ctx.map_or_else(
            || AgentIdentity::new("client-proxy", "ProxyAgent", "analyst"),
            |ctx| ctx.identity.clone(),
        );

        let session = McpSessionContext::new(SessionId::new(), agent, 1_700_000_000_000);
        let req_id = RequestId::new();
        let tool_call = ToolCall::new(&rpc_req.method, rpc_req.params.clone());

        let wit_ctx = build_inspection_context(&session, req_id, &tool_call);

        match runner.evaluate_concurrently(&wit_ctx, Duration::from_millis(500)).await {
            Ok(summary) => match summary.decision {
                HostDecision::Allow | HostDecision::Modify(_) => None,
                HostDecision::Deny(reason) => {
                    warn!(reason = %reason, "WASM Policy Evaluation Denied Request");
                    let json_id = serde_json::to_string(&rpc_req.id).unwrap_or_else(|_| "null".to_string());
                    let err_json = format!(
                        r#"{{"jsonrpc":"2.0","error":{{"code":-32001,"message":"Security Policy Denial: {reason}"}},"id":{json_id}}}"#
                    );
                    let err_body = Full::new(Bytes::from(err_json))
                        .map_err(|_| -> hyper::Error { unreachable!() })
                        .boxed();

                    Response::builder()
                        .status(StatusCode::OK)
                        .header(hyper::header::CONTENT_TYPE, "application/json")
                        .body(err_body)
                        .ok()
                }
            },
            Err(err) => {
                warn!(error = %err, "WASM Policy Evaluation Failed");
                None
            }
        }
    }

    /// Handles an incoming request, routing `/health` or forwarding to upstream.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] if forwarding or buffering fails.
    #[allow(clippy::too_many_lines, clippy::option_if_let_else)]
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

        // Dynamic route resolution — scoped block so watch::Ref is dropped before await points
        let upstream_target_url = {
            let req_path = req.uri().path();
            let current_config = self.config_rx.borrow();
            current_config
                .routes
                .iter()
                .find(|r| r.enabled && req_path.starts_with(&r.path))
                .map_or_else(
                    || self.fallback_upstream_url.clone(),
                    |r| r.upstream_url.clone(),
                )
        };

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        // Extract auth headers
        let auth_header_str = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        let api_key_str = req
            .headers()
            .get("X-API-Key")
            .and_then(|v| v.to_str().ok());

        // Extract IdentityContext if Extractor present
        let mut extracted_identity = None;
        if let Some(extractor) = &self.identity_extractor {
            match extractor.extract(auth_header_str, api_key_str, now_secs).await {
                Ok(ctx) => {
                    info!(
                        agent_id = %ctx.identity.agent_id(),
                        tenant = %ctx.tenant_id,
                        role = %ctx.identity.role(),
                        "Agent Identity Extracted Successfully"
                    );
                    extracted_identity = Some(ctx);
                }
                Err(err) => {
                    warn!(error = %err, "Agent Authentication Failed");
                    let err_body = Full::new(Bytes::from(format!(
                        r#"{{"jsonrpc":"2.0","error":{{"code":-32002,"message":"Authentication Failed: {err}"}},"id":null}}"#
                    )))
                    .map_err(|_| -> hyper::Error { unreachable!() })
                    .boxed();

                    return Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header(hyper::header::CONTENT_TYPE, "application/json")
                        .body(err_body)?);
                }
            }
        }

        // Perform Enterprise Token Translation if enabled
        let mut translated_upstream_token = None;
        if let Some(translator) = &self.token_translator {
            if let Some(ctx) = &extracted_identity {
                if let Ok(translated) = translator.translate(ctx, &upstream_target_url, now_secs).await {
                    info!(
                        upstream = %upstream_target_url,
                        "Enterprise Token Translated for Upstream MCP Server"
                    );
                    translated_upstream_token = Some(translated.token);
                }
            }
        }

        // Extract parts and body
        let (parts, incoming_body) = req.into_parts();

        // Collect body for inspection
        let body_bytes = incoming_body.collect().await?.to_bytes();

        // Inspect JSON-RPC & Evaluate Tool RBAC/ABAC and WASM Policy Guardrails if enabled
        if !body_bytes.is_empty() {
            if let Ok(rpc_req) = serde_json::from_slice::<JsonRpcRequest>(&body_bytes) {
                info!(
                    method = %rpc_req.method,
                    id = ?rpc_req.id,
                    "Intercepted MCP JSON-RPC Request"
                );

                // 1. RBAC/ABAC Tool Authorization Check
                if let Some(authz_engine) = &self.tool_authz_engine {
                    let dummy_ctx;
                    let identity_ref = if let Some(ctx) = &extracted_identity {
                        ctx
                    } else {
                        dummy_ctx = IdentityContext {
                            identity: AgentIdentity::new("anonymous", "AnonymousAgent", "default"),
                            tenant_id: "default".to_string(),
                            permissions: vec![],
                            session_scope: "anonymous".to_string(),
                            expires_at: u64::MAX,
                        };
                        &dummy_ctx
                    };

                    let tool_call = ToolCall::new(&rpc_req.method, rpc_req.params.clone());
                    if let AuthzDecision::Deny(reason) = authz_engine.check_authorization(identity_ref, &tool_call).await {
                        warn!(reason = %reason, "Tool Authorization Engine Denied Call");
                        let json_id = serde_json::to_string(&rpc_req.id).unwrap_or_else(|_| "null".to_string());
                        let err_json = format!(
                            r#"{{"jsonrpc":"2.0","error":{{"code":-32001,"message":"Unauthorized Tool Call: {reason}"}},"id":{json_id}}}"#
                        );
                        let err_body = Full::new(Bytes::from(err_json))
                            .map_err(|_| -> hyper::Error { unreachable!() })
                            .boxed();

                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(hyper::header::CONTENT_TYPE, "application/json")
                            .body(err_body)?);
                    }
                }

                // 2. WASM Policy Guardrails Check
                if let Some(deny_resp) = self
                    .evaluate_wasm_guardrail(&rpc_req, extracted_identity.as_ref())
                    .await
                {
                    return Ok(deny_resp);
                }
            } else {
                debug!("Request body present but not a valid JsonRpcRequest");
            }
        }

        // Construct target URI
        let path_and_query = parts
            .uri
            .path_and_query()
            .map_or("", hyper::http::uri::PathAndQuery::as_str);
        let target_uri = format!("{upstream_target_url}{path_and_query}");

        debug!(target = %target_uri, is_sse = is_sse, "Forwarding request to upstream");

        let mut fwd_req = Request::builder()
            .method(parts.method)
            .uri(&target_uri);

        // Copy headers & inject translated upstream credential
        if let Some(headers_mut) = fwd_req.headers_mut() {
            for (key, value) in &parts.headers {
                if key != HOST && key != AUTHORIZATION {
                    headers_mut.insert(key, value.clone());
                }
            }

            if let Some(token) = translated_upstream_token {
                if let Ok(auth_val) = HeaderValue::from_str(&format!("Bearer {token}")) {
                    headers_mut.insert(AUTHORIZATION, auth_val);
                }
            } else if let Some(orig_auth) = parts.headers.get(AUTHORIZATION) {
                headers_mut.insert(AUTHORIZATION, orig_auth.clone());
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
