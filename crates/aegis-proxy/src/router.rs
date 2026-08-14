//! Core request routing and forwarding pipeline with dynamic route table evaluation.

use crate::{
    config::schema::GatewayConfig,
    error::ProxyError,
    sse::{apply_sse_headers, is_sse_request},
    telemetry::{
        extract_trace_context, inject_trace_headers, record_guardrail_latency, record_http_request,
        record_security_violation, render_metrics, set_merkle_leaves,
    },
};
use aegis_core::{
    AgentIdentity, JsonRpcRequest, McpSessionContext, RequestId, SessionId, ToolCall,
};
use aegis_guardrails::{
    AgentRateLimiter, ApprovalDecision, DlpMaskingEngine, HitlApprovalEngine, IdentityContext,
    IdentityExtractor, InjectionSeverity, LoopBreakerEngine, PolicyDecision as AuthzDecision,
    PromptInjectionDetector, TokenTranslator, ToolAuthorizationEngine,
};
use aegis_proof::AuditLedger;
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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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
    prompt_injection_detector: Option<Arc<PromptInjectionDetector>>,
    dlp_engine: Option<Arc<DlpMaskingEngine>>,
    rate_limiter: Option<Arc<AgentRateLimiter>>,
    loop_breaker: Option<Arc<LoopBreakerEngine>>,
    hitl_engine: Option<Arc<HitlApprovalEngine>>,
    audit_ledger: Option<Arc<AuditLedger>>,
}

impl ProxyRouter {
    /// Creates a new `ProxyRouter` with an initialized HTTP client pool and default static upstream.
    #[must_use]
    pub fn new(upstream_url: impl Into<String>) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        let fallback_upstream = upstream_url.into();
        let mut default_cfg = GatewayConfig::default();
        default_cfg.routes[0]
            .upstream_url
            .clone_from(&fallback_upstream);
        let (_, config_rx) = watch::channel(default_cfg);

        Self {
            client,
            config_rx,
            fallback_upstream_url: fallback_upstream,
            wasm_runner: None,
            identity_extractor: None,
            token_translator: None,
            tool_authz_engine: None,
            prompt_injection_detector: None,
            dlp_engine: None,
            rate_limiter: None,
            loop_breaker: None,
            hitl_engine: None,
            audit_ledger: None,
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
            prompt_injection_detector: None,
            dlp_engine: None,
            rate_limiter: None,
            loop_breaker: None,
            hitl_engine: None,
            audit_ledger: None,
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

    /// Attaches a Prompt Injection Detector for context hijacking inspection.
    #[must_use]
    pub fn with_prompt_injection_detector(
        mut self,
        detector: Arc<PromptInjectionDetector>,
    ) -> Self {
        self.prompt_injection_detector = Some(detector);
        self
    }

    /// Attaches a DLP Masking Engine for response PII sanitization.
    #[must_use]
    pub fn with_dlp_engine(mut self, engine: Arc<DlpMaskingEngine>) -> Self {
        self.dlp_engine = Some(engine);
        self
    }

    /// Attaches an Agent Rate Limiter for request quota enforcement.
    #[must_use]
    pub fn with_rate_limiter(mut self, limiter: Arc<AgentRateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Attaches a Loop Breaker Engine for runaway agent execution loop prevention.
    #[must_use]
    pub fn with_loop_breaker(mut self, breaker: Arc<LoopBreakerEngine>) -> Self {
        self.loop_breaker = Some(breaker);
        self
    }

    /// Attaches a HITL Approval Engine for high-risk tool call suspension.
    #[must_use]
    pub fn with_hitl_engine(mut self, engine: Arc<HitlApprovalEngine>) -> Self {
        self.hitl_engine = Some(engine);
        self
    }

    /// Attaches an Audit Ledger for cryptographic SHA-256 audit entry recording.
    #[must_use]
    pub fn with_audit_ledger(mut self, ledger: Arc<AuditLedger>) -> Self {
        self.audit_ledger = Some(ledger);
        self
    }

    /// Helper to record audit log entry if ledger is attached.
    fn log_audit(
        &self,
        start_time: Instant,
        extracted_identity: Option<&IdentityContext>,
        tool_name: &str,
        decision_summary: &str,
    ) {
        if let Some(ledger) = &self.audit_ledger {
            let now_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
            let ag_id = extracted_identity.as_ref().map_or_else(
                || "anonymous".to_string(),
                |ctx| ctx.identity.agent_id().to_string(),
            );
            let elapsed_us = u64::try_from(start_time.elapsed().as_micros()).unwrap_or(u64::MAX);

            ledger.log_entry(
                "req-audit-log",
                now_ns,
                ag_id,
                tool_name,
                decision_summary,
                elapsed_us,
            );
        }
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

        match runner
            .evaluate_concurrently(&wit_ctx, Duration::from_millis(500))
            .await
        {
            Ok(summary) => match summary.decision {
                HostDecision::Allow | HostDecision::Modify(_) => None,
                HostDecision::Deny(reason) => {
                    warn!(reason = %reason, "WASM Policy Evaluation Denied Request");
                    let json_id =
                        serde_json::to_string(&rpc_req.id).unwrap_or_else(|_| "null".to_string());
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
        let start_time = Instant::now();

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

        // Route GET /metrics — Prometheus text exposition
        if req.uri().path() == "/metrics" {
            // Refresh Merkle leaf gauge while we're here
            if let Some(ledger) = &self.audit_ledger {
                let n = ledger.len().await;
                #[allow(clippy::cast_precision_loss)]
                set_merkle_leaves(n as f64);
            }
            let payload = render_metrics();
            let body = Full::new(Bytes::from(payload))
                .map_err(|_| -> hyper::Error { unreachable!() })
                .boxed();
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(
                    hyper::header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                )
                .body(body)?);
        }

        // Route GET /v1/proofs/root  — return current Merkle root + leaf count
        if req.uri().path() == "/v1/proofs/root" {
            if let Some(ledger) = &self.audit_ledger {
                let root_opt = ledger.get_merkle_root().await;
                let count = ledger.len().await;
                let json = match root_opt {
                    Some(root) => format!(r#"{{"merkle_root":"{root}","leaf_count":{count}}}"#),
                    None => r#"{"merkle_root":null,"leaf_count":0}"#.to_string(),
                };
                let body = Full::new(Bytes::from(json))
                    .map_err(|_| -> hyper::Error { unreachable!() })
                    .boxed();
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(hyper::header::CONTENT_TYPE, "application/json")
                    .body(body)?);
            }
            // Ledger not attached
            let body = Full::new(Bytes::from(r#"{"error":"audit ledger not configured"}"#))
                .map_err(|_| -> hyper::Error { unreachable!() })
                .boxed();
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(body)?);
        }

        // Route GET /v1/proofs/{request_id}  — return serialised AuditMerkleProof
        if let Some(request_id) = req
            .uri()
            .path()
            .strip_prefix("/v1/proofs/")
            .filter(|s| !s.is_empty())
        {
            if let Some(ledger) = &self.audit_ledger {
                match ledger.generate_proof_by_request_id(request_id).await {
                    Ok(proof) => {
                        let json = serde_json::to_string(&proof).unwrap_or_else(|e| {
                            format!(r#"{{"error":"serialization failed: {e}"}}"#)
                        });
                        let body = Full::new(Bytes::from(json))
                            .map_err(|_| -> hyper::Error { unreachable!() })
                            .boxed();
                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(hyper::header::CONTENT_TYPE, "application/json")
                            .body(body)?);
                    }
                    Err(err) => {
                        let json = format!(r#"{{"error":"proof not found: {err}"}}"#);
                        let body = Full::new(Bytes::from(json))
                            .map_err(|_| -> hyper::Error { unreachable!() })
                            .boxed();
                        return Ok(Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .header(hyper::header::CONTENT_TYPE, "application/json")
                            .body(body)?);
                    }
                }
            }
            let body = Full::new(Bytes::from(r#"{"error":"audit ledger not configured"}"#))
                .map_err(|_| -> hyper::Error { unreachable!() })
                .boxed();
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(body)?);
        }

        // Check SSE
        let is_sse = is_sse_request(&req);

        // Extract W3C TraceContext from incoming headers (generates root if absent)
        let trace_ctx = extract_trace_context(req.headers());
        debug!(trace_id = %trace_ctx.trace_id, span_id = %trace_ctx.span_id, "TraceContext extracted");

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
        let api_key_str = req.headers().get("X-API-Key").and_then(|v| v.to_str().ok());

        // Extract IdentityContext if Extractor present
        let mut extracted_identity = None;
        if let Some(extractor) = &self.identity_extractor {
            match extractor
                .extract(auth_header_str, api_key_str, now_secs)
                .await
            {
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

                    self.log_audit(
                        start_time,
                        extracted_identity.as_ref(),
                        "auth",
                        "DENY_AUTH_FAILED",
                    );
                    record_security_violation("auth_failed");
                    record_http_request(req.method().as_str(), 401, "auth");

                    return Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header(hyper::header::CONTENT_TYPE, "application/json")
                        .body(err_body)?);
                }
            }
        }

        // Rate Limiter Check
        if let Some(limiter) = &self.rate_limiter {
            let agent = extracted_identity.as_ref().map_or_else(
                || AgentIdentity::new("anonymous", "AnonymousAgent", "default"),
                |ctx| ctx.identity.clone(),
            );
            let rate_res = limiter.check_rate_limit(&agent, now_secs).await;
            if !rate_res.allowed {
                warn!(agent_id = %agent.agent_id(), "Rate Limit Exceeded — Request Rejected");
                let err_json = r#"{"jsonrpc":"2.0","error":{"code":-32004,"message":"Rate Limit Exceeded: Max request quota exceeded for agent"},"id":null}"#;
                let err_body = Full::new(Bytes::from(err_json))
                    .map_err(|_| -> hyper::Error { unreachable!() })
                    .boxed();

                self.log_audit(
                    start_time,
                    extracted_identity.as_ref(),
                    "rate_limit",
                    "DENY_RATE_LIMIT",
                );
                record_security_violation("rate_limit_exceeded");
                record_guardrail_latency("rate_limiter", start_time.elapsed().as_secs_f64());

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(hyper::header::CONTENT_TYPE, "application/json")
                    .body(err_body)?);
            }
        }

        // Perform Enterprise Token Translation if enabled
        let mut translated_upstream_token = None;
        if let Some(translator) = &self.token_translator {
            if let Some(ctx) = &extracted_identity {
                if let Ok(translated) = translator
                    .translate(ctx, &upstream_target_url, now_secs)
                    .await
                {
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

        let mut req_method_name = parts.uri.path().to_string();

        // Inspect prompt injection & JSON-RPC payload
        if !body_bytes.is_empty() {
            let body_str = String::from_utf8_lossy(&body_bytes);

            // 1. Prompt Injection Scanning
            if let Some(detector) = &self.prompt_injection_detector {
                let scan_res = detector.scan_payload(&body_str);
                if scan_res.severity == InjectionSeverity::CriticalInjection {
                    warn!(signatures = ?scan_res.matched_signatures, "Prompt Injection Detector Short-Circuited Request");
                    let sigs = scan_res.matched_signatures.join(", ");
                    let err_json = format!(
                        r#"{{"jsonrpc":"2.0","error":{{"code":-32003,"message":"Critical Prompt Injection Attack Detected: {sigs}"}},"id":null}}"#
                    );
                    let err_body = Full::new(Bytes::from(err_json))
                        .map_err(|_| -> hyper::Error { unreachable!() })
                        .boxed();

                    self.log_audit(
                        start_time,
                        extracted_identity.as_ref(),
                        "prompt_scan",
                        "DENY_PROMPT_INJECTION",
                    );

                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(hyper::header::CONTENT_TYPE, "application/json")
                        .body(err_body)?);
                }
            }

            if let Ok(rpc_req) = serde_json::from_slice::<JsonRpcRequest>(&body_bytes) {
                req_method_name.clone_from(&rpc_req.method);
                info!(
                    method = %rpc_req.method,
                    id = ?rpc_req.id,
                    "Intercepted MCP JSON-RPC Request"
                );

                let tool_call = ToolCall::new(&rpc_req.method, rpc_req.params.clone());

                // 2. HITL Approval Check for High-Risk Tools
                if let Some(hitl) = &self.hitl_engine {
                    if hitl.is_high_risk(&rpc_req.method).await {
                        if let Ok((req_id, ApprovalDecision::Rejected(reason))) =
                            hitl.request_approval(&tool_call, None).await
                        {
                            warn!(request_id = %req_id, reason = %reason, "HITL Approval Rejected");
                            let json_id = serde_json::to_string(&rpc_req.id)
                                .unwrap_or_else(|_| "null".to_string());
                            let err_json = format!(
                                r#"{{"jsonrpc":"2.0","error":{{"code":-32005,"message":"HITL Approval Required: {reason}"}},"id":{json_id}}}"#
                            );
                            let err_body = Full::new(Bytes::from(err_json))
                                .map_err(|_| -> hyper::Error { unreachable!() })
                                .boxed();

                            self.log_audit(
                                start_time,
                                extracted_identity.as_ref(),
                                &rpc_req.method,
                                "DENY_HITL_REJECTED",
                            );

                            return Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header(hyper::header::CONTENT_TYPE, "application/json")
                                .body(err_body)?);
                        }
                    }
                }

                // 3. Stateful Loop Breaker Check
                if let Some(breaker) = &self.loop_breaker {
                    let session_key = extracted_identity.as_ref().map_or_else(
                        || "default-session".to_string(),
                        |ctx| ctx.identity.agent_id().to_string(),
                    );

                    if let Err(loop_err) = breaker
                        .check_and_record(&session_key, &tool_call, now_secs)
                        .await
                    {
                        warn!(reason = %loop_err, "Stateful Loop Breaker Short-Circuited Request");
                        let json_id = serde_json::to_string(&rpc_req.id)
                            .unwrap_or_else(|_| "null".to_string());
                        let err_json = format!(
                            r#"{{"jsonrpc":"2.0","error":{{"code":-32004,"message":"Execution Loop Detected: {loop_err}"}},"id":{json_id}}}"#
                        );
                        let err_body = Full::new(Bytes::from(err_json))
                            .map_err(|_| -> hyper::Error { unreachable!() })
                            .boxed();

                        self.log_audit(
                            start_time,
                            extracted_identity.as_ref(),
                            &rpc_req.method,
                            "DENY_LOOP_BREAKER",
                        );

                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(hyper::header::CONTENT_TYPE, "application/json")
                            .body(err_body)?);
                    }
                }

                // 4. RBAC/ABAC Tool Authorization Check
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

                    if let AuthzDecision::Deny(reason) = authz_engine
                        .check_authorization(identity_ref, &tool_call)
                        .await
                    {
                        warn!(reason = %reason, "Tool Authorization Engine Denied Call");
                        let json_id = serde_json::to_string(&rpc_req.id)
                            .unwrap_or_else(|_| "null".to_string());
                        let err_json = format!(
                            r#"{{"jsonrpc":"2.0","error":{{"code":-32001,"message":"Unauthorized Tool Call: {reason}"}},"id":{json_id}}}"#
                        );
                        let err_body = Full::new(Bytes::from(err_json))
                            .map_err(|_| -> hyper::Error { unreachable!() })
                            .boxed();

                        self.log_audit(
                            start_time,
                            extracted_identity.as_ref(),
                            &rpc_req.method,
                            "DENY_UNAUTHORIZED_TOOL",
                        );

                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(hyper::header::CONTENT_TYPE, "application/json")
                            .body(err_body)?);
                    }
                }

                // 5. WASM Policy Guardrails Check
                if let Some(deny_resp) = self
                    .evaluate_wasm_guardrail(&rpc_req, extracted_identity.as_ref())
                    .await
                {
                    self.log_audit(
                        start_time,
                        extracted_identity.as_ref(),
                        &rpc_req.method,
                        "DENY_WASM_POLICY",
                    );
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

        // Capture method string before parts.method is moved into the builder
        let method_str = parts.method.as_str().to_string();
        let mut fwd_req = Request::builder().method(parts.method).uri(&target_uri);

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
            // Inject W3C traceparent for distributed tracing propagation
            inject_trace_headers(headers_mut, &trace_ctx);
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

                self.log_audit(
                    start_time,
                    extracted_identity.as_ref(),
                    &req_method_name,
                    "DENY_UPSTREAM_UNREACHABLE",
                );

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

        // Apply DLP Masking to outbound response body if enabled
        let boxed_resp_body = if is_sse {
            resp_body.map_err(hyper::Error::from).boxed()
        } else if let Some(dlp) = &self.dlp_engine {
            let resp_bytes = resp_body.collect().await?.to_bytes();
            let resp_str = String::from_utf8_lossy(&resp_bytes);
            let (masked_str, report) = dlp.mask_payload(&resp_str);
            if report.items_masked_count > 0 {
                info!(
                    items_masked = report.items_masked_count,
                    categories = ?report.masked_categories,
                    "DLP Masking Applied to Outbound Response"
                );
            }
            Full::new(Bytes::from(masked_str))
                .map_err(|_| -> hyper::Error { unreachable!() })
                .boxed()
        } else {
            resp_body.map_err(hyper::Error::from).boxed()
        };

        // Log successful audit entry
        self.log_audit(
            start_time,
            extracted_identity.as_ref(),
            &req_method_name,
            "ALLOW",
        );
        record_http_request(&method_str, resp_parts.status.as_u16(), &req_method_name);
        record_guardrail_latency("total", start_time.elapsed().as_secs_f64());

        Ok(client_resp.body(boxed_resp_body)?)
    }
}
