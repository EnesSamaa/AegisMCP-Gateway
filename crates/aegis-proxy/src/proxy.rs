//! Low-level Tokio and Hyper 1.x listener server loop with Tower middleware stack.

use crate::{
    config::schema::GatewayConfig,
    config::ProxyConfig,
    error::ProxyError,
    middleware::{LatencyTrackingLayer, RequestIdLayer, TimeoutLayer, TracingLayer},
    router::ProxyRouter,
};
use aegis_guardrails::{
    AgentRateLimiter, DlpMaskingEngine, IdentityExtractor, LoopBreakerEngine,
    PromptInjectionDetector, TokenTranslator, ToolAuthorizationEngine,
};
use aegis_wasm::PluginRunner;
use hyper_util::{
    rt::TokioIo, server::conn::auto::Builder as ServerConnBuilder, service::TowerToHyperService,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tower::{service_fn, ServiceBuilder};
use tracing::{error, info};

/// Async reverse proxy server for MCP traffic with Tower middleware stack.
pub struct McpProxy {
    config: ProxyConfig,
    router: Arc<ProxyRouter>,
    timeout_duration: Duration,
}

impl McpProxy {
    /// Creates a new `McpProxy` from [`ProxyConfig`].
    #[must_use]
    pub fn new(config: ProxyConfig) -> Self {
        let router = Arc::new(ProxyRouter::new(&config.upstream_url));
        Self {
            config,
            router,
            timeout_duration: Duration::from_secs(30),
        }
    }

    /// Creates a new `McpProxy` with dynamic configuration watch subscription.
    #[must_use]
    pub fn with_config_receiver(
        config: ProxyConfig,
        config_rx: watch::Receiver<GatewayConfig>,
    ) -> Self {
        let router = Arc::new(ProxyRouter::with_config_receiver(
            &config.upstream_url,
            config_rx,
        ));
        Self {
            config,
            router,
            timeout_duration: Duration::from_secs(30),
        }
    }

    /// Attaches a WASM plugin runner for real-time guardrail policy evaluation.
    #[must_use]
    pub fn with_wasm_runner(self, runner: Arc<PluginRunner>) -> Self {
        let router = (*self.router).clone().with_wasm_runner(runner);
        Self {
            config: self.config,
            router: Arc::new(router),
            timeout_duration: self.timeout_duration,
        }
    }

    /// Attaches an Agent Identity Extractor for authentication.
    #[must_use]
    pub fn with_identity_extractor(self, extractor: Arc<IdentityExtractor>) -> Self {
        let router = (*self.router).clone().with_identity_extractor(extractor);
        Self {
            config: self.config,
            router: Arc::new(router),
            timeout_duration: self.timeout_duration,
        }
    }

    /// Attaches an Enterprise Token Translator for credential mapping.
    #[must_use]
    pub fn with_token_translator(self, translator: Arc<TokenTranslator>) -> Self {
        let router = (*self.router).clone().with_token_translator(translator);
        Self {
            config: self.config,
            router: Arc::new(router),
            timeout_duration: self.timeout_duration,
        }
    }

    /// Attaches a Granular Tool Authorization Engine for RBAC/ABAC checks.
    #[must_use]
    pub fn with_tool_authz_engine(self, engine: Arc<ToolAuthorizationEngine>) -> Self {
        let router = (*self.router).clone().with_tool_authz_engine(engine);
        Self {
            config: self.config,
            router: Arc::new(router),
            timeout_duration: self.timeout_duration,
        }
    }

    /// Attaches a Prompt Injection Detector for context hijacking inspection.
    #[must_use]
    pub fn with_prompt_injection_detector(self, detector: Arc<PromptInjectionDetector>) -> Self {
        let router = (*self.router)
            .clone()
            .with_prompt_injection_detector(detector);
        Self {
            config: self.config,
            router: Arc::new(router),
            timeout_duration: self.timeout_duration,
        }
    }

    /// Attaches a DLP Masking Engine for response PII sanitization.
    #[must_use]
    pub fn with_dlp_engine(self, engine: Arc<DlpMaskingEngine>) -> Self {
        let router = (*self.router).clone().with_dlp_engine(engine);
        Self {
            config: self.config,
            router: Arc::new(router),
            timeout_duration: self.timeout_duration,
        }
    }

    /// Attaches an Agent Rate Limiter for request quota enforcement.
    #[must_use]
    pub fn with_rate_limiter(self, limiter: Arc<AgentRateLimiter>) -> Self {
        let router = (*self.router).clone().with_rate_limiter(limiter);
        Self {
            config: self.config,
            router: Arc::new(router),
            timeout_duration: self.timeout_duration,
        }
    }

    /// Attaches a Loop Breaker Engine for runaway agent execution loop prevention.
    #[must_use]
    pub fn with_loop_breaker(self, breaker: Arc<LoopBreakerEngine>) -> Self {
        let router = (*self.router).clone().with_loop_breaker(breaker);
        Self {
            config: self.config,
            router: Arc::new(router),
            timeout_duration: self.timeout_duration,
        }
    }

    /// Sets a custom request timeout duration.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout_duration = timeout;
        self
    }

    /// Runs the proxy listener loop until `shutdown_rx` receives a signal.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] if TCP binding fails.
    pub async fn run(self, mut shutdown_rx: oneshot::Receiver<()>) -> Result<(), ProxyError> {
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        info!(
            listen = %self.config.listen_addr,
            upstream = %self.config.upstream_url,
            timeout_secs = self.timeout_duration.as_secs(),
            "AegisMCP-Gateway proxy listening with Tower middleware pipeline"
        );

        let server_builder = ServerConnBuilder::new(hyper_util::rt::TokioExecutor::new());

        loop {
            tokio::select! {
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((stream, remote_addr)) => {
                            let router = Arc::clone(&self.router);
                            let io = TokioIo::new(stream);
                            let conn_builder = server_builder.clone();
                            let timeout_dur = self.timeout_duration;

                            tokio::spawn(async move {
                                let service = service_fn(move |req| {
                                    let router = Arc::clone(&router);
                                    async move {
                                        router.handle_request(req).await
                                    }
                                });

                                let service_stack = ServiceBuilder::new()
                                    .layer(TimeoutLayer::new(timeout_dur))
                                    .layer(RequestIdLayer::new())
                                    .layer(TracingLayer::new())
                                    .layer(LatencyTrackingLayer::new())
                                    .service(service);

                                let hyper_service = TowerToHyperService::new(service_stack);

                                if let Err(err) = conn_builder.serve_connection(io, hyper_service).await {
                                    error!(remote = %remote_addr, error = %err, "Error serving client connection");
                                }
                            });
                        }
                        Err(err) => {
                            error!(error = %err, "Accept error");
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    info!("Shutdown signal received, stopping proxy listener...");
                    break;
                }
            }
        }

        Ok(())
    }
}
