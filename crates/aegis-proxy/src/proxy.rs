//! Low-level Tokio and Hyper 1.x listener server loop with Tower middleware stack.

use crate::{
    config::ProxyConfig,
    error::ProxyError,
    middleware::{LatencyTrackingLayer, RequestIdLayer, TimeoutLayer, TracingLayer},
    router::ProxyRouter,
};
use hyper_util::{
    rt::TokioIo, server::conn::auto::Builder as ServerConnBuilder,
    service::TowerToHyperService,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::{net::TcpListener, sync::oneshot};
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
