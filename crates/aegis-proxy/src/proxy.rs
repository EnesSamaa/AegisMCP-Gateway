//! Low-level Tokio and Hyper 1.x listener server loop.

use crate::{config::ProxyConfig, error::ProxyError, router::ProxyRouter};
use hyper::service::service_fn;
use hyper_util::{rt::TokioIo, server::conn::auto::Builder as ServerConnBuilder};
use std::sync::Arc;
use tokio::{net::TcpListener, sync::oneshot};
use tracing::{error, info};

/// Async reverse proxy server for MCP traffic.
pub struct McpProxy {
    config: ProxyConfig,
    router: Arc<ProxyRouter>,
}

impl McpProxy {
    /// Creates a new `McpProxy` from [`ProxyConfig`].
    #[must_use]
    pub fn new(config: ProxyConfig) -> Self {
        let router = Arc::new(ProxyRouter::new(&config.upstream_url));
        Self { config, router }
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
            "AegisMCP-Gateway proxy listening"
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

                            tokio::spawn(async move {
                                let service = service_fn(move |req| {
                                    let router = Arc::clone(&router);
                                    async move {
                                        router.handle_request(req).await
                                    }
                                });

                                if let Err(err) = conn_builder.serve_connection(io, service).await {
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
