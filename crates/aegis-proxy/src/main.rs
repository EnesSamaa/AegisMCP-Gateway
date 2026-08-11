//! Binary entrypoint for AegisMCP-Gateway.

use aegis_proxy::{McpProxy, ProxyConfig};
use anyhow::Result;
use tokio::signal;
use tokio::sync::oneshot;
use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer().with_target(true).with_thread_ids(false))
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "AegisMCP-Gateway proxy starting"
    );

    let config = ProxyConfig::from_env();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let proxy_handle = tokio::spawn(async move {
        let proxy = McpProxy::new(config);
        if let Err(e) = proxy.run(shutdown_rx).await {
            tracing::error!(error = %e, "Proxy listener stopped unexpectedly");
        }
    });

    signal::ctrl_c().await?;
    info!("Ctrl+C received, shutting down gateway...");
    let _ = shutdown_tx.send(());

    let _ = proxy_handle.await;
    info!("AegisMCP-Gateway shutdown complete.");
    Ok(())
}
