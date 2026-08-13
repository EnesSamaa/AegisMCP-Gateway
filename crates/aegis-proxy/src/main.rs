//! Binary entrypoint for AegisMCP-Gateway.

use aegis_proxy::{ConfigManager, McpProxy, ProxyConfig};
use anyhow::Result;
use std::path::Path;
use tokio::signal;
use tokio::sync::oneshot;
use tracing::{error, info};
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

    let config_path = Path::new("aegis.yaml");
    let config_manager = ConfigManager::new(config_path)?;
    let config_rx = config_manager.subscribe();

    // Start background file watcher for hot-reloading
    let _watcher = match config_manager.start_watcher() {
        Ok(w) => {
            info!(
                "Dynamic configuration hot-reloader active for {}",
                config_path.display()
            );
            Some(w)
        }
        Err(e) => {
            error!(error = %e, "Could not start file watcher, dynamic hot-reloading disabled");
            None
        }
    };

    let proxy_config = ProxyConfig::from_env();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let proxy_handle = tokio::spawn(async move {
        let proxy = McpProxy::with_config_receiver(proxy_config, config_rx);
        if let Err(e) = proxy.run(shutdown_rx).await {
            error!(error = %e, "Proxy listener stopped unexpectedly");
        }
    });

    signal::ctrl_c().await?;
    info!("Ctrl+C received, shutting down gateway...");
    let _ = shutdown_tx.send(());

    let _ = proxy_handle.await;
    info!("AegisMCP-Gateway shutdown complete.");
    Ok(())
}
