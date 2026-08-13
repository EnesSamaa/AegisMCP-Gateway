//! Dynamic configuration manager with hot-reloading file watcher.

use crate::config::schema::GatewayConfig;
use crate::error::ProxyError;
use config::{Config, File, FileFormat};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use tokio::sync::watch;
use tracing::{error, info, warn};

/// Thread-safe dynamic configuration manager with hot-reloading capabilities.
pub struct ConfigManager {
    config_path: PathBuf,
    tx: watch::Sender<GatewayConfig>,
    rx: watch::Receiver<GatewayConfig>,
}

impl ConfigManager {
    /// Initializes `ConfigManager` from a YAML file path or returns fallback default config.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] if file reading fails.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, ProxyError> {
        let config_path = path.as_ref().to_path_buf();
        let initial_config = Self::load_from_path(&config_path)?;

        let (tx, rx) = watch::channel(initial_config);

        Ok(Self {
            config_path,
            tx,
            rx,
        })
    }

    /// Loads and parses YAML configuration from specified file path.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] if parsing fails.
    pub fn load_from_path(path: &Path) -> Result<GatewayConfig, ProxyError> {
        if !path.exists() {
            warn!(path = %path.display(), "Config file missing, using default GatewayConfig");
            return Ok(GatewayConfig::default());
        }

        let builder = Config::builder().add_source(File::from(path).format(FileFormat::Yaml));

        let settings = builder
            .build()
            .map_err(|e| ProxyError::Upstream(format!("Config build error: {e}")))?;

        let gateway_config: GatewayConfig = settings
            .try_deserialize()
            .map_err(|e| ProxyError::Upstream(format!("Config deserialize error: {e}")))?;

        Ok(gateway_config)
    }

    /// Returns a [`watch::Receiver`] to monitor real-time configuration changes.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<GatewayConfig> {
        self.rx.clone()
    }

    /// Spawns a background file watcher task to monitor `config_path` for changes and update the channel.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] if file watcher initialization fails.
    pub fn start_watcher(&self) -> Result<RecommendedWatcher, ProxyError> {
        let tx = self.tx.clone();
        let config_path = self.config_path.clone();

        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                if event.kind.is_modify() || event.kind.is_create() {
                    match Self::load_from_path(&config_path) {
                        Ok(new_config) => {
                            info!(
                                "Gateway configuration hot-reloaded successfully from {}",
                                config_path.display()
                            );
                            let _ = tx.send(new_config);
                        }
                        Err(err) => {
                            error!(error = %err, "Failed to hot-reload configuration file");
                        }
                    }
                }
            }
        })
        .map_err(|e| ProxyError::Upstream(format!("Notify watcher error: {e}")))?;

        let target_watch_dir = self.config_path.parent().unwrap_or_else(|| Path::new("."));

        watcher
            .watch(target_watch_dir, RecursiveMode::NonRecursive)
            .map_err(|e| ProxyError::Upstream(format!("Notify watch setup error: {e}")))?;

        Ok(watcher)
    }
}
