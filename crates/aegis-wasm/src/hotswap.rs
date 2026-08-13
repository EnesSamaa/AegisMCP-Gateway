//! Zero-Downtime Hot-Swapping Engine for WASM Policy Plugin Pools.

use crate::engine::WasmEngine;
use crate::error::WasmError;
use crate::linker::WasmLinker;
use crate::metadata::PluginMetadata;
use crate::pool::{PoolConfig, WasmInstancePool};
use crate::security::verify_plugin_signature;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::info;

/// Thread-safe hot-swappable container for active WASM plugin pools.
#[derive(Clone)]
pub struct PluginHotSwapper {
    engine: WasmEngine,
    linker: Arc<WasmLinker>,
    pools_tx: watch::Sender<HashMap<String, WasmInstancePool>>,
    pools_rx: watch::Receiver<HashMap<String, WasmInstancePool>>,
}

impl PluginHotSwapper {
    /// Creates a new `PluginHotSwapper` instance.
    #[must_use]
    pub fn new(engine: WasmEngine, linker: Arc<WasmLinker>) -> Self {
        let (pools_tx, pools_rx) = watch::channel(HashMap::new());
        Self {
            engine,
            linker,
            pools_tx,
            pools_rx,
        }
    }

    /// Returns a subscription to active plugin pools.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<HashMap<String, WasmInstancePool>> {
        self.pools_rx.clone()
    }

    /// Hot-swaps or registers a verified WASM plugin component into the active pool table.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] if signature verification or compilation fails.
    pub fn swap_plugin(
        &self,
        metadata: &PluginMetadata,
        wasm_bytes: &[u8],
        signature_bytes: &[u8; 64],
        public_key_bytes: &[u8; 32],
        pool_config: PoolConfig,
    ) -> Result<(), WasmError> {
        // 1. Verify Ed25519 Signature
        verify_plugin_signature(wasm_bytes, signature_bytes, public_key_bytes)?;

        // 2. Validate semver version format
        let version = metadata.parsed_version()?;

        // 3. Compile Component
        let component = wasmtime::component::Component::new(self.engine.inner(), wasm_bytes)
            .map_err(|e| {
                WasmError::Compilation(format!(
                    "Compilation failed for plugin '{}': {e}",
                    metadata.plugin_id
                ))
            })?;

        // 4. Build WasmInstancePool
        let new_pool = WasmInstancePool::new(
            self.engine.clone(),
            self.linker.clone(),
            component,
            pool_config,
        )?;

        // 5. Atomically update pool table via watch channel
        let mut current_map = self.pools_rx.borrow().clone();
        current_map.insert(metadata.plugin_id.clone(), new_pool);

        info!(
            plugin_id = %metadata.plugin_id,
            version = %version,
            "Hot-swapped WASM plugin pool successfully"
        );

        let _ = self.pools_tx.send(current_map);
        Ok(())
    }

    /// Retrieves an active [`WasmInstancePool`] for `plugin_id` if present.
    #[must_use]
    pub fn get_pool(&self, plugin_id: &str) -> Option<WasmInstancePool> {
        self.pools_rx.borrow().get(plugin_id).cloned()
    }
}
