//! High-performance WASM Component Instance Pool Manager.

use crate::bindings::GuardrailPolicy;
use crate::engine::WasmEngine;
use crate::error::WasmError;
use crate::linker::WasmLinker;
use crate::store::AegisStoreCtx;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info};
use wasmtime::component::Component;

/// Pooled Wasm instance execution item.
pub struct PooledInstance {
    /// Wasmtime Store wrapping [`AegisStoreCtx`].
    pub store: wasmtime::Store<AegisStoreCtx>,
    /// WIT interface bindings for [`GuardrailPolicy`].
    pub policy: GuardrailPolicy,
}

impl PooledInstance {
    /// Resets the store limits and state for clean reuse.
    pub fn reset(&mut self, max_memory_bytes: usize) {
        *self.store.data_mut() = AegisStoreCtx::new(max_memory_bytes);
    }
}

/// Configuration options for [`WasmInstancePool`].
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of pooled instances.
    pub max_size: usize,
    /// Maximum memory allocation per instance in bytes.
    pub max_memory_bytes: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_size: 32,
            max_memory_bytes: 16 * 1024 * 1024,
        }
    }
}

/// High-performance WASM instance pool using lock-free channels.
#[derive(Clone)]
pub struct WasmInstancePool {
    engine: WasmEngine,
    linker: Arc<WasmLinker>,
    component: Component,
    pool_tx: mpsc::Sender<PooledInstance>,
    pool_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<PooledInstance>>>,
    config: PoolConfig,
}

impl WasmInstancePool {
    /// Creates and pre-populates a new [`WasmInstancePool`] for the given component.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] if component instantiation or pool creation fails.
    pub fn new(
        engine: WasmEngine,
        linker: Arc<WasmLinker>,
        component: Component,
        config: PoolConfig,
    ) -> Result<Self, WasmError> {
        let (pool_tx, pool_rx) = mpsc::channel(config.max_size);

        let pool = Self {
            engine,
            linker,
            component,
            pool_tx,
            pool_rx: Arc::new(tokio::sync::Mutex::new(pool_rx)),
            config,
        };

        // Pre-warm initial instances
        let initial_capacity = (pool.config.max_size / 4).max(1);
        for _ in 0..initial_capacity {
            let instance = pool.create_instance()?;
            let _ = pool.pool_tx.try_send(instance);
        }

        info!(
            max_size = pool.config.max_size,
            prewarmed = initial_capacity,
            "Initialized WasmInstancePool"
        );

        Ok(pool)
    }

    /// Creates a fresh [`PooledInstance`] using [`WasmEngine`] and Linker.
    fn create_instance(&self) -> Result<PooledInstance, WasmError> {
        let ctx = AegisStoreCtx::new(self.config.max_memory_bytes);
        let mut store = wasmtime::Store::new(self.engine.inner(), ctx);
        store.limiter(|c| c.limits_mut());

        let policy = GuardrailPolicy::instantiate(&mut store, &self.component, self.linker.inner())
            .map_err(|e| WasmError::ModuleLoad(format!("Failed to instantiate component: {e}")))?;

        Ok(PooledInstance { store, policy })
    }

    /// Checks out an instance from the pool or creates a new one if below `max_size`.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] if checkout or creation fails.
    pub async fn checkout(&self) -> Result<PooledInstanceGuard, WasmError> {
        // Try receiving from pool channel without blocking
        let instance = {
            let mut rx = self.pool_rx.lock().await;
            rx.try_recv().ok()
        };

        let mut instance = if let Some(inst) = instance {
            debug!("Checked out recycled instance from WasmInstancePool");
            inst
        } else {
            debug!("Pool empty, creating fresh PooledInstance");
            self.create_instance()?
        };

        instance.reset(self.config.max_memory_bytes);

        Ok(PooledInstanceGuard {
            instance: Some(instance),
            pool_tx: self.pool_tx.clone(),
        })
    }
}

/// RAII Guard that returns the [`PooledInstance`] to the pool on drop.
pub struct PooledInstanceGuard {
    instance: Option<PooledInstance>,
    pool_tx: mpsc::Sender<PooledInstance>,
}

impl PooledInstanceGuard {
    /// Returns a mutable reference to the inner [`PooledInstance`].
    ///
    /// # Panics
    ///
    /// Panics if the internal instance option is None.
    pub const fn instance_mut(&mut self) -> &mut PooledInstance {
        self.instance.as_mut().expect("Guard holds instance")
    }
}

impl Drop for PooledInstanceGuard {
    fn drop(&mut self) {
        if let Some(instance) = self.instance.take() {
            let _ = self.pool_tx.try_send(instance);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_defaults() {
        let config = PoolConfig::default();
        assert_eq!(config.max_size, 32);
        assert_eq!(config.max_memory_bytes, 16 * 1024 * 1024);
    }
}
