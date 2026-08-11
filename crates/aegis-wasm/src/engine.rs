//! Wasmtime runtime engine integration with epoch interruption and SIMD support.

use crate::error::WasmError;
use std::time::Duration;
use tokio::task::JoinHandle;
use wasmtime::{Config, Engine, OptLevel};

/// Execution sandbox engine for WASM policy plugins.
#[derive(Clone)]
pub struct WasmEngine {
    engine: Engine,
}

impl WasmEngine {
    /// Creates a new `WasmEngine` with component model, epoch interruption, and SIMD enabled.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError::EngineInit`] if Wasmtime engine setup fails.
    pub fn new() -> Result<Self, WasmError> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.epoch_interruption(true);
        config.wasm_simd(true);
        config.cranelift_opt_level(OptLevel::Speed);

        let engine = Engine::new(&config)
            .map_err(|e| WasmError::EngineInit(e.to_string()))?;

        Ok(Self { engine })
    }

    /// Returns a reference to the underlying [`wasmtime::Engine`].
    #[must_use]
    pub const fn inner(&self) -> &Engine {
        &self.engine
    }

    /// Spawns a Tokio background task that increments the engine epoch at the specified interval.
    #[must_use]
    pub fn spawn_epoch_ticker(&self, interval: Duration) -> JoinHandle<()> {
        let engine = self.engine.clone();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            loop {
                timer.tick().await;
                engine.increment_epoch();
            }
        })
    }
}

impl Default for WasmEngine {
    fn default() -> Self {
        Self::new().expect("WasmEngine initialisation failed")
    }
}

impl std::fmt::Debug for WasmEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmEngine").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_engine_init() {
        let engine = WasmEngine::new().expect("Engine created successfully");
        assert!(engine.inner().precompile_module(&[]).is_err());
    }

    #[tokio::test]
    async fn test_epoch_ticker_spawning() {
        let engine = WasmEngine::new().expect("Engine created successfully");
        let handle = engine.spawn_epoch_ticker(Duration::from_millis(5));
        tokio::time::sleep(Duration::from_millis(20)).await;
        handle.abort();
    }
}
