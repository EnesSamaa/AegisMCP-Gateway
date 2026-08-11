//! Wasmtime runtime engine integration.
//!
//! Provides [`WasmEngine`] which manages the Wasmtime [`wasmtime::Engine`]
//! configured for WASI 0.2 component execution.

use crate::error::WasmError;
use wasmtime::{Config, Engine};

/// Execution sandbox engine for WASM policy plugins.
#[derive(Clone)]
pub struct WasmEngine {
    engine: Engine,
}

impl WasmEngine {
    /// Creates a new `WasmEngine` with component model support enabled.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError::EngineInit`] if Wasmtime engine setup fails.
    pub fn new() -> Result<Self, WasmError> {
        let mut config = Config::new();
        config.wasm_component_model(true);

        let engine = Engine::new(&config)
            .map_err(|e| WasmError::EngineInit(e.to_string()))?;

        Ok(Self { engine })
    }

    /// Returns a reference to the underlying [`wasmtime::Engine`].
    #[must_use]
    pub const fn inner(&self) -> &Engine {
        &self.engine
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
}
