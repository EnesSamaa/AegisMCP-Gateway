//! WASM engine stub.
//!
//! Full implementation will arrive in Day 4 of the roadmap.
//! The struct is public so dependents can type-check against it today.

use crate::error::WasmError;

/// The central WASM execution engine.
///
/// Wraps a `wasmtime::Engine` configured with async support and the WASI
/// 0.2 preview adapter. Construct via [`WasmEngine::new`].
///
/// # Example (future API)
///
/// ```rust,ignore
/// let engine = WasmEngine::new()?;
/// let result = engine.execute_policy("guardrail.wasm", &payload).await?;
/// ```
#[derive(Debug)]
pub struct WasmEngine {
    // Day 4: this will hold a `wasmtime::Engine` and a `wasmtime::component::Linker`.
    _private: (),
}

impl WasmEngine {
    /// Create a new `WasmEngine` with default configuration.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError::EngineInit`] if Wasmtime cannot be initialised
    /// (e.g., the host does not support the required CPU features).
    pub fn new() -> Result<Self, WasmError> {
        // TODO(Day 4): initialise `wasmtime::Engine` with async support.
        Ok(Self { _private: () })
    }
}

impl Default for WasmEngine {
    fn default() -> Self {
        Self::new().expect("WasmEngine::default() — engine initialisation must not fail")
    }
}
