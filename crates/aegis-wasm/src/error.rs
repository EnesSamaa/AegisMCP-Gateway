//! Error types for the `aegis-wasm` crate.

use thiserror::Error;

/// Errors that can be emitted by the WASM runtime.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WasmError {
    /// Failed to initialise the Wasmtime engine.
    #[error("WASM engine initialisation failed: {0}")]
    EngineInit(String),

    /// Failed to compile or instantiate a WASM module / component.
    #[error("WASM module load failed: {0}")]
    ModuleLoad(String),

    /// Failed to compile a WASM component.
    #[error("WASM compilation failed: {0}")]
    Compilation(String),

    /// Failed to bind WASI host interfaces to linker.
    #[error("Host interface binding failed: {0}")]
    HostInterfaceBind(String),

    /// A trap occurred during WASM execution.
    #[error("WASM trap during execution: {0}")]
    Trap(String),

    /// The WASM guest exceeded its resource quota.
    #[error("WASM resource limit exceeded: {resource}")]
    ResourceLimit {
        /// The resource that was exhausted (e.g., "memory", "fuel").
        resource: String,
    },
}
