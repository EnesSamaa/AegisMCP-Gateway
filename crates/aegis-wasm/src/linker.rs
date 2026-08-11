//! WASI Preview 2 Linker setup for AegisMCP-Gateway component modules.

use crate::engine::WasmEngine;
use crate::error::WasmError;
use crate::store::AegisStoreCtx;
use wasmtime::component::Linker;

/// Linker manager for WASI 0.2 component modules.
pub struct WasmLinker {
    linker: Linker<AegisStoreCtx>,
}

impl WasmLinker {
    /// Creates and configures a new [`WasmLinker`] bound to the provided [`WasmEngine`].
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] if linker initialization fails.
    pub fn new(engine: &WasmEngine) -> Result<Self, WasmError> {
        let linker = Linker::new(engine.inner());
        Ok(Self { linker })
    }

    /// Returns a reference to the inner [`Linker`].
    #[must_use]
    pub const fn inner(&self) -> &Linker<AegisStoreCtx> {
        &self.linker
    }

    /// Returns a mutable reference to the inner [`Linker`].
    pub const fn inner_mut(&mut self) -> &mut Linker<AegisStoreCtx> {
        &mut self.linker
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_linker_init() {
        let engine = WasmEngine::new().expect("WasmEngine initialised");
        let mut linker = WasmLinker::new(&engine).expect("Linker initialised");
        let _ = linker.inner_mut();
    }
}
