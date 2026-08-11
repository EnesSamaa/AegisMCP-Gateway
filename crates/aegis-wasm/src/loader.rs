//! Dynamic WASM Component Loader and in-memory compilation cache.

use crate::engine::WasmEngine;
use crate::error::WasmError;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use tracing::info;
use wasmtime::component::Component;

/// Dynamic WASM component loader with thread-safe in-memory compilation cache.
#[derive(Clone)]
pub struct ComponentLoader {
    engine: WasmEngine,
    cache: Arc<RwLock<HashMap<String, Component>>>,
}

impl ComponentLoader {
    /// Creates a new `ComponentLoader` for the given [`WasmEngine`].
    #[must_use]
    pub fn new(engine: WasmEngine) -> Self {
        Self {
            engine,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Loads and compiles a WebAssembly component binary from raw bytes.
    ///
    /// Caches the compiled [`Component`] under `plugin_id`.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError::Compilation`] if bytecode validation or compilation fails.
    pub fn load_bytes(
        &self,
        plugin_id: impl Into<String>,
        bytes: &[u8],
    ) -> Result<Component, WasmError> {
        let plugin_id = plugin_id.into();

        // Check cache first
        if let Ok(read_guard) = self.cache.read() {
            if let Some(cached_component) = read_guard.get(&plugin_id) {
                return Ok(cached_component.clone());
            }
        }

        // Validate WASM header magic bytes (\0asm)
        if bytes.len() < 8 || &bytes[0..4] != b"\0asm" {
            return Err(WasmError::Compilation(format!(
                "Invalid WebAssembly header magic bytes for plugin '{plugin_id}'"
            )));
        }

        info!(plugin_id = %plugin_id, bytes_len = bytes.len(), "Compiling WASI 0.2 component module");

        let component = Component::new(self.engine.inner(), bytes)
            .map_err(|e| WasmError::Compilation(format!("Failed to compile component '{plugin_id}': {e}")))?;

        if let Ok(mut write_guard) = self.cache.write() {
            write_guard.insert(plugin_id, component.clone());
        }

        Ok(component)
    }

    /// Loads and compiles a WebAssembly component binary from a file on disk.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] if file I/O or compilation fails.
    pub fn load_file(
        &self,
        plugin_id: impl Into<String>,
        path: impl AsRef<Path>,
    ) -> Result<Component, WasmError> {
        let path_ref = path.as_ref();
        let bytes = std::fs::read(path_ref)
            .map_err(|e| WasmError::Compilation(format!("Failed to read Wasm file {}: {e}", path_ref.display())))?;
        self.load_bytes(plugin_id, &bytes)
    }

    /// Returns a cached [`Component`] by `plugin_id` if present.
    #[must_use]
    pub fn get_cached(&self, plugin_id: &str) -> Option<Component> {
        self.cache.read().ok()?.get(plugin_id).cloned()
    }

    /// Clears all entries from the in-memory component cache.
    pub fn clear_cache(&self) {
        if let Ok(mut write_guard) = self.cache.write() {
            write_guard.clear();
        }
    }
}
