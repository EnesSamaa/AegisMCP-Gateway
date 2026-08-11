//! Sandboxed WASM execution store context and resource limits.

use wasmtime::{StoreLimits, StoreLimitsBuilder};

/// Default maximum memory allocation per WASM plugin instance (16 MB).
pub const DEFAULT_MAX_MEMORY_BYTES: usize = 16 * 1024 * 1024;

/// Sandboxed execution state context for WASM policy plugins.
#[derive(Debug)]
pub struct AegisStoreCtx {
    limits: StoreLimits,
}

impl AegisStoreCtx {
    /// Creates a new `AegisStoreCtx` with specified maximum memory allocation in bytes.
    #[must_use]
    pub fn new(max_memory_bytes: usize) -> Self {
        let limits = StoreLimitsBuilder::new()
            .memory_size(max_memory_bytes)
            .build();
        Self { limits }
    }

    /// Mutable reference to the internal [`StoreLimits`].
    #[must_use]
    pub const fn limits_mut(&mut self) -> &mut StoreLimits {
        &mut self.limits
    }
}

impl Default for AegisStoreCtx {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_MEMORY_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_context_init() {
        let mut ctx = AegisStoreCtx::default();
        let _ = ctx.limits_mut();
    }
}
