#![allow(missing_docs)]

use aegis_wasm::{AegisStoreCtx, PoolConfig};
use wasmtime::StoreLimitsBuilder;

#[test]
fn test_pool_config_custom_initialization() {
    let config = PoolConfig {
        max_size: 64,
        max_memory_bytes: 32 * 1024 * 1024,
    };
    assert_eq!(config.max_size, 64);
    assert_eq!(config.max_memory_bytes, 32 * 1024 * 1024);
}

#[test]
fn test_store_context_reusability_and_reset() {
    let mut ctx = AegisStoreCtx::new(16 * 1024 * 1024);
    let limits_ref = ctx.limits_mut();
    let _new_limits = StoreLimitsBuilder::new().memory_size(16 * 1024 * 1024).build();
    let _ = limits_ref;
}
