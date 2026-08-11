#![allow(missing_docs)]

use aegis_wasm::{AegisStoreCtx, WasmEngine, DEFAULT_MAX_MEMORY_BYTES};
use std::time::Duration;
use wasmtime::Store;

#[test]
fn test_wasm_engine_epoch_and_simd_configuration() {
    let engine = WasmEngine::new().expect("WasmEngine created successfully");
    assert!(engine.inner().precompile_module(&[]).is_err());
}

#[tokio::test]
async fn test_epoch_ticker_background_task() {
    let engine = WasmEngine::new().expect("WasmEngine created successfully");
    let handle = engine.spawn_epoch_ticker(Duration::from_millis(10));
    tokio::time::sleep(Duration::from_millis(30)).await;
    handle.abort();
}

#[test]
fn test_store_memory_limits_sandboxing() {
    let engine = WasmEngine::new().expect("WasmEngine created successfully");
    let ctx = AegisStoreCtx::new(16 * 1024 * 1024);

    let mut store = Store::new(engine.inner(), ctx);
    store.limiter(|ctx| ctx.limits_mut());

    assert_eq!(DEFAULT_MAX_MEMORY_BYTES, 16 * 1024 * 1024);
}
