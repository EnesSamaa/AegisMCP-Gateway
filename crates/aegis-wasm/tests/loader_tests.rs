#![allow(missing_docs)]

use aegis_wasm::{ComponentLoader, WasmEngine, WasmLinker};

#[test]
fn test_wasm_linker_and_loader_initialization() {
    let engine = WasmEngine::new().expect("Engine initialised");
    let _linker = WasmLinker::new(&engine).expect("Linker initialised");

    let loader = ComponentLoader::new(engine);
    assert!(loader.get_cached("non-existent").is_none());
}

#[test]
fn test_invalid_wasm_magic_bytes_rejected() {
    let engine = WasmEngine::new().expect("Engine initialised");
    let loader = ComponentLoader::new(engine);

    let invalid_bytes = b"NOT_A_WASM_FILE";
    let res = loader.load_bytes("bad_plugin", invalid_bytes);

    assert!(res.is_err());
}

#[test]
fn test_loader_cache_clearing() {
    let engine = WasmEngine::new().expect("Engine initialised");
    let loader = ComponentLoader::new(engine);

    assert!(loader.get_cached("plugin_1").is_none());
    loader.clear_cache();
    assert!(loader.get_cached("plugin_1").is_none());
}
