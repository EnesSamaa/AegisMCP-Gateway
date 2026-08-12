#![allow(missing_docs)]

use aegis_wasm::{
    verify_plugin_signature, PluginHotSwapper, PluginMetadata, WasmEngine, WasmLinker,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::sync::Arc;

#[test]
fn test_ed25519_signature_verification_success_and_failure() {
    let signing_key = SigningKey::from_bytes(&[99u8; 32]);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let payload = b"WASM_COMPONENT_BYTES_MOCK";
    let valid_sig = signing_key.sign(payload);

    let verify_res = verify_plugin_signature(
        payload,
        &valid_sig.to_bytes(),
        verifying_key.as_bytes(),
    );
    assert!(verify_res.is_ok());

    let mut invalid_sig = valid_sig.to_bytes();
    invalid_sig[0] ^= 0x01;
    let fail_res = verify_plugin_signature(
        payload,
        &invalid_sig,
        verifying_key.as_bytes(),
    );
    assert!(fail_res.is_err());
}

#[test]
fn test_plugin_metadata_parsing_and_hotswapper_init() {
    let engine = WasmEngine::new().expect("Engine created");
    let linker = Arc::new(WasmLinker::new(&engine).expect("Linker created"));
    let swapper = PluginHotSwapper::new(engine, linker);

    assert!(swapper.get_pool("pii-filter").is_none());

    let meta = PluginMetadata::new("pii-filter", "2.1.0", "SecurityTeam", "hash99");
    assert_eq!(meta.parsed_version().unwrap().major, 2);
}
