#![allow(missing_docs, unused_must_use)]

use aegis_core::{AgentIdentity, McpSessionContext, RequestId, SessionId, ToolCall};
use aegis_wasm::{build_inspection_context, verify_plugin_signature, AegisStoreCtx, PoolConfig};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

fn bench_ed25519_signature_verification(c: &mut Criterion) {
    let signing_key = SigningKey::from_bytes(&[55u8; 32]);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let wasm_payload = b"\0asm\x0d\x00\x01\x00_benchmark_wasm_binary_bytes";
    let signature = signing_key.sign(wasm_payload);
    let sig_bytes = signature.to_bytes();
    let pub_bytes = verifying_key.to_bytes();

    c.bench_function("ed25519_signature_verification", |b| {
        b.iter(|| {
            let res = verify_plugin_signature(
                black_box(wasm_payload),
                black_box(&sig_bytes),
                black_box(&pub_bytes),
            );
            assert!(res.is_ok());
        });
    });
}

fn bench_wit_context_building(c: &mut Criterion) {
    let identity = AgentIdentity::new("client-1", "BenchAgent", "analyst");
    let session = McpSessionContext::new(SessionId::new(), identity, 1_700_000_000_000);
    let req_id = RequestId::new();
    let tool_call = ToolCall::new(
        "sql_query",
        Some(serde_json::json!({"query": "SELECT * FROM orders WHERE total > 1000"})),
    );

    c.bench_function("wit_context_building", |b| {
        b.iter(|| {
            let ctx = build_inspection_context(
                black_box(&session),
                black_box(req_id),
                black_box(&tool_call),
            );
            black_box(ctx);
        });
    });
}

fn bench_store_context_reset(c: &mut Criterion) {
    let mut store_ctx = AegisStoreCtx::new(16 * 1024 * 1024);

    c.bench_function("store_context_reset", |b| {
        b.iter(|| {
            let _ = store_ctx.limits_mut();
            black_box(&store_ctx);
        });
    });
}

fn bench_pool_config_defaults(c: &mut Criterion) {
    c.bench_function("pool_config_defaults", |b| {
        b.iter(|| {
            let config = PoolConfig::default();
            black_box(config);
        });
    });
}

criterion_group!(
    benches,
    bench_ed25519_signature_verification,
    bench_wit_context_building,
    bench_store_context_reset,
    bench_pool_config_defaults
);
criterion_main!(benches);
