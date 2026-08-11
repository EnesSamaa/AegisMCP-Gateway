#![allow(missing_docs)]

use aegis_core::{JsonRpcRequest, RequestId};
use aegis_proxy::config::schema::GatewayConfig;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json::json;

fn bench_jsonrpc_deserialization(c: &mut Criterion) {
    let payload = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "sql_query",
            "arguments": {
                "query": "SELECT * FROM users WHERE active = true"
            }
        },
        "id": "req-bench-12345"
    })
    .to_string();

    let bytes = payload.as_bytes();

    c.bench_function("jsonrpc_deserialize_request", |b| {
        b.iter(|| {
            let req: JsonRpcRequest = serde_json::from_slice(black_box(bytes)).unwrap();
            black_box(req);
        });
    });
}

fn bench_route_matching(c: &mut Criterion) {
    let config = GatewayConfig::default();

    c.bench_function("dynamic_route_matching", |b| {
        b.iter(|| {
            let req_path = black_box("/mcp/v1/tools");
            let matched = config
                .routes
                .iter()
                .find(|r| r.enabled && req_path.starts_with(&r.path));
            black_box(matched);
        });
    });
}

fn bench_request_id_generation(c: &mut Criterion) {
    c.bench_function("request_id_generation", |b| {
        b.iter(|| {
            let id = RequestId::new();
            black_box(id);
        });
    });
}

criterion_group!(
    benches,
    bench_jsonrpc_deserialization,
    bench_route_matching,
    bench_request_id_generation
);
criterion_main!(benches);
