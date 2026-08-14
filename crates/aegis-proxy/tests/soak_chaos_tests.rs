#![allow(missing_docs)]
//! End-to-End Soak & Chaos Testing Suite for AegisMCP-Gateway.
//!
//! Validates memory stability, resilience against upstream MCP server failures,
//! malformed payload injection, and payload boundary enforcement.

use aegis_guardrails::DlpMaskingEngine;
use aegis_proof::AuditLedger;
use aegis_proxy::{init_metrics, McpProxy, ProxyConfig};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{body::Incoming, service::service_fn, Request, Response, StatusCode};
use hyper_util::{
    client::legacy::Client, rt::TokioExecutor, rt::TokioIo,
    server::conn::auto::Builder as ServerBuilder,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::{net::TcpListener, sync::oneshot};

fn full_body(data: impl Into<Bytes>) -> BoxBody<Bytes, hyper::Error> {
    Full::new(data.into())
        .map_err(|_| -> hyper::Error { unreachable!() })
        .boxed()
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    full_body(Bytes::new())
}

// ---------------------------------------------------------------------------
// Mock Upstream Servers for Chaos Scenarios
// ---------------------------------------------------------------------------

/// Normal mock upstream for soak tests.
async fn run_healthy_upstream(listener: TcpListener, request_counter: Arc<AtomicUsize>) {
    let builder = ServerBuilder::new(TokioExecutor::new());
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let io = TokioIo::new(stream);
        let conn = builder.clone();
        let counter = Arc::clone(&request_counter);

        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::Relaxed);
                    let _ = req.into_body().collect().await;
                    let body =
                        full_body(r#"{"jsonrpc":"2.0","result":{"status":"processed"},"id":1}"#);
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(body)
                            .unwrap(),
                    )
                }
            });
            let _ = conn.serve_connection(io, svc).await;
        });
    }
}

/// Upstream that crashes or resets TCP connections immediately.
async fn run_crashing_upstream(listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        // Immediately drop stream to simulate sudden upstream crash
        drop(stream);
    }
}

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

async fn start_gateway(upstream_url: String) -> (std::net::SocketAddr, oneshot::Sender<()>) {
    init_metrics();
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    drop(proxy_listener);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let cfg = ProxyConfig::new(proxy_addr, upstream_url);
    let ledger = Arc::new(AuditLedger::new());
    let dlp = Arc::new(DlpMaskingEngine::new());

    tokio::spawn(async move {
        McpProxy::new(cfg)
            .with_audit_ledger(ledger)
            .with_dlp_engine(dlp)
            .run(shutdown_rx)
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(150)).await;
    (proxy_addr, shutdown_tx)
}

// ---------------------------------------------------------------------------
// 1. High-Concurrency Soak & Stability Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_soak_high_throughput_concurrency() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_counter = Arc::new(AtomicUsize::new(0));

    tokio::spawn(run_healthy_upstream(
        upstream_listener,
        Arc::clone(&upstream_counter),
    ));

    let (proxy_addr, shutdown_tx) = start_gateway(format!("http://{upstream_addr}")).await;

    let concurrent_workers = 10;
    let requests_per_worker = 25;
    let total_expected_requests = concurrent_workers * requests_per_worker;

    let mut handles = Vec::new();

    for worker_id in 0..concurrent_workers {
        let handle = tokio::spawn(async move {
            let client =
                Client::builder(TokioExecutor::new()).build_http::<BoxBody<Bytes, hyper::Error>>();

            for req_id in 0..requests_per_worker {
                let payload = format!(
                    r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"worker":{worker_id},"seq":{req_id}}},"id":{req_id}}}"#
                );

                let req = Request::builder()
                    .method("POST")
                    .uri(format!("http://{proxy_addr}/mcp"))
                    .header("content-type", "application/json")
                    .header("X-API-Key", format!("agent-key-{worker_id}"))
                    .body(full_body(payload))
                    .unwrap();

                let resp = client.request(req).await.expect("Request must not drop");
                assert_eq!(resp.status(), StatusCode::OK);

                let body = resp.into_body().collect().await.unwrap().to_bytes();
                let json: serde_json::Value =
                    serde_json::from_slice(&body).expect("Must return valid JSON");
                assert_eq!(json["result"]["status"], "processed");
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.unwrap();
    }

    // Verify all requests successfully reached upstream through the proxy
    assert_eq!(
        upstream_counter.load(Ordering::Relaxed),
        total_expected_requests
    );

    let _ = shutdown_tx.send(());
}

// ---------------------------------------------------------------------------
// 2. Upstream Crash & Chaos Fault Tolerance
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_upstream_chaos_disconnect_and_bad_gateway() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    tokio::spawn(run_crashing_upstream(upstream_listener));

    let (proxy_addr, shutdown_tx) = start_gateway(format!("http://{upstream_addr}")).await;

    let client = Client::builder(TokioExecutor::new()).build_http::<BoxBody<Bytes, hyper::Error>>();

    let req = Request::builder()
        .method("POST")
        .uri(format!("http://{proxy_addr}/mcp"))
        .header("content-type", "application/json")
        .body(full_body(
            r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#,
        ))
        .unwrap();

    let resp = client.request(req).await.unwrap();

    // Gateway must gracefully return 502 Bad Gateway without panicking
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("Must return valid error JSON");

    assert_eq!(json["error"]["code"], -32010);
    assert_eq!(json["error"]["message"], "Upstream server unreachable");

    let _ = shutdown_tx.send(());
}

// ---------------------------------------------------------------------------
// 3. Malformed Payload Chaos & Protocol Boundary Enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_malformed_json_chaos_injection() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(run_healthy_upstream(
        upstream_listener,
        Arc::new(AtomicUsize::new(0)),
    ));

    let (proxy_addr, shutdown_tx) = start_gateway(format!("http://{upstream_addr}")).await;
    let client = Client::builder(TokioExecutor::new()).build_http::<BoxBody<Bytes, hyper::Error>>();

    // 1. Truncated JSON payload
    let req_truncated = Request::builder()
        .method("POST")
        .uri(format!("http://{proxy_addr}/mcp"))
        .header("content-type", "application/json")
        .body(full_body(
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"#,
        ))
        .unwrap();

    let resp_truncated = client.request(req_truncated).await.unwrap();
    assert_eq!(resp_truncated.status(), StatusCode::BAD_REQUEST);

    let body = resp_truncated
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], -32700);

    // 2. Binary garbage with JSON Content-Type
    let req_garbage = Request::builder()
        .method("POST")
        .uri(format!("http://{proxy_addr}/mcp"))
        .header("content-type", "application/json")
        .body(full_body(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0x00]))
        .unwrap();

    let resp_garbage = client.request(req_garbage).await.unwrap();
    assert_eq!(resp_garbage.status(), StatusCode::BAD_REQUEST);

    let _ = shutdown_tx.send(());
}

// ---------------------------------------------------------------------------
// 4. Oversized Payload Boundary Test (> 4MB)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_oversized_payload_rejection() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(run_healthy_upstream(
        upstream_listener,
        Arc::new(AtomicUsize::new(0)),
    ));

    let (proxy_addr, shutdown_tx) = start_gateway(format!("http://{upstream_addr}")).await;
    let client = Client::builder(TokioExecutor::new()).build_http::<BoxBody<Bytes, hyper::Error>>();

    // Create 5MB payload (exceeding the 4MB threshold)
    let five_mb = 5 * 1024 * 1024;
    let large_data = vec![b'A'; five_mb];

    let req_oversized = Request::builder()
        .method("POST")
        .uri(format!("http://{proxy_addr}/mcp"))
        .header("content-type", "application/json")
        .body(full_body(large_data))
        .unwrap();

    let resp = client.request(req_oversized).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], -32000);
    assert!(json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Payload Too Large"));

    let _ = shutdown_tx.send(());
}

// ---------------------------------------------------------------------------
// 5. Public Error Sanitization & Masking
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_public_error_sanitization_no_leakage() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(run_healthy_upstream(
        upstream_listener,
        Arc::new(AtomicUsize::new(0)),
    ));

    let (proxy_addr, shutdown_tx) = start_gateway(format!("http://{upstream_addr}")).await;
    let client = Client::builder(TokioExecutor::new()).build_http::<BoxBody<Bytes, hyper::Error>>();

    // Query non-existent proof route
    let req = Request::builder()
        .uri(format!(
            "http://{proxy_addr}/v1/proofs/non-existent-uuid-999"
        ))
        .body(empty_body())
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();

    // Verify no system path, database connection string, or panic trace is leaked
    assert!(!text.contains("C:\\"), "Must not leak filesystem paths");
    assert!(!text.contains("/home/"), "Must not leak Unix paths");
    assert!(!text.contains("postgres://"), "Must not leak database URIs");
    assert!(
        !text.contains("panicked at"),
        "Must not leak panic backtraces"
    );

    let _ = shutdown_tx.send(());
}
