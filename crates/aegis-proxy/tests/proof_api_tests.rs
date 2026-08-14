#![allow(missing_docs)]
//! Integration tests for the cryptographic proof HTTP API endpoints.
//!
//! Tests `GET /v1/proofs/root` and `GET /v1/proofs/{request_id}`.

use aegis_proof::{AuditLedger, AuditMerkleProof};
use aegis_proxy::{McpProxy, ProxyConfig};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{body::Incoming, service::service_fn, Request, Response, StatusCode};
use hyper_util::{
    client::legacy::Client, rt::TokioExecutor, rt::TokioIo,
    server::conn::auto::Builder as ServerBuilder,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::{net::TcpListener, sync::oneshot};

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Full::new(Bytes::new())
        .map_err(|_| -> hyper::Error { unreachable!() })
        .boxed()
}

/// Minimal mock upstream that returns a generic JSON response.
async fn run_mock_upstream(listener: TcpListener) {
    let builder = ServerBuilder::new(TokioExecutor::new());
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let io = TokioIo::new(stream);
        let conn = builder.clone();
        tokio::spawn(async move {
            let svc = service_fn(|_req: Request<Incoming>| async move {
                let body = Full::new(Bytes::from(r#"{"jsonrpc":"2.0","result":{},"id":1}"#))
                    .map_err(|_| -> hyper::Error { unreachable!() })
                    .boxed();
                Ok::<_, hyper::Error>(
                    Response::builder()
                        .header("content-type", "application/json")
                        .body(body)
                        .unwrap(),
                )
            });
            let _ = conn.serve_connection(io, svc).await;
        });
    }
}

/// Boots a proxy with an attached `AuditLedger` and pre-seeded entries,
/// returning the proxy address and the ledger reference.
async fn start_proof_proxy() -> (std::net::SocketAddr, Arc<AuditLedger>, oneshot::Sender<()>) {
    // Mock upstream
    let up_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up_listener.local_addr().unwrap();
    tokio::spawn(run_mock_upstream(up_listener));

    // Ledger with 4 pre-seeded entries
    let ledger = Arc::new(AuditLedger::new());
    for i in 0..4_u64 {
        ledger.log_entry(
            format!("test-req-{i}"),
            1_000_000 + i,
            "agent-test",
            "tools/call",
            "ALLOW",
            50 + i,
        );
    }
    // Allow background worker to ingest
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Proxy listener
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    drop(proxy_listener);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let cfg = ProxyConfig::new(proxy_addr, format!("http://{up_addr}"));
    let ledger_clone = Arc::clone(&ledger);

    tokio::spawn(async move {
        McpProxy::new(cfg)
            .with_audit_ledger(ledger_clone)
            .run(shutdown_rx)
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(150)).await;
    (proxy_addr, ledger, shutdown_tx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_proof_root_endpoint_returns_merkle_root() {
    let (proxy_addr, _ledger, shutdown_tx) = start_proof_proxy().await;

    let client = Client::builder(TokioExecutor::new()).build_http::<BoxBody<Bytes, hyper::Error>>();
    let req = Request::builder()
        .uri(format!("http://{proxy_addr}/v1/proofs/root"))
        .body(empty_body())
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(
        json["merkle_root"].is_string(),
        "merkle_root must be a hex string: {json}"
    );
    let root = json["merkle_root"].as_str().unwrap();
    assert_eq!(root.len(), 64, "Root must be 64 hex chars");

    let count = json["leaf_count"].as_u64().unwrap();
    assert_eq!(count, 4, "Leaf count must equal seeded entries");

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_proof_request_id_endpoint_returns_valid_proof() {
    let (proxy_addr, ledger, shutdown_tx) = start_proof_proxy().await;

    let expected_root = ledger.get_merkle_root().await.expect("Root must exist");

    let client = Client::builder(TokioExecutor::new()).build_http::<BoxBody<Bytes, hyper::Error>>();
    let req = Request::builder()
        .uri(format!("http://{proxy_addr}/v1/proofs/test-req-0"))
        .body(empty_body())
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let proof: AuditMerkleProof = serde_json::from_slice(&body).expect("Must deserialise proof");

    assert!(
        proof.verify(&expected_root),
        "HTTP-exported proof must verify against live Merkle root"
    );

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_proof_unknown_request_id_returns_404() {
    let (proxy_addr, _ledger, shutdown_tx) = start_proof_proxy().await;

    let client = Client::builder(TokioExecutor::new()).build_http::<BoxBody<Bytes, hyper::Error>>();
    let req = Request::builder()
        .uri(format!("http://{proxy_addr}/v1/proofs/no-such-request-id"))
        .body(empty_body())
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].is_string(), "Error field must be present");

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_proof_exported_all_entries_verify() {
    let (proxy_addr, ledger, shutdown_tx) = start_proof_proxy().await;

    let root = ledger.get_merkle_root().await.expect("Root must exist");
    let client = Client::builder(TokioExecutor::new()).build_http::<BoxBody<Bytes, hyper::Error>>();

    for i in 0..4_u64 {
        let req = Request::builder()
            .uri(format!("http://{proxy_addr}/v1/proofs/test-req-{i}"))
            .body(empty_body())
            .unwrap();

        let resp = client.request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "Entry {i} must return 200");

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let proof: AuditMerkleProof =
            serde_json::from_slice(&body).expect("Must deserialise proof");

        assert!(
            proof.verify(&root),
            "Proof for test-req-{i} must verify against root"
        );
    }

    let _ = shutdown_tx.send(());
}
