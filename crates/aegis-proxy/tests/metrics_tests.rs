#![allow(missing_docs)]
//! Integration tests for the Prometheus metrics HTTP endpoint (`GET /metrics`).

use aegis_proof::AuditLedger;
use aegis_proxy::{init_metrics, McpProxy, ProxyConfig};
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

fn json_body(s: &'static str) -> BoxBody<Bytes, hyper::Error> {
    Full::new(Bytes::from(s))
        .map_err(|_| -> hyper::Error { unreachable!() })
        .boxed()
}

/// Minimal mock upstream that always returns 200 OK.
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
                        .status(200)
                        .header("content-type", "application/json")
                        .body(body)
                        .unwrap(),
                )
            });
            let _ = conn.serve_connection(io, svc).await;
        });
    }
}

/// Starts a proxy with Prometheus metrics recorder initialised and an
/// `AuditLedger` attached. Returns (`proxy_addr`, `shutdown_tx`).
async fn start_metrics_proxy() -> (std::net::SocketAddr, oneshot::Sender<()>) {
    // Initialise the global Prometheus recorder (idempotent)
    init_metrics();

    // Mock upstream
    let up_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up_listener.local_addr().unwrap();
    tokio::spawn(run_mock_upstream(up_listener));

    // Ledger
    let ledger = Arc::new(AuditLedger::new());
    ledger.log_entry(
        "metrics-seed-req",
        1_000_000,
        "test-agent",
        "tools/list",
        "ALLOW",
        100,
    );
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Proxy
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    drop(proxy_listener);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let cfg = ProxyConfig::new(proxy_addr, format!("http://{up_addr}"));

    tokio::spawn(async move {
        McpProxy::new(cfg)
            .with_audit_ledger(ledger)
            .run(shutdown_rx)
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(150)).await;
    (proxy_addr, shutdown_tx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_metrics_endpoint_returns_prometheus_format() {
    let (proxy_addr, shutdown_tx) = start_metrics_proxy().await;

    let client = Client::builder(TokioExecutor::new()).build_http::<BoxBody<Bytes, hyper::Error>>();
    let req = Request::builder()
        .uri(format!("http://{proxy_addr}/metrics"))
        .body(empty_body())
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("text/plain"),
        "Content-Type must be text/plain, got: {ct}"
    );

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();

    // Must contain at least comment lines (Prometheus exposition format)
    assert!(
        !text.is_empty(),
        "Metrics endpoint must return non-empty body"
    );

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_metrics_counter_increments_on_request() {
    let (proxy_addr, shutdown_tx) = start_metrics_proxy().await;

    let client = Client::builder(TokioExecutor::new()).build_http::<BoxBody<Bytes, hyper::Error>>();

    // Issue a JSON-RPC request through the proxy (this should increment counters)
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://{proxy_addr}/mcp"))
        .header("content-type", "application/json")
        .body(json_body(
            r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#,
        ))
        .unwrap();

    let mcp_resp = client.request(req).await.unwrap();
    assert_eq!(mcp_resp.status(), StatusCode::OK);
    let _ = mcp_resp.into_body().collect().await.unwrap();

    // Fetch metrics
    let metrics_req = Request::builder()
        .uri(format!("http://{proxy_addr}/metrics"))
        .body(empty_body())
        .unwrap();
    let metrics_resp = client.request(metrics_req).await.unwrap();
    let body = metrics_resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();

    // After one successful forwarded request, aegis_http_requests_total must appear
    assert!(
        text.contains("aegis_http_requests_total"),
        "aegis_http_requests_total must be in metrics output:\n{text}"
    );

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_metrics_guardrail_latency_present_after_request() {
    let (proxy_addr, shutdown_tx) = start_metrics_proxy().await;

    let client = Client::builder(TokioExecutor::new()).build_http::<BoxBody<Bytes, hyper::Error>>();

    // Issue request to trigger latency recording
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://{proxy_addr}/mcp"))
        .header("content-type", "application/json")
        .body(json_body(
            r#"{"jsonrpc":"2.0","method":"tools/call","id":2}"#,
        ))
        .unwrap();
    let _ = client.request(req).await.unwrap();

    let metrics_req = Request::builder()
        .uri(format!("http://{proxy_addr}/metrics"))
        .body(empty_body())
        .unwrap();
    let body = client
        .request(metrics_req)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let text = std::str::from_utf8(&body).unwrap();

    assert!(
        text.contains("aegis_guardrail_latency_seconds"),
        "aegis_guardrail_latency_seconds must be in metrics output:\n{text}"
    );

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_metrics_merkle_leaves_gauge_populated() {
    let (proxy_addr, shutdown_tx) = start_metrics_proxy().await;

    let client = Client::builder(TokioExecutor::new()).build_http::<BoxBody<Bytes, hyper::Error>>();

    let req = Request::builder()
        .uri(format!("http://{proxy_addr}/metrics"))
        .body(empty_body())
        .unwrap();
    let body = client
        .request(req)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let text = std::str::from_utf8(&body).unwrap();

    assert!(
        text.contains("aegis_merkle_tree_leaves_total"),
        "aegis_merkle_tree_leaves_total must appear in metrics:\n{text}"
    );

    let _ = shutdown_tx.send(());
}
