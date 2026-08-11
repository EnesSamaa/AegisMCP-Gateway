#![allow(missing_docs)]

use aegis_proxy::{
    middleware::{X_REQUEST_ID, X_RESPONSE_TIME_US},
    McpProxy, ProxyConfig,
};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{body::Incoming, service::service_fn, Request, Response, StatusCode};
use hyper_util::{
    client::legacy::Client, rt::TokioExecutor, rt::TokioIo,
    server::conn::auto::Builder as ServerBuilder,
};
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

async fn run_slow_mock_upstream(listener: TcpListener, delay: Duration) {
    let server_builder = ServerBuilder::new(TokioExecutor::new());
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let io = TokioIo::new(stream);
        let conn_builder = server_builder.clone();

        tokio::spawn(async move {
            let service = service_fn(move |_req: Request<Incoming>| async move {
                tokio::time::sleep(delay).await;
                let body = full_body("slow response");
                Ok::<_, hyper::Error>(Response::builder().body(body).unwrap())
            });
            let _ = conn_builder.serve_connection(io, service).await;
        });
    }
}

#[tokio::test]
async fn test_middleware_request_id_and_latency_headers() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(run_slow_mock_upstream(upstream_listener, Duration::from_millis(5)));

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    drop(proxy_listener);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let config = ProxyConfig::new(proxy_addr, format!("http://{upstream_addr}"));

    let proxy_handle = tokio::spawn(async move {
        let proxy = McpProxy::new(config);
        proxy.run(shutdown_rx).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .uri(format!("http://{proxy_addr}/mcp"))
        .header(X_REQUEST_ID, "custom-req-id-999")
        .body(empty_body())
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify headers
    assert_eq!(
        resp.headers().get(X_REQUEST_ID).unwrap(),
        "custom-req-id-999"
    );
    assert!(resp.headers().contains_key(X_RESPONSE_TIME_US));

    let _ = shutdown_tx.send(());
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn test_middleware_timeout_expiry() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    // Upstream takes 500ms
    tokio::spawn(run_slow_mock_upstream(upstream_listener, Duration::from_millis(500)));

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    drop(proxy_listener);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let config = ProxyConfig::new(proxy_addr, format!("http://{upstream_addr}"));

    let proxy_handle = tokio::spawn(async move {
        // Proxy timeout set to 50ms (will expire)
        let proxy = McpProxy::new(config).with_timeout(Duration::from_millis(50));
        proxy.run(shutdown_rx).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .uri(format!("http://{proxy_addr}/mcp"))
        .body(empty_body())
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(body_bytes.contains(&b"-32011"[0]));

    let _ = shutdown_tx.send(());
    let _ = proxy_handle.await;
}
