#![allow(missing_docs)]

use aegis_proxy::{McpProxy, ProxyConfig};
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

// Mock Upstream MCP Server
async fn run_mock_upstream(listener: TcpListener) {
    let server_builder = ServerBuilder::new(TokioExecutor::new());
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let io = TokioIo::new(stream);
        let conn_builder = server_builder.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| async move {
                let path = req.uri().path();
                if path == "/mcp" {
                    let body =
                        full_body(r#"{"jsonrpc":"2.0","result":{"status":"success"},"id":1}"#);
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .header("content-type", "application/json")
                            .body(body)
                            .unwrap(),
                    )
                } else {
                    let body = full_body("Not Found");
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(body)
                            .unwrap(),
                    )
                }
            });
            let _ = conn_builder.serve_connection(io, service).await;
        });
    }
}

#[tokio::test]
async fn test_proxy_wasm_guardrail_integration() {
    // 1. Start Upstream Server
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(run_mock_upstream(upstream_listener));

    // 2. Start Proxy
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    drop(proxy_listener);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let config = ProxyConfig::new(proxy_addr, format!("http://{upstream_addr}"));

    let proxy_handle = tokio::spawn(async move {
        let proxy = McpProxy::new(config);
        proxy.run(shutdown_rx).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(150)).await;

    // 3. Client sends clean MCP request
    let client = Client::builder(TokioExecutor::new()).build_http();
    let proxy_url = format!("http://{proxy_addr}/mcp");

    let req = Request::builder()
        .method("POST")
        .uri(&proxy_url)
        .header("content-type", "application/json")
        .body(
            Full::new(Bytes::from(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"sql_query"},"id":100}"#,
            ))
            .map_err(|_| -> hyper::Error { unreachable!() })
            .boxed(),
        )
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(body_bytes.contains(&b"status"[0]));

    // Shutdown proxy
    let _ = shutdown_tx.send(());
    let _ = proxy_handle.await;
}
