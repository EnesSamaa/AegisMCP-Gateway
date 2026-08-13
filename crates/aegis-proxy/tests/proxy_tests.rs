#![allow(missing_docs)]

use aegis_proxy::{McpProxy, ProxyConfig};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{body::Incoming, service::service_fn, Request, Response, StatusCode};
use hyper_util::{
    client::legacy::Client, rt::TokioExecutor, rt::TokioIo,
    server::conn::auto::Builder as ServerBuilder,
};
use tokio::{net::TcpListener, sync::oneshot};

fn full_body(data: impl Into<Bytes>) -> BoxBody<Bytes, hyper::Error> {
    Full::new(data.into())
        .map_err(|_| -> hyper::Error { unreachable!() })
        .boxed()
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    full_body(Bytes::new())
}

async fn run_mock_upstream(listener: TcpListener) {
    let server_builder = ServerBuilder::new(TokioExecutor::new());
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let io = TokioIo::new(stream);
        let conn_builder = server_builder.clone();

        tokio::spawn(async move {
            let service = service_fn(|req: Request<Incoming>| async move {
                let path = req.uri().path();
                if path == "/mcp" {
                    let body = full_body(r#"{"jsonrpc":"2.0","result":{"tools":[]},"id":1}"#);
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .header("content-type", "application/json")
                            .body(body)
                            .unwrap(),
                    )
                } else if path == "/sse" {
                    let body = full_body("event: message\ndata: {\"test\":\"sse\"}\n\n");
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .header("content-type", "text/event-stream")
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
async fn test_proxy_health_and_mcp_forwarding() {
    // 1. Start Mock Upstream
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

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // 3. Test /health
    let client = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .uri(format!("http://{proxy_addr}/health"))
        .body(empty_body())
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(body_bytes.starts_with(b"{\"status\":\"ok\""));

    // 4. Test /mcp Forwarding
    let req_mcp = Request::builder()
        .method("POST")
        .uri(format!("http://{proxy_addr}/mcp"))
        .header("content-type", "application/json")
        .body(full_body(
            r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#,
        ))
        .unwrap();

    let resp_mcp = client.request(req_mcp).await.unwrap();
    assert_eq!(resp_mcp.status(), StatusCode::OK);
    let mcp_bytes = resp_mcp.into_body().collect().await.unwrap().to_bytes();
    assert!(mcp_bytes.contains(&b"tools"[0]));

    // 5. Test /sse Stream Forwarding
    let req_sse = Request::builder()
        .uri(format!("http://{proxy_addr}/sse"))
        .header("accept", "text/event-stream")
        .body(empty_body())
        .unwrap();

    let resp_sse = client.request(req_sse).await.unwrap();
    assert_eq!(resp_sse.status(), StatusCode::OK);
    assert_eq!(
        resp_sse.headers().get("content-type").unwrap(),
        "text/event-stream"
    );
    let sse_bytes = resp_sse.into_body().collect().await.unwrap().to_bytes();
    assert!(sse_bytes.starts_with(b"event: message"));

    // Shutdown
    let _ = shutdown_tx.send(());
    let _ = proxy_handle.await;
}
