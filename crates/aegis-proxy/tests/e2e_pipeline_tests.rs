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
use std::sync::atomic::{AtomicU64, Ordering};
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

// Mock Upstream Server tracking request counts
async fn run_mock_upstream_mcp(listener: TcpListener, request_counter: Arc<AtomicU64>) {
    let server_builder = ServerBuilder::new(TokioExecutor::new());
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let io = TokioIo::new(stream);
        let conn_builder = server_builder.clone();
        let counter = Arc::clone(&request_counter);

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let path = req.uri().path();
                    if path == "/mcp" {
                        let body = full_body(
                            r#"{"jsonrpc":"2.0","result":{"tools":[{"name":"sql_query"}]},"id":1}"#,
                        );
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .header("content-type", "application/json")
                                .body(body)
                                .unwrap(),
                        )
                    } else if path == "/sse" {
                        let body = full_body("event: message\ndata: {\"mcp\":\"stream\"}\n\n");
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
                }
            });
            let _ = conn_builder.serve_connection(io, service).await;
        });
    }
}

#[tokio::test]
async fn test_e2e_high_concurrency_pipeline() {
    let request_counter = Arc::new(AtomicU64::new(0));

    // 1. Start Upstream Server
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(run_mock_upstream_mcp(
        upstream_listener,
        Arc::clone(&request_counter),
    ));

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

    // 3. Launch 100 Parallel Requests
    let client = Arc::new(Client::builder(TokioExecutor::new()).build_http());
    let mut tasks = Vec::new();
    let num_requests: u64 = 100;

    for i in 0..num_requests {
        let client_clone = Arc::clone(&client);
        let proxy_url = format!("http://{proxy_addr}/mcp");

        tasks.push(tokio::spawn(async move {
            let req = Request::builder()
                .method("POST")
                .uri(&proxy_url)
                .header("content-type", "application/json")
                .header(X_REQUEST_ID, format!("e2e-req-{i}"))
                .body(
                    Full::new(Bytes::from(format!(
                        r#"{{"jsonrpc":"2.0","method":"tools/list","id":{i}}}"#
                    )))
                    .map_err(|_| -> hyper::Error { unreachable!() })
                    .boxed(),
                )
                .unwrap();

            let resp = client_clone.request(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);

            // Assert Middleware Header Reflections
            assert_eq!(
                resp.headers().get(X_REQUEST_ID).unwrap().to_str().unwrap(),
                format!("e2e-req-{i}")
            );
            assert!(resp.headers().contains_key(X_RESPONSE_TIME_US));

            let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
            assert!(body_bytes.contains(&b"sql_query"[0]));
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }

    // Assert total upstream request count
    assert_eq!(request_counter.load(Ordering::SeqCst), num_requests);

    // 4. Test SSE Stream Concurrent Call
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

    // Clean shutdown
    let _ = shutdown_tx.send(());
    let _ = proxy_handle.await;
}
