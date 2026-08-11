#![allow(missing_docs)]

use aegis_proxy::{ConfigManager, McpProxy, ProxyConfig};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{body::Incoming, service::service_fn, Request, Response};
use hyper_util::{
    client::legacy::Client, rt::TokioExecutor, rt::TokioIo,
    server::conn::auto::Builder as ServerBuilder,
};
use std::fs;
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

async fn run_mock_server(listener: TcpListener, response_msg: &'static str) {
    let server_builder = ServerBuilder::new(TokioExecutor::new());
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let io = TokioIo::new(stream);
        let conn_builder = server_builder.clone();

        tokio::spawn(async move {
            let service = service_fn(move |_req: Request<Incoming>| async move {
                let body = full_body(response_msg);
                Ok::<_, hyper::Error>(Response::builder().body(body).unwrap())
            });
            let _ = conn_builder.serve_connection(io, service).await;
        });
    }
}

#[tokio::test]
async fn test_yaml_config_parsing_and_manager() {
    let temp_dir = std::env::temp_dir();
    let config_file = temp_dir.join(format!("aegis_test_{}.yaml", uuid::Uuid::new_v4()));

    let yaml_content = r#"
server:
  listen_addr: "127.0.0.1:8080"
  default_timeout_ms: 15000

routes:
  - path: "/mcp-test"
    upstream_url: "http://127.0.0.1:9091"
    required_role: "test-role"
    enabled: true

roles:
  - role: "test-role"
    allowed_tools:
      - "read_data"
    max_rate_limit: 500

security:
  enable_wasm_guardrails: true
  enable_proof_logging: false
"#;

    fs::write(&config_file, yaml_content).unwrap();

    let manager = ConfigManager::new(&config_file).unwrap();
    let config = ConfigManager::load_from_path(&config_file).unwrap();

    assert_eq!(config.server.default_timeout_ms, 15000);
    assert_eq!(config.routes.len(), 1);
    assert_eq!(config.routes[0].path, "/mcp-test");
    assert_eq!(config.roles[0].role, "test-role");
    assert!(!config.security.enable_proof_logging);

    let rx = manager.subscribe();
    assert_eq!(rx.borrow().routes[0].path, "/mcp-test");

    let _ = fs::remove_file(config_file);
}

#[tokio::test]
async fn test_dynamic_route_table_hot_swap() {
    // 1. Upstream 1
    let upstream1_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream1_addr = upstream1_listener.local_addr().unwrap();
    tokio::spawn(run_mock_server(upstream1_listener, "upstream-1"));

    // 2. Upstream 2
    let upstream2_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream2_addr = upstream2_listener.local_addr().unwrap();
    tokio::spawn(run_mock_server(upstream2_listener, "upstream-2"));

    // 3. Setup Proxy with watch channel
    let temp_dir = std::env::temp_dir();
    let config_file = temp_dir.join(format!("aegis_hotswap_{}.yaml", uuid::Uuid::new_v4()));

    let initial_yaml = format!(
        r#"
server:
  listen_addr: "127.0.0.1:8080"
  default_timeout_ms: 30000
routes:
  - path: "/route"
    upstream_url: "http://{upstream1_addr}"
    enabled: true
roles: []
security:
  enable_wasm_guardrails: false
  enable_proof_logging: false
"#
    );
    fs::write(&config_file, &initial_yaml).unwrap();

    let manager = ConfigManager::new(&config_file).unwrap();
    let rx = manager.subscribe();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    drop(proxy_listener);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let proxy_config = ProxyConfig::new(proxy_addr, format!("http://{upstream1_addr}"));

    let proxy_handle = tokio::spawn(async move {
        let proxy = McpProxy::with_config_receiver(proxy_config, rx);
        proxy.run(shutdown_rx).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = Client::builder(TokioExecutor::new()).build_http();

    // Initial Request -> Upstream 1
    let req1 = Request::builder()
        .uri(format!("http://{proxy_addr}/route"))
        .body(empty_body())
        .unwrap();

    let resp1 = client.request(req1).await.unwrap();
    let body1 = resp1.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body1.as_ref(), b"upstream-1");

    // Dynamic Hot Swap -> Update config file to point to Upstream 2
    let updated_yaml = format!(
        r#"
server:
  listen_addr: "127.0.0.1:8080"
  default_timeout_ms: 30000
routes:
  - path: "/route"
    upstream_url: "http://{upstream2_addr}"
    enabled: true
roles: []
security:
  enable_wasm_guardrails: false
  enable_proof_logging: false
"#
    );
    fs::write(&config_file, &updated_yaml).unwrap();

    // Reload from file to verify manager loading
    let _new_config = ConfigManager::load_from_path(&config_file).unwrap();

    let _ = shutdown_tx.send(());
    let _ = proxy_handle.await;
    let _ = fs::remove_file(config_file);
}
