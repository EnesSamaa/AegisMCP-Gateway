# AegisMCP-Gateway Architecture Specification

> **Week 1 Milestone Architecture Document (Version 0.1.0-week1)**

AegisMCP-Gateway is a high-performance, Zero-Trust Security Gateway & Reverse Proxy for the Model Context Protocol (MCP) written in Rust.

---

## 🏛️ 1. Multi-Crate Cargo Workspace Architecture

AegisMCP-Gateway is designed as a modular 5-crate Rust workspace:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                           AegisMCP-Gateway                              │
├───────────────┬────────────────┬─────────────────┬──────────────────────┤
│ aegis-core    │ aegis-proxy    │ aegis-wasm      │ aegis-guardrails     │ aegis-proof
├───────────────┼────────────────┼─────────────────┼──────────────────────┤
│ JSON-RPC 2.0  │ Hyper 1.x      │ Wasmtime 47     │ Regex & Rule Engine  │ SHA-256 Merkle
│ MCP Primitives│ Tokio Runtime  │ WASI 0.2 WIT    │ Risk Matrix          │ Audit Proofs
│ Error Hierarchy│ Tower Stack   │ Host Bindings   │ Policy Evaluation    │ Leaf Verification
└───────────────┴────────────────┴─────────────────┴──────────────────────┘
```

### Sub-Crates Overview
1. **`aegis-core`**: Core MCP protocol primitives, JSON-RPC 2.0 data models (`RequestId`, `JsonRpcRequest`, `JsonRpcResponse`, `ToolCall`, `ToolResult`), custom serialization logic, and error hierarchy.
2. **`aegis-proxy`**: Asynchronous reverse proxy engine built on Tokio and Hyper 1.x. Handles HTTP/JSON-RPC, Server-Sent Events (SSE) streaming, Tower middleware stack, dynamic YAML configuration (`config-rs`), and `notify` file-watcher hot-reloading.
3. **`aegis-wasm`**: WebAssembly runtime plugin engine leveraging Wasmtime 47 and WASI 0.2 component model (`wit-bindgen` / `wasmtime::component::bindgen!`) for executing untrusted WASM policy plugins in sandboxed environments.
4. **`aegis-guardrails`**: Inspection engine, regex matchers, priority-ordered policy rules, and risk rating matrix (`low`, `medium`, `high`, `critical`).
5. **`aegis-proof`**: Cryptographic audit logger implementing SHA-256 binary Merkle Trees for producing tamper-evident proofs of policy evaluation history.

---

## 🔄 2. Tower Middleware Pipeline (`aegis-proxy`)

Every incoming HTTP request passes through a stacked `tower::Service` pipeline before reaching the target MCP upstream server:

```text
 Client Request
       │
       ▼
┌──────────────────────┐  Extracts or generates X-Request-ID (UUID v4)
│  RequestIdLayer      │  Reflects header on outgoing response.
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐  Instruments OpenTelemetry/tracing spans with
│  TracingLayer        │  HTTP method, URI, version, and Request ID.
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐  Measures request processing duration using Instant.
│ LatencyTrackingLayer │  Appends X-Response-Time-Us header to response.
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐  Enforces configurable request timeout (tokio::time::timeout).
│  TimeoutLayer        │  Returns 504 Gateway Timeout JSON-RPC error on expiry.
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐  Evaluates dynamic route table (watch::Receiver<GatewayConfig>).
│  ProxyRouter         │  Forwards payload to target upstream MCP URL.
└──────────┬───────────┘
           │
           ▼
  Upstream MCP Server
```

---

## 📄 3. WASI 0.2 WIT Contracts (`wit/`)

Policy inspection contracts are defined using WebAssembly Interface Types (`.wit`) under package `aegis:guardrail@0.1.0`:

- **`types.wit`**: Core data structures (`inspection-context`, `policy-decision`, `violation-risk`, `guardrail-result`).
- **`inspector.wit`**: Main host-guest interface (`inspect: func(ctx: inspection-context) -> guardrail-result`).
- **`world.wit`**: Component world contract (`world guardrail-policy { export inspector; }`).

---

## ⚡ 4. Dynamic YAML Configuration & Hot-Reloading

- **Schema**: Defined in `aegis.yaml` (root) and `crates/aegis-proxy/src/config/schema.rs`.
- **Manager**: `ConfigManager` uses `config-rs` to parse YAML and `notify` to watch file system events.
- **Lock-Free Swapping**: Updates are broadcast down a `tokio::sync::watch` channel. The `ProxyRouter` reads updated route tables on-the-fly without locking worker threads or restarting the gateway process.

---

## 📊 5. Week 1 Benchmarks & Verification

- **Test Suite**: 50 passing unit and integration tests across 5 workspace crates.
- **Clippy**: 100% clean (`cargo clippy --workspace --all-targets -- -D warnings`).
- **Micro-benchmarks**: Criterion benchmarks for JSON-RPC deserialization, dynamic route resolution, and Request ID generation in `crates/aegis-proxy/benches/proxy_throughput.rs`.
