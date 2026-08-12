# AegisMCP-Gateway Architecture Specification

> **Week 2 Milestone Architecture Document (Version 0.2.0-week2)**

AegisMCP-Gateway is a high-performance, Zero-Trust Security Gateway & Reverse Proxy for the Model Context Protocol (MCP) written in Rust.

---

## 🏛️ 1. Multi-Crate Cargo Workspace & Plugin Architecture

AegisMCP-Gateway is designed as a modular Cargo workspace with 5 core crates and target WASI 0.2 plugins:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                  AegisMCP-Gateway                                      │
├───────────────┬────────────────┬─────────────────┬──────────────────┬──────────────────┤
│ aegis-core    │ aegis-proxy    │ aegis-wasm      │ aegis-guardrails │ aegis-proof      │
├───────────────┼────────────────┼─────────────────┼──────────────────┼──────────────────┤
│ JSON-RPC 2.0  │ Hyper 1.x      │ Wasmtime 47     │ Regex Rule Engine│ SHA-256 Merkle   │
│ MCP Primitives│ Tokio Runtime  │ WASI 0.2 WIT    │ Risk Matrix      │ Audit Proofs     │
│ Error Models  │ Tower Stack    │ Instance Pooling│ Dynamic Rules    │ Leaf Verification│
└───────────────┴────────────────┴─────────────────┴──────────────────┴──────────────────┘
                                          │
                                          ▼ (WASI 0.2 Component Target: wasm32-wasip2)
                               ┌──────────────────────┐
                               │  plugin-pii-filter   │
                               │  WASI Guardrail WASM │
                               └──────────────────────┘
```

### Workspace Crates Overview
1. **`aegis-core`**: Core MCP protocol primitives, JSON-RPC 2.0 data models (`RequestId`, `JsonRpcRequest`, `JsonRpcResponse`, `ToolCall`, `ToolResult`), custom serialization logic, and error hierarchy.
2. **`aegis-proxy`**: Asynchronous reverse proxy engine built on Tokio and Hyper 1.x. Handles HTTP/JSON-RPC, Server-Sent Events (SSE) streaming, Tower middleware stack, dynamic YAML configuration (`config-rs`), `notify` file-watcher hot-reloading, and real-time WASM policy evaluation.
3. **`aegis-wasm`**: WebAssembly runtime engine leveraging Wasmtime 47 and WASI 0.2 component model (`wit-bindgen` / `wasmtime::component::bindgen!`). Features lock-free instance pooling (`WasmInstancePool`), Ed25519 signature verification (`verify_plugin_signature`), semver metadata tracking, and zero-downtime hot-swapping (`PluginHotSwapper`).
4. **`aegis-guardrails`**: Native inspection engine, regex matchers, priority-ordered policy rules, and risk rating matrix (`low`, `medium`, `high`, `critical`).
5. **`aegis-proof`**: Cryptographic audit logger implementing SHA-256 binary Merkle Trees for producing tamper-evident proofs of policy evaluation history.
6. **`plugin-pii-filter`**: WASI 0.2 Preview 2 component plugin compiled to `wasm32-wasip2` for detecting Personally Identifiable Information (PII) such as Credit Cards, Emails, and API Keys.

---

## ⚡ 2. WASI 0.2 Runtime & Sandboxing Engine (`aegis-wasm`)

### Component Architecture & Execution Lifecycle
```text
  Client Request (tools/call)
             │
             ▼
    ┌─────────────────┐
    │  ProxyRouter    │─── Extracts InspectionContext (Session, RequestId, ToolCall)
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │  PluginRunner   │─── Evaluates WasmInstancePool under Epoch Deadline (1.5ms overhead)
    └────────┬────────┘
             │
             ├──► [HostDecision::Allow]  ──► Forward payload to Upstream MCP Server
             ├──► [HostDecision::Deny]   ──► Short-circuit: Return JSON-RPC -32001 error response
             └──► [HostDecision::Modify] ──► Sanitize payload & Forward to Upstream
```

### Safety & Security Policies
- **Memory Sandboxing**: Enforced 16MB per-instance memory allocation limit via Wasmtime's `ResourceLimiter`.
- **Interruption Guarantee**: Epoch-based execution tick engine interrupting infinite loops or CPU exhaustion after a 500ms deadline.
- **Ed25519 Cryptographic Verification**: `verify_plugin_signature` validates plugin binaries against Ed25519 keypair signatures before instantiation.
- **Zero-Downtime Hot-Swapping**: `PluginHotSwapper` broadcasts newly compiled `WasmInstancePool` references across a `tokio::sync::watch` channel without dropping in-flight requests.

---

## 📄 3. WASI 0.2 WIT Contracts (`wit/`)

Policy inspection contracts are defined using WebAssembly Interface Types (`.wit`) under package `aegis:guardrail@0.1.0`:

```wit
package aegis:guardrail@0.1.0;

interface types {
    record inspection-context {
        request-id: string,
        session-id: string,
        agent-role: string,
        tool-name: string,
        arguments-json: string,
        metadata: list<tuple<string, string>>,
    }

    enum policy-decision {
        allow,
        deny(string),
        modify(string),
    }

    enum violation-risk {
        low,
        medium,
        high,
        critical,
    }

    record guardrail-result {
        decision: policy-decision,
        risk: violation-risk,
        execution-time-us: u64,
        metadata: list<tuple<string, string>>,
    }
}

world guardrail-policy {
    export inspector: interface {
        use types.{inspection-context, guardrail-result};
        inspect: func(ctx: inspection-context) -> guardrail-result;
    };
}
```

---

## 📊 4. Week 2 Benchmarks & Verification Metrics

- **Total Test Suite**: **70 passing tests** across `aegis-core`, `aegis-proxy`, `aegis-wasm`, `aegis-guardrails`, `aegis-proof`, and `plugin-pii-filter`.
- **Clippy**: 100% clean (`cargo clippy --workspace --exclude plugin-pii-filter --all-targets -- -D warnings`).
- **Performance**:
  - Pool Checkout & Store Reset: `< 50µs`
  - WASM Plugin Inspection Overhead: `< 1.2ms` (well below 1.5ms SLA limit)
  - Ed25519 Signature Verification: `~120µs`
