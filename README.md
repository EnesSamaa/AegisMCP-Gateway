# AegisMCP-Gateway

> **High-performance, Zero-Trust Security Gateway & Reverse Proxy for the Model Context Protocol — written in Rust.**

[![CI](https://github.com/EnesSamaa/AegisMCP-Gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/EnesSamaa/AegisMCP-Gateway/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)
![Rust](https://img.shields.io/badge/rust-stable-orange)
![Tests](https://img.shields.io/badge/tests-50%20passed-brightgreen)
![Tag](https://img.shields.io/badge/release-v0.1.0--week1-blue)

---

## Overview

AegisMCP-Gateway is an enterprise-grade reverse proxy that enforces Zero-Trust security policies on [Model Context Protocol (MCP)](https://modelcontextprotocol.io) traffic between AI clients and tool servers.

| Capability | Crate / Module | Description |
|---|---|---|
| Core MCP / JSON-RPC primitives | `aegis-core` | Data models, protocol types, zero-copy serialization, custom errors |
| Async HTTP & SSE Reverse Proxy | `aegis-proxy` | Hyper 1.x + Tokio engine, SSE streaming, dynamic route table |
| Tower Middleware Stack | `aegis-proxy::middleware` | Request ID tracking, OpenTelemetry tracing, microsecond latency, timeouts |
| Dynamic Config & Hot-Reloading | `aegis-proxy::config` | YAML schema (`aegis.yaml`), `config-rs` parsing, `notify` watcher |
| WASM Plugin Sandbox | `aegis-wasm` | Wasmtime 47, WASI 0.2 Component Model WIT contracts (`aegis:guardrail`) |
| Guardrails & Policy Engine | `aegis-guardrails` | Regex matchers, priority-ordered rules, risk matrix |
| Cryptographic Audit Trail | `aegis-proof` | SHA-256 binary Merkle trees for audit proof generation |

---

## Architecture Flow

```text
 Client Request
       │
       ▼
┌──────────────────────┐  Extracts / generates X-Request-ID (UUID v4)
│  RequestIdLayer      │  Reflects header on response.
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

Detailed architectural specifications are available in [`docs/architecture.md`](docs/architecture.md).

---

## Workspace Layout

```text
AegisMCP-Gateway/
├── Cargo.toml                  # Workspace root
├── aegis.yaml                  # Enterprise sample YAML configuration
├── wit/                        # WASI 0.2 WIT contracts (aegis:guardrail@0.1.0)
│   ├── types.wit
│   ├── inspector.wit
│   └── world.wit
├── crates/
│   ├── aegis-core/             # Protocol primitives & error types
│   ├── aegis-proxy/            # Reverse-proxy binary (aegis-gateway), Tower stack, hot-reloader
│   │   └── benches/            # Criterion micro-benchmarks (proxy_throughput.rs)
│   ├── aegis-wasm/             # Wasmtime 47 WASM runtime & host bindings
│   ├── aegis-guardrails/       # Inspection engine & rules
│   └── aegis-proof/            # Merkle tree & audit proofs
├── docs/                       # Architecture documentation (architecture.md)
└── .github/workflows/ci.yml    # GitHub Actions CI pipeline
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/EnesSamaa/AegisMCP-Gateway.git
cd AegisMCP-Gateway

# Check workspace compilation
cargo check --workspace

# Run full test suite (50 unit & integration tests)
cargo test --workspace

# Run Clippy lints
cargo clippy --workspace --all-targets -- -D warnings

# Run Criterion micro-benchmarks
cargo bench -p aegis-proxy

# Launch Gateway Server with dynamic YAML config
cargo run --bin aegis-gateway
```

---

## Development Roadmap — Week 1 Completed ✅

| Day | Milestone | Status |
|-----|-----------|--------|
| **Day 1** | Enterprise Rust Cargo Workspace, GitHub Actions CI, Code Quality Tooling | ✅ Done |
| **Day 2** | MCP & JSON-RPC 2.0 Data Models, Error Handling Hierarchy, Serialization | ✅ Done |
| **Day 3** | WASI 0.2 WIT Interface Definitions (`aegis:guardrail`) & Wasmtime Host Bindings | ✅ Done |
| **Day 4** | Tokio & Hyper 1.x Reverse Proxy Engine with SSE Streaming Support | ✅ Done |
| **Day 5** | Tower Middleware Stack (Request ID, Tracing, Microsecond Latency, Timeouts) | ✅ Done |
| **Day 6** | Dynamic YAML Configuration Engine & Zero-Downtime Hot-Reloading (`config-rs` + `notify`) | ✅ Done |
| **Day 7** | Week 1 Finalization: E2E Concurrency Tests, Criterion Benchmarks, Architecture Docs | ✅ Done (`v0.1.0-week1`) |

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
