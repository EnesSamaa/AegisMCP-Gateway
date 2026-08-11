# AegisMCP-Gateway

> **High-performance, Zero-Trust Security Gateway & Reverse Proxy for the Model Context Protocol — written in Rust.**

[![CI](https://github.com/EnesSamaa/AegisMCP-Gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/EnesSamaa/AegisMCP-Gateway/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)
![Rust](https://img.shields.io/badge/rust-stable-orange)

---

## Overview

AegisMCP-Gateway is an enterprise-grade reverse proxy that enforces Zero-Trust security policies on [Model Context Protocol (MCP)](https://modelcontextprotocol.io) traffic between AI clients and tool servers.

| Capability | Crate |
|---|---|
| Core MCP / JSON-RPC types | `aegis-core` |
| Async HTTP reverse proxy (Hyper v1 + Tokio) | `aegis-proxy` |
| WASM policy plugin runtime (Wasmtime 47 + WASI 0.2) | `aegis-wasm` |
| Content inspection & guardrail rules | `aegis-guardrails` |
| Cryptographic audit trail & Merkle proofs | `aegis-proof` |

---

## Workspace layout

```
AegisMCP-Gateway/
├── Cargo.toml                  # Workspace root
├── crates/
│   ├── aegis-core/             # Protocol primitives & error types
│   ├── aegis-proxy/            # Reverse-proxy binary (aegis-gateway)
│   ├── aegis-wasm/             # Wasmtime WASM runtime
│   ├── aegis-guardrails/       # Inspection engine & rules
│   └── aegis-proof/            # Merkle tree & audit proofs
├── .github/workflows/ci.yml    # GitHub Actions CI
├── .rustfmt.toml               # Rustfmt configuration
└── .clippy.toml                # Clippy thresholds
```

---

## Quick start

```bash
# Clone
git clone https://github.com/EnesSamaa/AegisMCP-Gateway.git
cd AegisMCP-Gateway

# Check everything compiles
cargo check --workspace

# Run the test suite
cargo test --workspace

# Run the gateway binary (stub — Day 1)
cargo run --bin aegis-gateway
```

---

## Development roadmap

| Day | Milestone |
|-----|-----------|
| **1** ✅ | Cargo workspace, CI/CD tooling, foundational crate structure |
| 2 | Hyper v1 reverse-proxy engine, connection pooling |
| 3 | MCP protocol parser, JSON-RPC request routing |
| 4 | Wasmtime engine initialisation, WASI 0.2 sandbox |
| 5 | Guardrail evaluation pipeline, rule hot-reload |
| … | (see `ROADMAP.md`) |

---

## Contributing

Please read `CONTRIBUTING.md` before opening a pull request.
All contributions are dual-licensed under **MIT OR Apache-2.0**.

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
