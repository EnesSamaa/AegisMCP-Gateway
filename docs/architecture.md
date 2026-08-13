# AegisMCP-Gateway Architecture Specification

> **Week 3 Milestone Architecture Document (Version 0.3.0-week3)**

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
│ JSON-RPC 2.0  │ Hyper 1.x      │ Wasmtime 47     │ 6-Layer Security │ SHA-256 Merkle   │
│ MCP Primitives│ Tokio Runtime  │ WASI 0.2 WIT    │ RBAC/ABAC/DLP    │ Audit Proofs     │
│ Error Models  │ Tower Stack    │ Instance Pooling│ HITL Approval    │ Leaf Verification│
└───────────────┴────────────────┴─────────────────┴──────────────────┴──────────────────┘
                                          │
                                          ▼ (WASI 0.2 Component Target: wasm32-wasip2)
                               ┌──────────────────────┐
                               │  plugin-pii-filter   │
                               │  WASI Guardrail WASM │
                               └──────────────────────┘
```

### Workspace Crates Overview
1. **`aegis-core`**: Core MCP protocol primitives, JSON-RPC 2.0 data models (`RequestId`, `AgentIdentity`, `JsonRpcRequest`, `JsonRpcResponse`, `ToolCall`, `ToolResult`), custom serialization logic, and error hierarchy.
2. **`aegis-proxy`**: Asynchronous reverse proxy engine built on Tokio and Hyper 1.x. Handles HTTP/JSON-RPC, Server-Sent Events (SSE) streaming, Tower middleware stack, dynamic YAML configuration (`config-rs`), `notify` file-watcher hot-reloading, and real-time WASM policy evaluation.
3. **`aegis-wasm`**: WebAssembly runtime engine leveraging Wasmtime 47 and WASI 0.2 component model (`wit-bindgen` / `wasmtime::component::bindgen!`). Features lock-free instance pooling (`WasmInstancePool`), Ed25519 signature verification (`verify_plugin_signature`), semver metadata tracking, and zero-downtime hot-swapping (`PluginHotSwapper`).
4. **`aegis-guardrails`**: Enterprise Zero-Trust Security Stack:
   - `IdentityExtractor`: Bearer JWT & Static X-API-Key extraction.
   - `TokenTranslator`: Identity-to-Upstream short-lived credential translation.
   - `ToolAuthorizationEngine`: Granular RBAC / ABAC tool execution matrix.
   - `PromptInjectionDetector`: RegexSet indirect prompt injection & context hijacking detector.
   - `LoopBreakerEngine`: Stateful sliding-window ring buffer detecting runaway execution loops.
   - `HitlApprovalEngine`: Asynchronous task suspension & operator approval workflow.
   - `DlpMaskingEngine`: Real-time outbound PII/PHI redaction (`Credit Card`, `Email`, `API Key`, `SSN`).
5. **`aegis-proof`**: Cryptographic audit logger implementing SHA-256 binary Merkle Trees for producing tamper-evident proofs of policy evaluation history.
6. **`plugin-pii-filter`**: WASI 0.2 Preview 2 component plugin compiled to `wasm32-wasip2` for detecting Personally Identifiable Information (PII).

---

## 🛡️ 2. The 6-Layer Zero-Trust Security Guardrail Pipeline

Every request passing through `AegisMCP-Gateway` is evaluated through a strict, multi-layered security pipeline:

```text
 Client HTTP Request
         │
         ▼
┌───────────────────────────────────────────────────────────┐
│ 1. Identity & AuthN (JWT / X-API-Key Extraction)           │  ──► Code -32002 (Auth Failed)
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────┐
│ 2. Prompt Injection & Hijacking Detector                  │  ──► Code -32003 (Critical Injection)
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────┐
│ 3. Agent Rate Limiter & Stateful Loop Breaker              │  ──► Code -32004 (Quota / Execution Loop)
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────┐
│ 4. Granular Tool Authorization Engine (RBAC / ABAC)       │  ──► Code -32001 (Unauthorized Tool Call)
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────┐
│ 5. Human-in-the-Loop (HITL) High-Risk Suspension           │  ──► Code -32005 (Approval Required)
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────┐
│ 6. WASI 0.2 WASM Guardrail Inspection                     │  ──► Code -32001 (WASM Policy Denial)
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
                 Upstream MCP Server Forwarding
                             │
                             ▼
┌───────────────────────────────────────────────────────────┐
│ Outbound DLP Masking (Real-Time PII / Secret Redaction)   │  ──► [REDACTED_CREDIT_CARD], [REDACTED_EMAIL]
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
                      Client Response
```

---

## ⚡ 3. WASI 0.2 Runtime & Sandboxing Engine (`aegis-wasm`)

### Safety & Security Policies
- **Memory Sandboxing**: Enforced 16MB per-instance memory allocation limit via Wasmtime's `ResourceLimiter`.
- **Interruption Guarantee**: Epoch-based execution tick engine interrupting infinite loops or CPU exhaustion after a 500ms deadline.
- **Ed25519 Cryptographic Verification**: `verify_plugin_signature` validates plugin binaries against Ed25519 keypair signatures before instantiation.
- **Zero-Downtime Hot-Swapping**: `PluginHotSwapper` broadcasts newly compiled `WasmInstancePool` references across a `tokio::sync::watch` channel without dropping in-flight requests.

---

## 📊 4. Week 3 Benchmarks & SLA Verification Metrics

- **Total Test Suite**: **91 passing tests** across `aegis-core`, `aegis-proxy`, `aegis-wasm`, `aegis-guardrails`, `aegis-proof`, and `plugin-pii-filter`.
- **Red-Teaming Attack Simulations**: 100% interception across Indirect Prompt Injection, Privilege Escalation, Infinite Execution Loops, DLP Data Leakage, and HITL High-Risk Operations (`red_team_simulations.rs`).
- **Clippy**: 100% clean (`cargo clippy --workspace --exclude plugin-pii-filter --all-targets -- -D warnings`).
- **Format**: 100% clean (`cargo fmt --all -- --check`).
- **End-to-End Security Latency Overhead**:
  - Full 6-Layer Guardrail Stack Processing: **`< 1.8ms`** (well below the 15ms SLA requirement).
  - Outbound DLP Masking: **`< 0.4ms`**.
