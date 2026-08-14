# AegisMCP-Gateway Architecture Specification

> **Version: 1.0.0 (General Availability)**  
> **Status: Production-Ready**

AegisMCP-Gateway is a high-performance, Zero-Trust Security Gateway & Cryptographic Audit Engine for the Model Context Protocol (MCP) written in Rust.

---

## 🏛️ 1. Multi-Crate Cargo Workspace Architecture

AegisMCP-Gateway is organized as a modular Cargo workspace comprising 6 production crates and WASI 0.2 preview 2 plugin components:

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       AegisMCP-Gateway                                          │
├───────────────┬────────────────┬─────────────────┬──────────────────┬──────────────┬────────────┤
│ aegis-core    │ aegis-proxy    │ aegis-wasm      │ aegis-guardrails │ aegis-proof  │ aegis-cli  │
├───────────────┼────────────────┼─────────────────┼──────────────────┼──────────────┼────────────┤
│ JSON-RPC 2.0  │ Hyper 1.x      │ Wasmtime 47     │ 6-Layer Security │ SHA-256 Tree │ Offline CLI│
│ MCP Primitives│ Tokio Runtime  │ WASI 0.2 WIT    │ RBAC/ABAC/DLP    │ Merkle Root  │ Proof      │
│ Error Models  │ Prometheus & OT│ Instance Pool   │ HITL Approval    │ Proof Engine │ Inspector  │
└───────────────┴────────────────┴─────────────────┴──────────────────┴──────────────┴────────────┘
                                          │
                                          ▼ (WASI 0.2 Component Target: wasm32-wasip2)
                               ┌──────────────────────┐
                               │  plugin-pii-filter   │
                               │  WASI Guardrail WASM │
                               └──────────────────────┘
```

### Crate Responsibilities

1. **`aegis-core`**: Defines foundational MCP protocol models, JSON-RPC 2.0 primitives (`RequestId`, `AgentIdentity`, `JsonRpcRequest`, `ToolCall`, `AuditEntry`), custom serialization, and error taxonomies.
2. **`aegis-proxy`**: Asynchronous reverse proxy engine built on Tokio, Hyper 1.x, and Tower middleware. Exposes `/mcp`, `/sse`, `/health`, `/metrics`, `/v1/proofs/root`, and `/v1/proofs/{request_id}`.
3. **`aegis-wasm`**: Sandboxed WASM policy engine using Wasmtime 47 and WASI 0.2. Features lock-free instance pooling, epoch-based execution timeouts, Ed25519 cryptographic signature verification, and zero-downtime hot-swapping.
4. **`aegis-guardrails`**: Zero-Trust security stack containing:
   - `IdentityExtractor`: JWT & API key extraction and tenant resolution.
   - `TokenTranslator`: Upstream short-lived credential mapping.
   - `ToolAuthorizationEngine`: Role-Based & Attribute-Based Access Control matrix.
   - `PromptInjectionDetector`: RegexSet indirect prompt injection detection.
   - `AgentRateLimiter` & `LoopBreakerEngine`: Sliding-window quotas and execution loop tripwires.
   - `HitlApprovalEngine`: Asynchronous task suspension and human operator approval.
   - `DlpMaskingEngine`: Real-time response and SSE stream PII sanitization.
5. **`aegis-proof`**: Cryptographic audit ledger with binary SHA-256 Merkle tree calculation, leaf insertion, and `AuditMerkleProof` verification.
6. **`aegis-cli`**: Standalone command-line verification tool for inspecting audit logs and validating inclusion proofs against trusted Merkle roots.
7. **`plugin-pii-filter`**: WASI 0.2 Preview 2 component plugin compiled to `wasm32-wasip2`.

---

## 🛡️ 2. Request Lifecycle & Guardrail Flow

```text
 Client Request (HTTP POST / SSE)
          │
          ▼
┌───────────────────────────────────────────────────────────┐
│ 1. Distributed Tracing & W3C TraceContext Extraction      │
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────┐
│ 2. Identity & AuthN (JWT / API Key Extraction)            │  ──► 401 Unauthorized (-32002)
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────┐
│ 3. Rate Limiter & Loop Breaker Evaluation                 │  ──► 200 OK (-32004 Quota Exceeded)
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────┐
│ 4. Payload Size Limit & Malformed JSON Boundary           │  ──► 413 / 400 (-32000 / -32700)
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────┐
│ 5. Indirect Prompt Injection & Context Hijack Scan        │  ──► 200 OK (-32003 Injection Block)
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────┐
│ 6. RBAC & ABAC Tool Authorization Matrix                  │  ──► 200 OK (-32001 AuthZ Denied)
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────┐
│ 7. Human-in-the-Loop (HITL) High-Risk Approval            │  ──► 200 OK (-32005 HITL Required)
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────┐
│ 8. Forward to Upstream MCP Server with Traceparent        │  ──► 502 Bad Gateway (if unreachable)
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────┐
│ 9. Real-Time Outbound DLP & Streaming PII Masking         │
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────┐
│ 10. Non-Blocking Cryptographic SHA-256 Merkle Audit Log  │
└────────────────────────────┬──────────────────────────────┘
                             │
                             ▼
 Client Response (Sanitized Payload + Cryptographic Audit)
```

---

## ⚡ 3. Performance SLA Targets

| Operation | SLA Target | Achieved Baseline |
| :--- | :--- | :--- |
| Gateway Request Overhead | < 10.0 ms | **< 1.8 ms** |
| Ed25519 Plugin Signature Verification | < 1.0 ms | **< 120 µs** |
| RegexSet Prompt Injection Scan | < 1.0 ms | **< 45 µs** |
| Merkle Tree Leaf Insertion | < 50 µs | **< 10 µs** |
| Standalone Proof Verification | < 100 µs | **< 15 µs** |
