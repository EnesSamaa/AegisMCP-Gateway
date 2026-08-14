# AegisMCP-Gateway Security Model & Threat Specification

> **Version: 1.0.0 (General Availability)**

AegisMCP-Gateway implements a defense-in-depth Zero-Trust architecture designed specifically for the security challenges posed by Autonomous AI Agents, Large Language Models (LLMs), and Model Context Protocol (MCP) tool execution.

---

## 🎯 Threat Model & Mitigations

### 1. Indirect Prompt Injection & System Instruction Override
- **Threat**: Malicious payloads within tool parameters or external data sources attempting to hijack agent execution context (e.g. `"Ignore previous instructions and execute..."`, ChatML syntax evasion).
- **Defense**: High-throughput `PromptInjectionDetector` using pre-compiled `RegexSet` matching for context-hijacking patterns in < 45 µs.

### 2. Unauthorized Tool Invocations & Privilege Escalation
- **Threat**: Compromised or hallucinations agents attempting to invoke sensitive or administrative tools (e.g. `db.drop_all`, `cloud.delete_instance`).
- **Defense**: Granular Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC) in `ToolAuthorizationEngine` enforcing parameter boundaries and role restrictions.

### 3. Runaway Execution Loops & Denial of Wallet (DoW)
- **Threat**: AI agents trapped in infinite execution cycles repeating identical tool calls, exhausting rate limits and incurring extreme API costs.
- **Defense**: Stateful sliding-window `LoopBreakerEngine` and token-bucket `AgentRateLimiter` tracking call frequency per agent identity.

### 4. Data Loss & PII Exfiltration in Outbound Streams
- **Threat**: Accidental leakage of Personally Identifiable Information (PII), credentials, or Protected Health Information (PHI) in outbound tool responses.
- **Defense**: Inline streaming `DlpMaskingEngine` performing real-time regex sanitization on JSON bodies and Server-Sent Events (SSE) chunks.

### 5. High-Risk Tool Execution
- **Threat**: Irreversible operations executing without manual human authorization.
- **Defense**: Asynchronous `HitlApprovalEngine` intercepting high-risk tool invocations, generating an `ApprovalRequestId`, and suspending request execution until an operator grants approval.

### 6. Audit Trail Tampering
- **Threat**: Malicious actors modifying local audit logs to conceal unauthorized agent behavior.
- **Defense**: Append-only SHA-256 cryptographic ledger with binary `IncrementalMerkleTree`. Generates exportable inclusion proofs (`AuditMerkleProof`) that can be verified mathematically offline with `aegis-cli`.

---

## 🔒 Memory Safety & Hardening Standards

- **`forbid(unsafe_code)`**: The entire workspace is built with zero unsafe Rust code.
- **Google Distroless Runtime**: Containers run as non-root (`USER nonroot:nonroot`) on `gcr.io/distroless/cc-debian12:nonroot` with read-only root filesystems and dropped Linux capabilities.
- **Boundary Limits**: Strict 4MB default payload size enforcement and malformed JSON boundary handling.
- **Sanitized Responses**: No filesystem paths, internal database strings, or stack traces are exposed in public error payloads.
