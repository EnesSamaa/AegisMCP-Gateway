//! Audit entry data models and deterministic SHA-256 hash calculation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Single cryptographic audit entry capturing an intercepted request and policy decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Sequential monotonic ID within the ledger.
    pub seq_id: u64,
    /// Unique request identifier.
    pub request_id: String,
    /// Epoch timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Calling agent identity.
    pub agent_id: String,
    /// Target MCP tool name or method.
    pub tool_name: String,
    /// Resulting policy decision summary (e.g. "ALLOW", "DENY", "`HITL_APPROVED`").
    pub policy_decision: String,
    /// Total processing overhead in microseconds.
    pub execution_time_us: u64,
    /// Deterministic SHA-256 leaf digest (hex string).
    pub payload_hash: String,
}

impl AuditEntry {
    /// Creates a new `AuditEntry` and computes its deterministic SHA-256 payload hash.
    #[must_use]
    pub fn new(
        seq_id: u64,
        request_id: impl Into<String>,
        timestamp_ns: u64,
        agent_id: impl Into<String>,
        tool_name: impl Into<String>,
        policy_decision: impl Into<String>,
        execution_time_us: u64,
    ) -> Self {
        let req_id = request_id.into();
        let ag_id = agent_id.into();
        let tool = tool_name.into();
        let decision = policy_decision.into();

        let payload_hash = Self::compute_hash(&req_id, timestamp_ns, &ag_id, &tool, &decision);

        Self {
            seq_id,
            request_id: req_id,
            timestamp_ns,
            agent_id: ag_id,
            tool_name: tool,
            policy_decision: decision,
            execution_time_us,
            payload_hash,
        }
    }

    /// Calculates deterministic SHA-256 hash across audit attributes.
    #[must_use]
    pub fn compute_hash(
        request_id: &str,
        timestamp_ns: u64,
        agent_id: &str,
        tool_name: &str,
        policy_decision: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(request_id.as_bytes());
        hasher.update(timestamp_ns.to_le_bytes());
        hasher.update(agent_id.as_bytes());
        hasher.update(tool_name.as_bytes());
        hasher.update(policy_decision.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}
