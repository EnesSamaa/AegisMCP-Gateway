//! Human-in-the-Loop (HITL) Approval Engine for high-risk tool call suspension.

use crate::error::GuardrailError;
use aegis_core::ToolCall;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

/// Unique identifier for a pending HITL approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApprovalRequestId(Uuid);

impl ApprovalRequestId {
    /// Generates a new random `ApprovalRequestId`.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Returns the inner [`Uuid`].
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for ApprovalRequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ApprovalRequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "approval:{}", self.0)
    }
}

/// Human operator decision for a pending tool execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    /// Tool call is approved to proceed.
    Approved,
    /// Tool call is rejected with a reason.
    Rejected(String),
}

/// Human-in-the-Loop (HITL) Approval Engine managing suspended tool calls.
#[derive(Clone)]
pub struct HitlApprovalEngine {
    high_risk_patterns: Arc<RwLock<Vec<String>>>,
    pending_approvals: Arc<RwLock<HashMap<ApprovalRequestId, oneshot::Sender<ApprovalDecision>>>>,
    default_timeout: Duration,
}

impl HitlApprovalEngine {
    /// Creates a new `HitlApprovalEngine` with default 60s timeout.
    #[must_use]
    #[allow(clippy::duration_suboptimal_units)]
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(60))
    }

    /// Creates a `HitlApprovalEngine` with custom timeout duration.
    #[must_use]
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            high_risk_patterns: Arc::new(RwLock::new(Vec::new())),
            pending_approvals: Arc::new(RwLock::new(HashMap::new())),
            default_timeout: timeout,
        }
    }

    /// Registers a high-risk tool pattern (e.g. `db.drop_*`, `cloud.delete_instance`).
    pub async fn register_high_risk_pattern(&self, pattern: impl Into<String>) {
        let p = pattern.into();
        info!(pattern = %p, "Registered High-Risk Tool HITL Approval Pattern");
        let mut patterns = self.high_risk_patterns.write().await;
        patterns.push(p);
    }

    /// Checks if a tool call matches any registered high-risk patterns.
    pub async fn is_high_risk(&self, tool_name: &str) -> bool {
        let patterns = self.high_risk_patterns.read().await;
        patterns.iter().any(|p| {
            if p == "*" || p == tool_name {
                return true;
            }
            if let Some(prefix) = p.strip_suffix('*') {
                if tool_name.starts_with(prefix) {
                    return true;
                }
            }
            false
        })
    }

    /// Submits a tool call for approval and returns the assigned request ID and receiver channel.
    pub async fn submit_for_approval(
        &self,
        tool_call: &ToolCall,
    ) -> (ApprovalRequestId, oneshot::Receiver<ApprovalDecision>) {
        let req_id = ApprovalRequestId::new();
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_approvals.write().await;
            pending.insert(req_id, tx);
        }
        warn!(
            request_id = %req_id,
            tool = %tool_call.name,
            "Tool Execution Suspended Awaiting Human Approval"
        );
        (req_id, rx)
    }

    /// Suspends request execution and awaits human operator approval or timeout.
    ///
    /// # Errors
    ///
    /// Returns [`GuardrailError`] if channel operations fail.
    pub async fn request_approval(
        &self,
        tool_call: &ToolCall,
        timeout_override: Option<Duration>,
    ) -> Result<(ApprovalRequestId, ApprovalDecision), GuardrailError> {
        let (req_id, rx) = self.submit_for_approval(tool_call).await;
        let timeout_dur = timeout_override.unwrap_or(self.default_timeout);

        match tokio::time::timeout(timeout_dur, rx).await {
            Ok(Ok(decision)) => Ok((req_id, decision)),
            Ok(Err(_)) => {
                self.pending_approvals.write().await.remove(&req_id);
                Ok((
                    req_id,
                    ApprovalDecision::Rejected("HITL Channel closed".to_string()),
                ))
            }
            Err(_) => {
                self.pending_approvals.write().await.remove(&req_id);
                warn!(request_id = %req_id, "HITL Approval Timed Out");
                Ok((
                    req_id,
                    ApprovalDecision::Rejected("HITL Approval Timed Out".to_string()),
                ))
            }
        }
    }

    /// Resolves a suspended HITL approval request with an operator decision.
    ///
    /// # Errors
    ///
    /// Returns [`GuardrailError::AuthenticationFailed`] if `request_id` is invalid or expired.
    #[allow(clippy::option_if_let_else)]
    pub async fn resolve_approval(
        &self,
        request_id: ApprovalRequestId,
        decision: ApprovalDecision,
    ) -> Result<(), GuardrailError> {
        let mut pending = self.pending_approvals.write().await;
        if let Some(tx) = pending.remove(&request_id) {
            let _ = tx.send(decision);
            info!(request_id = %request_id, "HITL Approval Resolved Successfully");
            Ok(())
        } else {
            Err(GuardrailError::AuthenticationFailed(format!(
                "No pending HITL request found for ID '{request_id}'"
            )))
        }
    }
}

impl Default for HitlApprovalEngine {
    fn default() -> Self {
        Self::new()
    }
}
