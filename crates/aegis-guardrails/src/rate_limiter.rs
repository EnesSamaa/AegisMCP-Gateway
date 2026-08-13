//! Adaptive Sliding-Window Rate Limiter Engine for per-agent rate limits.

use aegis_core::AgentIdentity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;

/// Result returned by [`AgentRateLimiter::check_rate_limit`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitResult {
    /// Whether the request is permitted under rate limit quotas.
    pub allowed: bool,
    /// Remaining allowed requests in current sliding window.
    pub remaining_quota: u32,
    /// Seconds until quota window resets.
    pub reset_after_secs: u64,
}

/// Sliding window state entry for an agent.
#[derive(Debug, Clone)]
struct WindowState {
    request_timestamps: Vec<u64>,
}

/// Adaptive sliding-window rate limiter per agent identity.
#[derive(Clone)]
pub struct AgentRateLimiter {
    max_requests_per_window: u32,
    window_duration_secs: u64,
    states: Arc<RwLock<HashMap<String, WindowState>>>,
}

impl AgentRateLimiter {
    /// Creates a new `AgentRateLimiter` with max requests per window duration in seconds.
    #[must_use]
    pub fn new(max_requests_per_window: u32, window_duration_secs: u64) -> Self {
        Self {
            max_requests_per_window,
            window_duration_secs,
            states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Checks and updates the rate limit for a given [`AgentIdentity`].
    pub async fn check_rate_limit(
        &self,
        identity: &AgentIdentity,
        current_time_secs: u64,
    ) -> RateLimitResult {
        let key = identity.agent_id().to_string();
        let cutoff = current_time_secs.saturating_sub(self.window_duration_secs);

        let mut map = self.states.write().await;
        let state = map.entry(key).or_insert_with(|| WindowState {
            request_timestamps: Vec::new(),
        });

        // Evict expired timestamps
        state.request_timestamps.retain(|&ts| ts >= cutoff);

        let current_count = u32::try_from(state.request_timestamps.len()).unwrap_or(u32::MAX);

        if current_count >= self.max_requests_per_window {
            drop(map);
            warn!(agent_id = %identity.agent_id(), "Rate Limit Exceeded for Agent");
            return RateLimitResult {
                allowed: false,
                remaining_quota: 0,
                reset_after_secs: self.window_duration_secs,
            };
        }

        state.request_timestamps.push(current_time_secs);
        let remaining = self.max_requests_per_window - (current_count + 1);
        drop(map);

        RateLimitResult {
            allowed: true,
            remaining_quota: remaining,
            reset_after_secs: self.window_duration_secs,
        }
    }
}
