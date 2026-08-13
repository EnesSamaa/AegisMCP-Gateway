//! Stateful Loop Breaker Engine for detecting agent execution loops.

use aegis_core::ToolCall;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;

/// Configuration options for [`LoopBreakerEngine`].
#[derive(Debug, Clone)]
pub struct LoopBreakerConfig {
    /// Maximum allowed identical calls within the sliding window.
    pub max_identical_calls: usize,
    /// Sliding window duration in seconds.
    pub window_duration_secs: u64,
}

impl Default for LoopBreakerConfig {
    fn default() -> Self {
        Self {
            max_identical_calls: 5,
            window_duration_secs: 10,
        }
    }
}

/// Single recorded tool call entry in history.
#[derive(Debug, Clone)]
struct CallEntry {
    param_hash: u64,
    timestamp_secs: u64,
}

/// Stateful loop detection engine tracking repeated identical tool calls.
#[derive(Clone)]
pub struct LoopBreakerEngine {
    config: LoopBreakerConfig,
    history: Arc<RwLock<HashMap<String, Vec<CallEntry>>>>,
}

impl LoopBreakerEngine {
    /// Creates a new `LoopBreakerEngine` with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(LoopBreakerConfig::default())
    }

    /// Creates a `LoopBreakerEngine` with custom [`LoopBreakerConfig`].
    #[must_use]
    pub fn with_config(config: LoopBreakerConfig) -> Self {
        Self {
            config,
            history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Computes a deterministic 64-bit hash for a [`ToolCall`].
    fn compute_hash(tool_call: &ToolCall) -> u64 {
        let mut hasher = DefaultHasher::new();
        tool_call.name.hash(&mut hasher);
        if let Some(args) = &tool_call.arguments {
            args.to_string().hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Checks if a tool call triggers a loop detection error and records it in history.
    ///
    /// # Errors
    ///
    /// Returns an error message if repeated identical calls exceed `max_identical_calls`.
    pub async fn check_and_record(
        &self,
        session_id: &str,
        tool_call: &ToolCall,
        current_time_secs: u64,
    ) -> Result<(), String> {
        let hash = Self::compute_hash(tool_call);
        let cutoff = current_time_secs.saturating_sub(self.config.window_duration_secs);

        let mut history_map = self.history.write().await;
        let entries = history_map.entry(session_id.to_string()).or_default();

        // Evict expired entries
        entries.retain(|e| e.timestamp_secs >= cutoff);

        // Count identical parameter calls within sliding window
        let identical_count = entries.iter().filter(|e| e.param_hash == hash).count();

        if identical_count >= self.config.max_identical_calls {
            drop(history_map);
            warn!(
                session_id = %session_id,
                tool = %tool_call.name,
                count = identical_count + 1,
                "Stateful Loop Breaker Tripped"
            );
            return Err(format!(
                "Agent execution loop detected: tool '{}' called repeatedly with identical parameters",
                tool_call.name
            ));
        }

        entries.push(CallEntry {
            param_hash: hash,
            timestamp_secs: current_time_secs,
        });
        drop(history_map);

        Ok(())
    }
}

impl Default for LoopBreakerEngine {
    fn default() -> Self {
        Self::new()
    }
}
