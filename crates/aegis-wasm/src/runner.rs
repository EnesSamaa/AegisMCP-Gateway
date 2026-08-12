//! High-performance concurrent plugin execution pipeline.

use crate::bindings::aegis::guardrail::types as wit_types;
use crate::error::WasmError;
use crate::mapping::{parse_guardrail_result, HostPolicySummary};
use crate::pool::WasmInstancePool;
use std::time::Duration;

/// Concurrent runner for WASI 0.2 guardrail plugins.
#[derive(Clone)]
pub struct PluginRunner {
    pool: WasmInstancePool,
}

impl PluginRunner {
    /// Creates a new `PluginRunner` wrapping a [`WasmInstancePool`].
    #[must_use]
    pub const fn new(pool: WasmInstancePool) -> Self {
        Self { pool }
    }

    /// Evaluates an inspection context concurrently using a pooled instance.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] if checkout, execution, or WASM trap occurs.
    pub async fn evaluate_concurrently(
        &self,
        ctx: &wit_types::InspectionContext,
        _timeout: Duration,
    ) -> Result<HostPolicySummary, WasmError> {
        let mut guard = self.pool.checkout().await?;
        let pooled = guard.instance_mut();

        // Configure epoch deadline for interruption safety
        pooled.store.set_epoch_deadline(1);

        let inspector = pooled.policy.aegis_guardrail_inspector();
        let result = inspector
            .call_inspect(&mut pooled.store, ctx)
            .map_err(|e| WasmError::Trap(format!("WASM evaluation trap: {e}")))?;

        Ok(parse_guardrail_result(&result))
    }
}
