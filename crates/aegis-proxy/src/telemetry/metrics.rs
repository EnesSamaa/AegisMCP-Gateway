//! Prometheus metrics exposition engine for AegisMCP-Gateway.
//!
//! Registers and exposes five core metric families:
//! - `aegis_http_requests_total` — gateway throughput counter by method/status/route.
//! - `aegis_guardrail_latency_seconds` — per-layer security processing histogram.
//! - `aegis_security_violations_total` — dropped/sanitized threat counter.
//! - `aegis_wasm_pool_active_instances` — live WASM executor gauge.
//! - `aegis_merkle_tree_leaves_total` — cryptographic audit log ingestion gauge.

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;

/// Opaque handle to the Prometheus recorder — can render metrics on demand.
pub type MetricsHandle = PrometheusHandle;

// ---------------------------------------------------------------------------
// Global recorder handle (initialised once at startup)
// ---------------------------------------------------------------------------

static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Metric name: HTTP request throughput counter.
pub const METRIC_HTTP_REQUESTS_TOTAL: &str = "aegis_http_requests_total";

/// Metric name: per-guardrail-layer processing latency histogram.
pub const METRIC_GUARDRAIL_LATENCY_SECONDS: &str = "aegis_guardrail_latency_seconds";

/// Metric name: security violation/denial event counter.
pub const METRIC_SECURITY_VIOLATIONS_TOTAL: &str = "aegis_security_violations_total";

/// Metric name: live WASM plugin instance pool gauge.
pub const METRIC_WASM_POOL_ACTIVE_INSTANCES: &str = "aegis_wasm_pool_active_instances";

/// Metric name: total Merkle tree leaf count gauge.
pub const METRIC_MERKLE_TREE_LEAVES_TOTAL: &str = "aegis_merkle_tree_leaves_total";

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

/// Installs the global Prometheus metrics recorder and returns its handle.
///
/// Calling this more than once is a no-op — the first call wins.
///
/// # Panics
///
/// Panics if the Prometheus recorder cannot be installed (e.g., another recorder
/// was already registered with the `metrics` global).
pub fn init_metrics() -> &'static PrometheusHandle {
    PROMETHEUS_HANDLE.get_or_init(|| {
        PrometheusBuilder::new()
            .install_recorder()
            .expect("Failed to install Prometheus metrics recorder")
    })
}

// ---------------------------------------------------------------------------
// Renderer
// ---------------------------------------------------------------------------

/// Renders all currently registered metrics in Prometheus text exposition format.
///
/// Returns a fallback comment string if the recorder has not been initialised.
#[must_use]
pub fn render_metrics() -> String {
    PROMETHEUS_HANDLE.get().map_or_else(
        || "# metrics recorder not initialised\n".to_string(),
        PrometheusHandle::render,
    )
}

// ---------------------------------------------------------------------------
// Recording helpers
// ---------------------------------------------------------------------------

/// Increments the `aegis_http_requests_total` counter.
pub fn record_http_request(method: &str, status: u16, route: &str) {
    metrics::counter!(
        METRIC_HTTP_REQUESTS_TOTAL,
        "method" => method.to_string(),
        "status" => status.to_string(),
        "route"  => route.to_string(),
    )
    .increment(1);
}

/// Records a latency sample for a named guardrail layer.
pub fn record_guardrail_latency(layer: &str, duration_secs: f64) {
    metrics::histogram!(
        METRIC_GUARDRAIL_LATENCY_SECONDS,
        "layer" => layer.to_string(),
    )
    .record(duration_secs);
}

/// Increments the security violation counter for a given violation type.
pub fn record_security_violation(violation_type: &str) {
    metrics::counter!(
        METRIC_SECURITY_VIOLATIONS_TOTAL,
        "violation_type" => violation_type.to_string(),
    )
    .increment(1);
}

/// Sets the live WASM pool instance gauge for a plugin.
pub fn set_wasm_pool_active(plugin_id: &str, count: f64) {
    metrics::gauge!(
        METRIC_WASM_POOL_ACTIVE_INSTANCES,
        "plugin_id" => plugin_id.to_string(),
    )
    .set(count);
}

/// Sets the total Merkle audit tree leaf count gauge.
pub fn set_merkle_leaves(count: f64) {
    metrics::gauge!(METRIC_MERKLE_TREE_LEAVES_TOTAL).set(count);
}
