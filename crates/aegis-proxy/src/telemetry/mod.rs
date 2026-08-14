//! # Telemetry module
//!
//! Provides Prometheus metrics exposition and W3C `TraceContext` propagation
//! for the AegisMCP-Gateway observability stack.

pub mod metrics;
pub mod trace_ctx;

pub use metrics::{
    init_metrics, record_guardrail_latency, record_http_request, record_security_violation,
    render_metrics, set_merkle_leaves, MetricsHandle, METRIC_GUARDRAIL_LATENCY_SECONDS,
    METRIC_HTTP_REQUESTS_TOTAL, METRIC_MERKLE_TREE_LEAVES_TOTAL, METRIC_SECURITY_VIOLATIONS_TOTAL,
    METRIC_WASM_POOL_ACTIVE_INSTANCES,
};
pub use trace_ctx::{extract_trace_context, inject_trace_headers, TraceContext};
