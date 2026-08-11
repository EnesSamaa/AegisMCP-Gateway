//! # aegis-proxy
//!
//! Hyper 1.x + Tokio asynchronous reverse proxy engine for AegisMCP-Gateway.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic, clippy::nursery)]
#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod middleware;
pub mod proxy;
pub mod router;
pub mod sse;

pub use config::{
    AgentRoleMapping, ConfigManager, GatewayConfig, ProxyConfig, RouteConfig, SecuritySettings,
    ServerSettings,
};
pub use error::ProxyError;
pub use middleware::{
    LatencyTrackingLayer, RequestIdLayer, TimeoutLayer, TracingLayer, X_REQUEST_ID,
    X_RESPONSE_TIME_US,
};
pub use proxy::McpProxy;
pub use router::ProxyRouter;
pub use sse::{apply_sse_headers, format_sse_event, is_sse_request};
