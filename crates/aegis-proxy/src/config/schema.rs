//! Dynamic YAML configuration schemas for AegisMCP-Gateway.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Runtime configuration options for `aegis-proxy`.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address to bind local HTTP proxy listener.
    pub listen_addr: SocketAddr,

    /// Upstream MCP server URL (e.g. `"http://127.0.0.1:9090"`).
    pub upstream_url: String,
}

impl ProxyConfig {
    /// Constructs `ProxyConfig` reading environment variables `LISTEN_ADDR` and `UPSTREAM_URL`.
    ///
    /// Fallbacks: `127.0.0.1:8080` for `listen_addr`, `http://127.0.0.1:9090` for `upstream_url`.
    #[must_use]
    pub fn from_env() -> Self {
        let fallback_addr = SocketAddr::from(([127, 0, 0, 1], 8080));
        let listen_addr: SocketAddr = std::env::var("LISTEN_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(fallback_addr);

        let upstream_url =
            std::env::var("UPSTREAM_URL").unwrap_or_else(|_| "http://127.0.0.1:9090".to_string());

        Self {
            listen_addr,
            upstream_url,
        }
    }

    /// Creates a new `ProxyConfig` with custom listen address and upstream URL.
    #[must_use]
    pub fn new(listen_addr: SocketAddr, upstream_url: impl Into<String>) -> Self {
        Self {
            listen_addr,
            upstream_url: upstream_url.into(),
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

/// Root gateway configuration schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayConfig {
    /// Server listener and timeout settings.
    pub server: ServerSettings,

    /// List of dynamic proxy routes.
    pub routes: Vec<RouteConfig>,

    /// Agent role definitions and tool permissions.
    pub roles: Vec<AgentRoleMapping>,

    /// Security & engine flags.
    pub security: SecuritySettings,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            server: ServerSettings::default(),
            routes: vec![RouteConfig::default()],
            roles: vec![AgentRoleMapping::default()],
            security: SecuritySettings::default(),
        }
    }
}

/// Server network and timeout configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerSettings {
    /// Address to bind proxy server (e.g., `127.0.0.1:8080`).
    pub listen_addr: SocketAddr,

    /// Default request timeout in milliseconds.
    pub default_timeout_ms: u64,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            default_timeout_ms: 30000,
        }
    }
}

/// Upstream proxy route rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteConfig {
    /// URI path matching prefix (e.g. `/mcp`, `/sse`).
    pub path: String,

    /// Target upstream MCP server URL (e.g. `http://127.0.0.1:9090`).
    pub upstream_url: String,

    /// Optional required agent role for authorization.
    pub required_role: Option<String>,

    /// Whether this route is currently active.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

const fn default_true() -> bool {
    true
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            path: "/mcp".to_string(),
            upstream_url: "http://127.0.0.1:9090".to_string(),
            required_role: None,
            enabled: true,
        }
    }
}

/// Agent identity role mapping and tool permissions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRoleMapping {
    /// Name of the role (e.g. `admin`, `analyst`).
    pub role: String,

    /// List of allowed tool names or wildcards (e.g. `["*"]` or `["sql_query"]`).
    pub allowed_tools: Vec<String>,

    /// Optional rate limit (requests per minute).
    pub max_rate_limit: Option<u32>,
}

impl Default for AgentRoleMapping {
    fn default() -> Self {
        Self {
            role: "default".to_string(),
            allowed_tools: vec!["*".to_string()],
            max_rate_limit: Some(1000),
        }
    }
}

/// Security flags and engine toggles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecuritySettings {
    /// Enable WASI 0.2 plugin guardrail inspection.
    pub enable_wasm_guardrails: bool,

    /// Enable Merkle proof cryptographic audit logging.
    pub enable_proof_logging: bool,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            enable_wasm_guardrails: true,
            enable_proof_logging: true,
        }
    }
}
