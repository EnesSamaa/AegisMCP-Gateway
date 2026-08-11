//! Configuration settings for `aegis-proxy`.

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
