//! # aegis-proxy
//!
//! Entry-point for the `aegis-gateway` binary.
//!
//! This file bootstraps the Tokio runtime, initialises structured logging via
//! `tracing-subscriber`, and starts the HTTP reverse-proxy server that sits in
//! front of upstream MCP servers.
//!
//! ## Architecture (stub — Day 1)
//!
//! ```text
//! ┌─────────────┐      HTTP/1.1 + HTTP/2      ┌────────────────────┐
//! │  MCP Client │ ──────────────────────────► │  AegisMCP-Gateway  │
//! └─────────────┘                             │  (aegis-proxy)     │
//!                                             │                    │
//!                     Filtered & proxied      │  aegis-guardrails  │
//!                     ◄────────────────────── │  aegis-wasm        │
//!                                             │  aegis-proof       │
//!                                             └────────────────────┘
//! ```
//!
//! The actual proxy logic will be filled in on Day 2+.

use anyhow::Result;
use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    // -----------------------------------------------------------------------
    // Initialise structured logging
    // Respects the `RUST_LOG` environment variable; defaults to `info`.
    // -----------------------------------------------------------------------
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer().with_target(true).with_thread_ids(false))
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "AegisMCP-Gateway starting up"
    );

    // -----------------------------------------------------------------------
    // Placeholder: bind address and server startup
    // Full implementation in Day 2 (aegis-proxy HTTP layer).
    // -----------------------------------------------------------------------
    let bind_addr = "127.0.0.1:8080";
    info!(address = bind_addr, "Gateway listener will bind here (stub)");

    info!("Day 1 workspace bootstrap complete — no active listener yet");
    Ok(())
}
