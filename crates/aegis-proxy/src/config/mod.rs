//! AegisMCP-Gateway dynamic YAML configuration module.

pub mod manager;
pub mod schema;

pub use manager::ConfigManager;
pub use schema::{
    AgentRoleMapping, GatewayConfig, ProxyConfig, RouteConfig, SecuritySettings, ServerSettings,
};
