//! Granular Tool-Level Authorization Engine (RBAC / ABAC) for MCP tool calls.

use crate::identity::IdentityContext;
use aegis_core::ToolCall;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Decision returned by the [`ToolAuthorizationEngine`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// Request is fully authorized to proceed.
    Allow,
    /// Request is denied with a human-readable security policy reason.
    Deny(String),
}

/// ABAC parameter inspection policy for specific tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolParamPolicy {
    /// Target tool name (e.g. `db_query`, `shell_execute`).
    pub tool_name: String,
    /// Substring / regex patterns that trigger automatic denial if present in argument payload.
    pub denied_patterns: Vec<String>,
    /// Required patterns that must be present in argument payload (if non-empty).
    pub required_patterns: Vec<String>,
}

/// Granular RBAC/ABAC authorization engine for MCP `tools/call` requests.
#[derive(Clone, Default)]
pub struct ToolAuthorizationEngine {
    /// Role to allowed tool names mapping (RBAC).
    role_policies: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Tool parameter inspection policies (ABAC).
    param_policies: Arc<RwLock<HashMap<String, ToolParamPolicy>>>,
}

impl ToolAuthorizationEngine {
    /// Creates a new `ToolAuthorizationEngine`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            role_policies: Arc::new(RwLock::new(HashMap::new())),
            param_policies: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Configures allowed tool rules for an agent role (RBAC).
    pub async fn add_role_policy(&self, role: impl Into<String>, allowed_tools: Vec<String>) {
        let role_str = role.into();
        info!(role = %role_str, tools = ?allowed_tools, "Configured RBAC Tool Access Policy");
        let mut map = self.role_policies.write().await;
        map.insert(role_str, allowed_tools);
    }

    /// Configures parameter inspection rules for a tool (ABAC).
    pub async fn add_param_policy(&self, policy: ToolParamPolicy) {
        info!(tool = %policy.tool_name, "Configured ABAC Tool Parameter Policy");
        let mut map = self.param_policies.write().await;
        map.insert(policy.tool_name.clone(), policy);
    }

    /// Checks if a tool call matches an allowed pattern string (e.g. `*`, `github.read_*`, `read_file`).
    fn matches_pattern(pattern: &str, tool_name: &str) -> bool {
        if pattern == "*" || pattern == tool_name {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            if tool_name.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    /// Checks RBAC and ABAC authorization policies for an incoming [`ToolCall`].
    pub async fn check_authorization(
        &self,
        ctx: &IdentityContext,
        tool_call: &ToolCall,
    ) -> PolicyDecision {
        let role = ctx.identity.role();
        let tool_name = &tool_call.name;

        // 1. RBAC Check — verify role permits tool execution
        let role_map = self.role_policies.read().await;
        let is_rbac_allowed = role_map.get(role).map_or_else(
            || ctx.has_permission("*") || ctx.has_permission(&format!("tool:{tool_name}")),
            |allowed| allowed.iter().any(|p| Self::matches_pattern(p, tool_name)),
        );
        drop(role_map);

        if !is_rbac_allowed {
            warn!(role = %role, tool = %tool_name, "RBAC Authorization Denied Tool Call");
            return PolicyDecision::Deny(format!(
                "RBAC Policy Denial: Role '{role}' is not permitted to execute tool '{tool_name}'"
            ));
        }

        // 2. ABAC Check — inspect argument parameters if argument policy exists
        let param_map = self.param_policies.read().await;
        if let Some(param_policy) = param_map.get(tool_name) {
            let args_json = tool_call
                .arguments
                .as_ref()
                .map_or_else(String::new, ToString::to_string);

            // Check denied substrings / commands
            for denied in &param_policy.denied_patterns {
                if args_json.contains(denied) {
                    warn!(tool = %tool_name, pattern = %denied, "ABAC Parameter Policy Denied Request");
                    return PolicyDecision::Deny(format!(
                        "ABAC Policy Denial: Tool '{tool_name}' argument contains restricted pattern '{denied}'"
                    ));
                }
            }

            // Check required substrings (if non-empty)
            if !param_policy.required_patterns.is_empty() {
                let has_required = param_policy
                    .required_patterns
                    .iter()
                    .any(|req| args_json.contains(req));
                if !has_required {
                    warn!(tool = %tool_name, "ABAC Parameter Policy Required Pattern Missing");
                    return PolicyDecision::Deny(format!(
                        "ABAC Policy Denial: Tool '{tool_name}' argument missing required pattern"
                    ));
                }
            }
        }
        drop(param_map);

        PolicyDecision::Allow
    }
}
