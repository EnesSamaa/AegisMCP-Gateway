//! Shared primitive type aliases, newtypes, and session/identity structures.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// A unique identifier for an inbound request as it flows through the gateway.
///
/// Wraps a [`Uuid`] to provide type safety and avoid confusion with session
/// or protocol-level request IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(Uuid);

impl RequestId {
    /// Generates a new random (v4) `RequestId`.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Returns the inner [`Uuid`].
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "req:{}", self.0)
    }
}

/// A unique identifier for a client session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(Uuid);

impl SessionId {
    /// Generates a new random (v4) `SessionId`.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Returns the inner [`Uuid`].
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Agent Identity & Session Context
// ---------------------------------------------------------------------------

/// Identity attributes of an agent or client connected to the gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Client application or user identifier.
    pub client_id: String,

    /// Human-readable name of the agent.
    pub agent_name: String,

    /// Role associated with the agent (e.g., `"admin"`, `"analyst"`, `"executor"`).
    pub role: String,

    /// Optional tenant identifier for multi-tenant isolation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Granted permissions/scopes for this agent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
}

impl AgentIdentity {
    /// Creates a new `AgentIdentity` with default empty permissions and no tenant ID.
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        agent_name: impl Into<String>,
        role: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            agent_name: agent_name.into(),
            role: role.into(),
            tenant_id: None,
            permissions: Vec::new(),
        }
    }

    /// Sets the tenant ID for this identity.
    #[must_use]
    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Adds a permission scope to this identity.
    #[must_use]
    pub fn with_permission(mut self, permission: impl Into<String>) -> Self {
        self.permissions.push(permission.into());
        self
    }

    /// Checks if this identity has a specific permission scope.
    #[must_use]
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }
}

/// Context for an active MCP session managed by the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpSessionContext {
    /// Unique session identifier.
    pub session_id: SessionId,

    /// Agent identity attached to this session.
    pub identity: AgentIdentity,

    /// Creation timestamp of the session (Unix milliseconds).
    pub created_at_unix_ms: u64,

    /// Additional session metadata (e.g. key-value tags).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

impl McpSessionContext {
    /// Creates a new `McpSessionContext`.
    #[must_use]
    pub fn new(session_id: SessionId, identity: AgentIdentity, created_at_unix_ms: u64) -> Self {
        Self {
            session_id,
            identity,
            created_at_unix_ms,
            metadata: HashMap::new(),
        }
    }

    /// Inserts a metadata entry into the session context.
    pub fn insert_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_and_session_id_formatting() {
        let req_id = RequestId::new();
        assert!(req_id.to_string().starts_with("req:"));

        let session_id = SessionId::new();
        assert!(session_id.to_string().starts_with("session:"));
    }

    #[test]
    fn test_agent_identity_permissions() {
        let identity = AgentIdentity::new("id-1", "AgentX", "admin")
            .with_permission("mcp:read")
            .with_permission("mcp:write");

        assert!(identity.has_permission("mcp:read"));
        assert!(identity.has_permission("mcp:write"));
        assert!(!identity.has_permission("mcp:execute"));
    }
}
