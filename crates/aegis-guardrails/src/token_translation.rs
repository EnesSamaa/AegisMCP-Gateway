//! Enterprise Token Translation Engine for Upstream Credential Mapping.

use crate::error::GuardrailError;
use crate::identity::IdentityContext;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Scoped short-lived credential for forwarding to an upstream MCP server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpstreamCredential {
    /// Token string (e.g. `mcp_upstream_token_abc123`).
    pub token: String,
    /// Target upstream URL matching rule.
    pub target_upstream: String,
    /// Restricted allowed scopes list.
    pub allowed_scopes: Vec<String>,
    /// Token expiration timestamp in seconds since epoch.
    pub expires_at: u64,
}

impl UpstreamCredential {
    /// Checks if the credential has expired relative to current epoch seconds.
    #[must_use]
    pub const fn is_expired(&self, current_epoch_secs: u64) -> bool {
        self.expires_at <= current_epoch_secs
    }
}

/// Key used to look up translation mappings: `(tenant_id, role, target_upstream)`.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct TranslationKey {
    tenant_id: String,
    role: String,
    target_upstream: String,
}

/// Enterprise Token Translation Engine mapping gateway identity to upstream tokens.
#[derive(Clone, Default)]
pub struct TokenTranslator {
    mappings: Arc<RwLock<HashMap<TranslationKey, UpstreamCredential>>>,
}

impl TokenTranslator {
    /// Creates a new `TokenTranslator` instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            mappings: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers a translation mapping rule for a specific tenant, role, and upstream.
    pub async fn register_rule(
        &self,
        tenant_id: impl Into<String>,
        role: impl Into<String>,
        target_upstream: impl Into<String>,
        credential: UpstreamCredential,
    ) {
        let key = TranslationKey {
            tenant_id: tenant_id.into(),
            role: role.into(),
            target_upstream: target_upstream.into(),
        };

        info!(
            tenant_id = %key.tenant_id,
            role = %key.role,
            upstream = %key.target_upstream,
            "Registered Enterprise Token Translation Mapping Rule"
        );

        let mut map = self.mappings.write().await;
        map.insert(key, credential);
    }

    /// Translates an [`IdentityContext`] into a restricted upstream access token.
    ///
    /// # Errors
    ///
    /// Returns [`GuardrailError::TokenTranslationFailed`] if no rule exists or token is expired.
    pub async fn translate(
        &self,
        ctx: &IdentityContext,
        target_upstream: &str,
        current_epoch_secs: u64,
    ) -> Result<UpstreamCredential, GuardrailError> {
        let key = TranslationKey {
            tenant_id: ctx.tenant_id.clone(),
            role: ctx.identity.role().to_string(),
            target_upstream: target_upstream.to_string(),
        };

        let map = self.mappings.read().await;
        let found_cred = map.get(&key).cloned();
        drop(map);

        if let Some(cred) = found_cred {
            if cred.is_expired(current_epoch_secs) {
                return Err(GuardrailError::TokenTranslationFailed(
                    "Translated upstream token has expired".to_string(),
                ));
            }
            return Ok(cred);
        }

        Err(GuardrailError::TokenTranslationFailed(format!(
            "No token translation rule found for tenant '{}', role '{}', upstream '{}'",
            ctx.tenant_id,
            ctx.identity.role(),
            target_upstream
        )))
    }
}
