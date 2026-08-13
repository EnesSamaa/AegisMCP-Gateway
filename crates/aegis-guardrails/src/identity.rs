//! Agent Identity Extractor and `IdentityContext` definition.

use crate::error::GuardrailError;
use aegis_core::AgentIdentity;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// JWT Claims representation for Agent authentication tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentJwtClaims {
    /// Agent / User Subject ID (e.g. `agent-123`).
    pub sub: String,
    /// Agent Role (e.g. `analyst`, `admin`, `devops`).
    pub role: String,
    /// Tenant / Organization ID (e.g. `tenant-corp-a`).
    pub tenant: String,
    /// Granted permissions list (e.g. `tools:read`, `tools:call`).
    #[serde(default)]
    pub perms: Vec<String>,
    /// Expiration timestamp in seconds since UNIX epoch.
    pub exp: u64,
}

/// Extracted context containing full identity and security permissions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityContext {
    /// Inner [`AgentIdentity`] protocol structure.
    pub identity: AgentIdentity,
    /// Tenant / Organization identifier.
    pub tenant_id: String,
    /// Granted permission scopes.
    pub permissions: Vec<String>,
    /// Session scope (e.g. `session-scoped`).
    pub session_scope: String,
    /// Token expiration timestamp in seconds.
    pub expires_at: u64,
}

impl IdentityContext {
    /// Checks if the identity context contains a specific permission.
    #[must_use]
    pub fn has_permission(&self, perm: &str) -> bool {
        self.permissions.iter().any(|p| p == perm || p == "*")
    }

    /// Checks if the token has expired relative to current epoch seconds.
    #[must_use]
    pub const fn is_expired(&self, current_epoch_secs: u64) -> bool {
        self.expires_at <= current_epoch_secs
    }
}

/// Extractor for Agent identity credentials from JWTs or API Keys.
#[derive(Clone)]
pub struct IdentityExtractor {
    jwt_decoding_key: DecodingKey,
    api_key_registry: Arc<RwLock<HashMap<String, IdentityContext>>>,
}

impl IdentityExtractor {
    /// Creates a new `IdentityExtractor` with a shared JWT secret.
    #[must_use]
    pub fn new(jwt_secret: &[u8]) -> Self {
        Self {
            jwt_decoding_key: DecodingKey::from_secret(jwt_secret),
            api_key_registry: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers a static API Key to `IdentityContext` mapping.
    pub async fn register_api_key(&self, api_key: impl Into<String>, ctx: IdentityContext) {
        let mut registry = self.api_key_registry.write().await;
        registry.insert(api_key.into(), ctx);
    }

    /// Extracts [`IdentityContext`] from HTTP headers (`Authorization` or `X-API-Key`).
    ///
    /// # Errors
    ///
    /// Returns [`GuardrailError::AuthenticationFailed`] if token decoding or validation fails.
    pub async fn extract(
        &self,
        auth_header: Option<&str>,
        api_key_header: Option<&str>,
        current_epoch_secs: u64,
    ) -> Result<IdentityContext, GuardrailError> {
        // 1. Try Bearer JWT
        if let Some(auth_str) = auth_header {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let token_data =
                    decode::<AgentJwtClaims>(token, &self.jwt_decoding_key, &Validation::default())
                        .map_err(|e| {
                            GuardrailError::AuthenticationFailed(format!(
                                "JWT validation failed: {e}"
                            ))
                        })?;

                let claims = token_data.claims;

                if claims.exp <= current_epoch_secs {
                    return Err(GuardrailError::AuthenticationFailed(
                        "JWT token has expired".to_string(),
                    ));
                }

                let identity = AgentIdentity::new(&claims.sub, &claims.sub, &claims.role);

                return Ok(IdentityContext {
                    identity,
                    tenant_id: claims.tenant,
                    permissions: claims.perms,
                    session_scope: "jwt-authenticated".to_string(),
                    expires_at: claims.exp,
                });
            }
        }

        // 2. Try X-API-Key
        if let Some(key) = api_key_header {
            let registry = self.api_key_registry.read().await;
            let found_ctx = registry.get(key).cloned();
            drop(registry);

            if let Some(ctx) = found_ctx {
                if ctx.is_expired(current_epoch_secs) {
                    return Err(GuardrailError::AuthenticationFailed(
                        "API Key has expired".to_string(),
                    ));
                }
                return Ok(ctx);
            }
            return Err(GuardrailError::AuthenticationFailed(
                "Invalid X-API-Key".to_string(),
            ));
        }

        Err(GuardrailError::AuthenticationFailed(
            "Missing Authorization Bearer or X-API-Key header".to_string(),
        ))
    }
}
