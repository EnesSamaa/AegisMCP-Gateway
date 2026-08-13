#![allow(missing_docs)]

use aegis_core::AgentIdentity;
use aegis_guardrails::{
    AgentJwtClaims, IdentityContext, IdentityExtractor, TokenTranslator, UpstreamCredential,
};
use jsonwebtoken::{encode, EncodingKey, Header};

#[tokio::test]
async fn test_extract_identity_from_valid_jwt() {
    let secret = b"super-secret-jwt-key-12345";
    let extractor = IdentityExtractor::new(secret);

    let claims = AgentJwtClaims {
        sub: "agent-007".to_string(),
        role: "analyst".to_string(),
        tenant: "tenant-corp-a".to_string(),
        perms: vec!["tools:read".to_string(), "tools:call".to_string()],
        exp: 2_000_000_000,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .expect("JWT encoding succeeded");

    let auth_header = format!("Bearer {token}");
    let ctx = extractor
        .extract(Some(&auth_header), None, 1_700_000_000)
        .await
        .expect("Extraction succeeded");

    assert_eq!(ctx.identity.agent_id(), "agent-007");
    assert_eq!(ctx.identity.role(), "analyst");
    assert_eq!(ctx.tenant_id, "tenant-corp-a");
    assert!(ctx.has_permission("tools:call"));
    assert!(!ctx.is_expired(1_700_000_000));
}

#[tokio::test]
async fn test_extract_identity_expired_jwt_rejected() {
    let secret = b"super-secret-jwt-key-12345";
    let extractor = IdentityExtractor::new(secret);

    let claims = AgentJwtClaims {
        sub: "agent-007".to_string(),
        role: "analyst".to_string(),
        tenant: "tenant-corp-a".to_string(),
        perms: vec![],
        exp: 1_600_000_000, // Expired timestamp
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .expect("JWT encoding succeeded");

    let auth_header = format!("Bearer {token}");
    let res = extractor
        .extract(Some(&auth_header), None, 1_700_000_000)
        .await;

    assert!(res.is_err());
}

#[tokio::test]
async fn test_extract_identity_from_api_key() {
    let extractor = IdentityExtractor::new(b"secret");

    let static_ctx = IdentityContext {
        identity: AgentIdentity::new("api-agent-1", "ApiAgent", "admin"),
        tenant_id: "tenant-beta".to_string(),
        permissions: vec!["*".to_string()],
        session_scope: "api-key-scoped".to_string(),
        expires_at: 2_000_000_000,
    };

    extractor
        .register_api_key("mock_api_key_test_1234567890", static_ctx.clone())
        .await;

    let ctx = extractor
        .extract(None, Some("mock_api_key_test_1234567890"), 1_700_000_000)
        .await
        .expect("API key extraction succeeded");

    assert_eq!(ctx, static_ctx);
}

#[tokio::test]
async fn test_token_translator_mapping_and_scope_restriction() {
    let translator = TokenTranslator::new();

    let credential = UpstreamCredential {
        token: "mcp_upstream_restricted_token_xyz987".to_string(),
        target_upstream: "http://upstream-mcp-server:8080".to_string(),
        allowed_scopes: vec!["read_only".to_string()],
        expires_at: 2_000_000_000,
    };

    translator
        .register_rule(
            "tenant-corp-a",
            "analyst",
            "http://upstream-mcp-server:8080",
            credential.clone(),
        )
        .await;

    let ctx = IdentityContext {
        identity: AgentIdentity::new("agent-1", "Agent", "analyst"),
        tenant_id: "tenant-corp-a".to_string(),
        permissions: vec![],
        session_scope: "session".to_string(),
        expires_at: 2_000_000_000,
    };

    let translated = translator
        .translate(&ctx, "http://upstream-mcp-server:8080", 1_700_000_000)
        .await
        .expect("Translation succeeded");

    assert_eq!(translated.token, "mcp_upstream_restricted_token_xyz987");
    assert_eq!(translated.allowed_scopes, vec!["read_only"]);
}

#[tokio::test]
async fn test_token_translator_expired_credential_rejected() {
    let translator = TokenTranslator::new();

    let expired_credential = UpstreamCredential {
        token: "expired_token".to_string(),
        target_upstream: "http://upstream-mcp-server:8080".to_string(),
        allowed_scopes: vec![],
        expires_at: 1_600_000_000, // Expired
    };

    translator
        .register_rule(
            "tenant-corp-a",
            "analyst",
            "http://upstream-mcp-server:8080",
            expired_credential,
        )
        .await;

    let ctx = IdentityContext {
        identity: AgentIdentity::new("agent-1", "Agent", "analyst"),
        tenant_id: "tenant-corp-a".to_string(),
        permissions: vec![],
        session_scope: "session".to_string(),
        expires_at: 2_000_000_000,
    };

    let res = translator
        .translate(&ctx, "http://upstream-mcp-server:8080", 1_700_000_000)
        .await;

    assert!(res.is_err());
}
