#![allow(missing_docs)]

use aegis_core::{
    jsonrpc::{
        JsonRpcError, JSONRPC_INTERNAL_ERROR, JSONRPC_INVALID_PARAMS, JSONRPC_INVALID_REQUEST,
        JSONRPC_METHOD_NOT_FOUND, JSONRPC_PARSE_ERROR,
    },
    McpError,
};

#[test]
fn test_error_code_mapping() {
    let err_parse = McpError::ParseError("syntax error".into());
    assert_eq!(err_parse.code(), JSONRPC_PARSE_ERROR);
    assert!(err_parse.is_protocol_error());

    let err_invalid_req = McpError::InvalidRequest("missing method".into());
    assert_eq!(err_invalid_req.code(), JSONRPC_INVALID_REQUEST);

    let err_method = McpError::MethodNotFound("foo/bar".into());
    assert_eq!(err_method.code(), JSONRPC_METHOD_NOT_FOUND);

    let err_params = McpError::InvalidParams("bad type".into());
    assert_eq!(err_params.code(), JSONRPC_INVALID_PARAMS);

    let err_internal = McpError::InternalError("db crash".into());
    assert_eq!(err_internal.code(), JSONRPC_INTERNAL_ERROR);
}

#[test]
fn test_security_error_mapping() {
    let err_unauth = McpError::UnauthorizedToolCall {
        tool_name: "rm_rf".into(),
        reason: "Role 'user' lacks execution permission".into(),
    };
    assert_eq!(err_unauth.code(), -32_001);
    assert!(err_unauth.is_security_error());

    let err_pii = McpError::PiiViolation {
        rule: "ssn-filter".into(),
        detail: "Found SSN in tool arguments".into(),
    };
    assert_eq!(err_pii.code(), -32_002);
    assert!(err_pii.is_security_error());

    let err_inj = McpError::InjectionDetected {
        threat_type: "PromptInjection".into(),
        detail: "Ignore previous instructions attempt".into(),
    };
    assert_eq!(err_inj.code(), -32_003);
    assert!(err_inj.is_security_error());

    let err_rate = McpError::RateLimitExceeded {
        limit: 100,
        reset_seconds: 60,
    };
    assert_eq!(err_rate.code(), -32_004);
    assert!(err_rate.is_security_error());
}

#[test]
fn test_upstream_error_mapping() {
    let err_unreachable = McpError::UpstreamUnreachable {
        uri: "http://localhost:9090".into(),
        detail: "Connection refused".into(),
    };
    assert_eq!(err_unreachable.code(), -32_010);
    assert!(err_unreachable.is_upstream_error());

    let err_timeout = McpError::UpstreamTimeout {
        uri: "http://localhost:9090".into(),
        timeout_ms: 5000,
    };
    assert_eq!(err_timeout.code(), -32_011);
    assert!(err_timeout.is_upstream_error());

    let err_bad_gw = McpError::BadGateway {
        message: "502 Bad Gateway".into(),
    };
    assert_eq!(err_bad_gw.code(), -32_012);
    assert!(err_bad_gw.is_upstream_error());
}

#[test]
fn test_conversion_to_json_rpc_error() {
    let domain_err = McpError::UnauthorizedToolCall {
        tool_name: "exec".into(),
        reason: "forbidden".into(),
    };

    let rpc_err: JsonRpcError = domain_err.into();
    assert_eq!(rpc_err.code, -32_001);
    assert!(rpc_err.message.contains("Unauthorized tool call"));
}
