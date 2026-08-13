#![allow(missing_docs)]

use aegis_core::{AgentIdentity, ToolCall};
use aegis_guardrails::{AgentRateLimiter, LoopBreakerConfig, LoopBreakerEngine};

#[tokio::test]
async fn test_loop_breaker_trips_on_repeated_calls() {
    let config = LoopBreakerConfig {
        max_identical_calls: 3,
        window_duration_secs: 10,
    };
    let breaker = LoopBreakerEngine::with_config(config);

    let tool_call = ToolCall::new(
        "sql_query",
        Some(serde_json::json!({"query": "SELECT * FROM users"})),
    );

    let session = "session-test-123";

    // 3 identical calls allowed
    assert!(breaker
        .check_and_record(session, &tool_call, 100)
        .await
        .is_ok());
    assert!(breaker
        .check_and_record(session, &tool_call, 101)
        .await
        .is_ok());
    assert!(breaker
        .check_and_record(session, &tool_call, 102)
        .await
        .is_ok());

    // 4th identical call trips loop breaker
    let res = breaker.check_and_record(session, &tool_call, 103).await;
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Agent execution loop detected"));
}

#[tokio::test]
async fn test_loop_breaker_resets_after_window() {
    let config = LoopBreakerConfig {
        max_identical_calls: 2,
        window_duration_secs: 5,
    };
    let breaker = LoopBreakerEngine::with_config(config);

    let tool_call = ToolCall::new("list_files", None);
    let session = "session-test-456";

    assert!(breaker
        .check_and_record(session, &tool_call, 10)
        .await
        .is_ok());
    assert!(breaker
        .check_and_record(session, &tool_call, 11)
        .await
        .is_ok());

    // Expiry: 10 + 6 = 16 (window is 5s, so call at t=10 expired)
    assert!(breaker
        .check_and_record(session, &tool_call, 16)
        .await
        .is_ok());
}

#[tokio::test]
async fn test_rate_limiter_quota_exhaustion_and_reset() {
    let limiter = AgentRateLimiter::new(2, 5); // 2 requests per 5 seconds
    let agent = AgentIdentity::new("agent-007", "JamesBond", "analyst");

    let res1 = limiter.check_rate_limit(&agent, 100).await;
    assert!(res1.allowed);
    assert_eq!(res1.remaining_quota, 1);

    let res2 = limiter.check_rate_limit(&agent, 101).await;
    assert!(res2.allowed);
    assert_eq!(res2.remaining_quota, 0);

    // 3rd call exceeds limit
    let res3 = limiter.check_rate_limit(&agent, 102).await;
    assert!(!res3.allowed);
    assert_eq!(res3.remaining_quota, 0);

    // After 5s window, resets
    let res4 = limiter.check_rate_limit(&agent, 106).await;
    assert!(res4.allowed);
}
