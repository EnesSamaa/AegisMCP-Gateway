#![allow(missing_docs)]

use aegis_guardrails::DlpMaskingEngine;

#[test]
fn test_dlp_masking_credit_card_and_email() {
    let dlp = DlpMaskingEngine::new();

    let input = "Customer john.doe@example.com paid using card 4532-1122-3344-5566.";
    let (masked, report) = dlp.mask_payload(input);

    assert_eq!(report.items_masked_count, 2);
    assert!(report
        .masked_categories
        .contains(&"Credit Card".to_string()));
    assert!(report
        .masked_categories
        .contains(&"Email Address".to_string()));
    assert!(masked.contains("[REDACTED_EMAIL]"));
    assert!(masked.contains("[REDACTED_CREDIT_CARD]"));
    assert!(!masked.contains("john.doe@example.com"));
    assert!(!masked.contains("4532-1122-3344-5566"));
}

#[test]
fn test_dlp_masking_api_keys_and_ssn() {
    let dlp = DlpMaskingEngine::new();

    let input = "Secret key sk_test_mock_secret_12345678901234567890 and SSN 123-45-6789.";
    let (masked, report) = dlp.mask_payload(input);

    assert_eq!(report.items_masked_count, 2);
    assert!(masked.contains("[REDACTED_API_KEY]"));
    assert!(masked.contains("[REDACTED_SSN]"));
    assert!(!masked.contains("123-45-6789"));
}

#[test]
fn test_dlp_sse_event_chunk_masking() {
    let dlp = DlpMaskingEngine::new();

    let sse_chunk =
        "event: message\ndata: {\"email\":\"admin@company.org\",\"status\":\"active\"}\n\n";
    let (masked, report) = dlp.mask_payload(sse_chunk);

    assert_eq!(report.items_masked_count, 1);
    assert!(masked.starts_with("event: message\ndata: "));
    assert!(masked.ends_with("\n\n"));
    assert!(masked.contains("[REDACTED_EMAIL]"));
}

#[test]
fn test_clean_payload_dlp_unmodified() {
    let dlp = DlpMaskingEngine::new();

    let clean = "{\"jsonrpc\":\"2.0\",\"result\":{\"status\":\"ok\"},\"id\":1}";
    let (masked, report) = dlp.mask_payload(clean);

    assert_eq!(report.items_masked_count, 0);
    assert_eq!(masked, clean);
}
