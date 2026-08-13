#![allow(missing_docs)]

use aegis_core::AuditEntry;
use aegis_proof::AuditLedger;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn test_payload_hash_determinism_and_seq_integrity() {
    let ledger = AuditLedger::new();

    let entry_hash = AuditEntry::compute_hash(
        "req-100",
        1_700_000_000_000_000,
        "agent-alpha",
        "sql_query",
        "ALLOW",
    );

    let entry_hash_2 = AuditEntry::compute_hash(
        "req-100",
        1_700_000_000_000_000,
        "agent-alpha",
        "sql_query",
        "ALLOW",
    );

    assert_eq!(
        entry_hash, entry_hash_2,
        "Payload hash must be deterministic"
    );

    ledger.log_entry(
        "req-100",
        1_700_000_000_000_000,
        "agent-alpha",
        "sql_query",
        "ALLOW",
        150,
    );

    // Wait for async persistence worker
    tokio::time::sleep(Duration::from_millis(50)).await;

    let fetched = ledger
        .get_by_request_id("req-100")
        .await
        .expect("Entry found");
    assert_eq!(fetched.seq_id, 1);
    assert_eq!(fetched.payload_hash, entry_hash);
}

#[tokio::test]
async fn test_audit_ledger_concurrent_logging() {
    let ledger = Arc::new(AuditLedger::new());
    let mut handles = Vec::new();

    for i in 0..50 {
        let ledger_clone = Arc::clone(&ledger);
        handles.push(tokio::spawn(async move {
            let req_id = format!("req-task-{i}");
            ledger_clone.log_entry(
                req_id,
                1_700_000_000_000_000 + i,
                "agent-concurrent",
                "tools/call",
                "ALLOW",
                120,
            );
        }));
    }

    for handle in handles {
        handle.await.expect("Task joined");
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(ledger.len().await, 50);

    // Verify lookup by request ID for task 25
    let fetched = ledger
        .get_by_request_id("req-task-25")
        .await
        .expect("Found task 25 entry");
    assert_eq!(fetched.tool_name, "tools/call");
}
