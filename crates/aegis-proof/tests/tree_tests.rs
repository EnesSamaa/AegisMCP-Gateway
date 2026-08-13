#![allow(missing_docs)]

use aegis_core::AuditEntry;
use aegis_proof::{AuditLedger, IncrementalMerkleTree};
use std::time::Duration;

#[tokio::test]
async fn test_merkle_tree_root_calculation_determinism() {
    let tree1 = IncrementalMerkleTree::new();
    let tree2 = IncrementalMerkleTree::new();

    let leaf1 = AuditEntry::compute_hash("req-1", 1000, "agent-a", "tool-a", "ALLOW");
    let leaf2 = AuditEntry::compute_hash("req-2", 2000, "agent-b", "tool-b", "DENY");

    tree1.push_leaf_hex(&leaf1).await.unwrap();
    tree1.push_leaf_hex(&leaf2).await.unwrap();

    tree2.push_leaf_hex(&leaf1).await.unwrap();
    tree2.push_leaf_hex(&leaf2).await.unwrap();

    let root1 = tree1.root_hex().await.expect("Root 1 calculated");
    let root2 = tree2.root_hex().await.expect("Root 2 calculated");

    assert_eq!(root1, root2, "Merkle roots must be deterministic");
}

#[tokio::test]
async fn test_merkle_proof_generation_and_verification() {
    let ledger = AuditLedger::new();

    for i in 0..8 {
        ledger.log_entry(
            format!("req-{i}"),
            1000 + i,
            "agent-test",
            "tools/call",
            "ALLOW",
            100,
        );
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    let root = ledger.get_merkle_root().await.expect("Merkle root exists");

    for seq in 1..=8 {
        let proof = ledger
            .generate_proof_by_seq(seq)
            .await
            .expect("Generated proof");
        assert!(
            proof.verify(&root),
            "Proof verification failed for seq {seq}"
        );

        // Tamper test with invalid root
        assert!(
            !proof.verify("0000000000000000000000000000000000000000000000000000000000000000"),
            "Proof verification must fail for tampered root"
        );
    }
}

#[tokio::test]
async fn test_tamper_detection_on_modified_audit_logs() {
    let ledger = AuditLedger::new();

    ledger.log_entry("req-original", 5000, "agent-x", "db_query", "ALLOW", 200);

    tokio::time::sleep(Duration::from_millis(50)).await;

    let root = ledger.get_merkle_root().await.expect("Root exists");
    let mut proof = ledger
        .generate_proof_by_request_id("req-original")
        .await
        .expect("Proof exists");

    assert!(proof.verify(&root), "Original proof must verify");

    // Tamper with leaf hash inside proof
    proof.leaf_hash =
        "1111111111111111111111111111111111111111111111111111111111111111".to_string();

    assert!(
        !proof.verify(&root),
        "Tampered leaf proof must fail verification"
    );
}
