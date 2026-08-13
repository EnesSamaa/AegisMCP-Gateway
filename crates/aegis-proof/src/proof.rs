//! Merkle inclusion proof generation and verification logic.

use crate::Sha256Digest;
use serde::{Deserialize, Serialize};

/// High-level serializable Merkle inclusion proof for an audit entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditMerkleProof {
    /// Zero-based index of the target audit entry.
    pub leaf_index: usize,
    /// Hex-encoded SHA-256 payload digest of the target entry.
    pub leaf_hash: String,
    /// Ordered list of hex-encoded sibling hashes along the Merkle authentication path.
    pub sibling_hashes: Vec<String>,
    /// Hex-encoded Merkle root hash at time of proof generation.
    pub root_hash: String,
}

impl AuditMerkleProof {
    /// Constructs a new `AuditMerkleProof`.
    #[must_use]
    pub fn new(
        leaf_index: usize,
        leaf_hash: impl Into<String>,
        sibling_hashes: Vec<String>,
        root_hash: impl Into<String>,
    ) -> Self {
        Self {
            leaf_index,
            leaf_hash: leaf_hash.into(),
            sibling_hashes,
            root_hash: root_hash.into(),
        }
    }

    /// Verifies this proof against an expected Merkle root hex string without needing ledger state.
    #[must_use]
    pub fn verify(&self, expected_root_hex: &str) -> bool {
        if self.root_hash != expected_root_hex {
            return false;
        }

        let Ok(leaf_digest) = Sha256Digest::from_hex(&self.leaf_hash) else {
            return false;
        };

        let Ok(expected_root) = Sha256Digest::from_hex(expected_root_hex) else {
            return false;
        };

        let mut siblings = Vec::with_capacity(self.sibling_hashes.len());
        for sib_hex in &self.sibling_hashes {
            let Ok(d) = Sha256Digest::from_hex(sib_hex) else {
                return false;
            };
            siblings.push(d);
        }

        let core_proof = crate::merkle::MerkleProof {
            leaf: leaf_digest,
            index: self.leaf_index,
            siblings,
        };

        core_proof.verify(&expected_root)
    }
}
