//! Incremental SHA-256 Merkle Tree Engine.

use crate::{error::ProofError, merkle::MerkleTree as CoreMerkleTree, Sha256Digest};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Thread-safe incremental Merkle Tree engine for appending audit leaf hashes.
#[derive(Clone, Default)]
pub struct IncrementalMerkleTree {
    inner: Arc<RwLock<CoreMerkleTree>>,
}

impl IncrementalMerkleTree {
    /// Creates a new, empty `IncrementalMerkleTree`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(CoreMerkleTree::new())),
        }
    }

    /// Appends a hex-encoded SHA-256 leaf digest to the tree.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::InvalidDigestHex`] if `hex_hash` is invalid.
    pub async fn push_leaf_hex(&self, hex_hash: &str) -> Result<usize, ProofError> {
        let digest = Sha256Digest::from_hex(hex_hash)?;
        let mut tree = self.inner.write().await;
        tree.push(digest);
        Ok(tree.len() - 1)
    }

    /// Computes and returns the current hex-encoded Merkle root.
    pub async fn root_hex(&self) -> Option<String> {
        let tree = self.inner.read().await;
        tree.root().ok().map(Sha256Digest::to_hex)
    }

    /// Returns total number of leaves in the tree.
    pub async fn len(&self) -> usize {
        let tree = self.inner.read().await;
        tree.len()
    }

    /// Returns `true` if the tree has no leaves.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Generates a core [`crate::merkle::MerkleProof`] for the leaf at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError`] if index is out of bounds or tree is empty.
    pub async fn prove(&self, index: usize) -> Result<crate::merkle::MerkleProof, ProofError> {
        let tree = self.inner.read().await;
        tree.prove(index)
    }
}
