//! Merkle tree and inclusion proof types.

use crate::{error::ProofError, hash::Sha256Digest};

// ---------------------------------------------------------------------------
// Merkle tree
// ---------------------------------------------------------------------------

/// An append-only binary Merkle tree over [`Sha256Digest`] leaves.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    leaves: Vec<Sha256Digest>,
}

impl MerkleTree {
    /// Create a new, empty Merkle tree.
    #[must_use]
    pub const fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Append a new leaf to the tree.
    pub fn push(&mut self, leaf: Sha256Digest) {
        self.leaves.push(leaf);
    }

    /// Convenience method: hash `data` and append the resulting leaf.
    pub fn push_data(&mut self, data: &[u8]) {
        self.push(Sha256Digest::of(data));
    }

    /// Returns the number of leaves in the tree.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Returns `true` if the tree has no leaves.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Compute the Merkle root of the current leaves.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::EmptyTree`] if the tree has no leaves.
    pub fn root(&self) -> Result<Sha256Digest, ProofError> {
        if self.leaves.is_empty() {
            return Err(ProofError::EmptyTree);
        }
        Ok(compute_root(&self.leaves))
    }

    /// Generate an inclusion proof for the leaf at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::IndexOutOfBounds`] if `index >= len()`.
    pub fn prove(&self, index: usize) -> Result<MerkleProof, ProofError> {
        if index >= self.leaves.len() {
            return Err(ProofError::IndexOutOfBounds {
                index,
                len: self.leaves.len(),
            });
        }
        let siblings = generate_siblings(&self.leaves, index);
        Ok(MerkleProof {
            leaf: self.leaves[index],
            index,
            siblings,
        })
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------

/// A Merkle inclusion proof demonstrating that a leaf is in the tree.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The leaf digest being proven.
    pub leaf: Sha256Digest,

    /// The zero-based index of the leaf in the tree.
    pub index: usize,

    /// The sibling digests from leaf to root (left-to-right path).
    pub siblings: Vec<Sha256Digest>,
}

impl MerkleProof {
    /// Verify this proof against a known `root`.
    ///
    /// Returns `true` if the proof is valid.
    #[must_use]
    pub fn verify(&self, root: &Sha256Digest) -> bool {
        let mut current = self.leaf;
        let mut idx = self.index;

        for sibling in &self.siblings {
            current = if idx.is_multiple_of(2) {
                Sha256Digest::combine(&current, sibling)
            } else {
                Sha256Digest::combine(sibling, &current)
            };
            idx /= 2;
        }

        &current == root
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn compute_root(leaves: &[Sha256Digest]) -> Sha256Digest {
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut layer: Vec<Sha256Digest> = leaves
        .chunks(2)
        .map(|chunk| {
            if chunk.len() == 2 {
                Sha256Digest::combine(&chunk[0], &chunk[1])
            } else {
                Sha256Digest::combine(&chunk[0], &chunk[0])
            }
        })
        .collect();

    while layer.len() > 1 {
        layer = layer
            .chunks(2)
            .map(|chunk| {
                if chunk.len() == 2 {
                    Sha256Digest::combine(&chunk[0], &chunk[1])
                } else {
                    Sha256Digest::combine(&chunk[0], &chunk[0])
                }
            })
            .collect();
    }

    layer[0]
}

fn generate_siblings(leaves: &[Sha256Digest], index: usize) -> Vec<Sha256Digest> {
    let mut siblings = Vec::new();
    let mut layer: Vec<Sha256Digest> = leaves.to_vec();
    let mut idx = index;

    while layer.len() > 1 {
        let sibling_idx = if idx.is_multiple_of(2) {
            if idx + 1 < layer.len() { idx + 1 } else { idx }
        } else {
            idx - 1
        };
        siblings.push(layer[sibling_idx]);
        idx /= 2;
        layer = layer
            .chunks(2)
            .map(|chunk| {
                if chunk.len() == 2 {
                    Sha256Digest::combine(&chunk[0], &chunk[1])
                } else {
                    Sha256Digest::combine(&chunk[0], &chunk[0])
                }
            })
            .collect();
    }

    siblings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_root_equals_leaf() {
        let mut tree = MerkleTree::new();
        tree.push_data(b"only-leaf");
        let root = tree.root().expect("non-empty tree");
        assert_eq!(root, Sha256Digest::of(b"only-leaf"));
    }

    #[test]
    fn proof_verifies_against_root() {
        let mut tree = MerkleTree::new();
        for i in 0u8..8 {
            tree.push_data(&[i]);
        }
        let root = tree.root().expect("non-empty");
        for i in 0..8 {
            let proof = tree.prove(i).expect("valid index");
            assert!(proof.verify(&root), "proof for index {i} failed");
        }
    }

    #[test]
    fn empty_tree_returns_error() {
        let tree = MerkleTree::new();
        assert!(tree.root().is_err());
    }

    #[test]
    fn out_of_bounds_prove_returns_error() {
        let mut tree = MerkleTree::new();
        tree.push_data(b"leaf");
        assert!(tree.prove(5).is_err());
    }
}
