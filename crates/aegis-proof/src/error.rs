//! Error types for the `aegis-proof` crate.

use thiserror::Error;

/// Errors emitted by the Merkle proof infrastructure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProofError {
    /// Attempted to compute a root or generate a proof on an empty tree.
    #[error("cannot operate on an empty Merkle tree")]
    EmptyTree,

    /// Requested leaf index is out of bounds.
    #[error("leaf index {index} is out of bounds (tree has {len} leaves)")]
    IndexOutOfBounds {
        /// The requested index.
        index: usize,
        /// The current number of leaves.
        len: usize,
    },

    /// Invalid hex string provided for SHA-256 digest parsing.
    #[error("invalid digest hex string: {0}")]
    InvalidDigestHex(String),
}
