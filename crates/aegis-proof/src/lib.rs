//! # aegis-proof
//!
//! Cryptographic hashing and Merkle-tree proof infrastructure for AegisMCP-Gateway.
//!
//! This crate provides the audit-trail layer: every proxied request/response
//! pair is hashed and inserted into an append-only Merkle tree whose root can
//! be attested at any time.
//!
//! ## Module organisation
//!
//! ```text
//! aegis-proof
//! ├── error  — proof-specific error types
//! ├── hash   — SHA-256 hashing utilities
//! └── merkle — Merkle tree and inclusion proof types
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic, clippy::nursery)]
#![warn(missing_docs)]

pub mod error;
pub mod hash;
pub mod merkle;

pub use error::ProofError;
pub use hash::Sha256Digest;
pub use merkle::{MerkleProof, MerkleTree};
