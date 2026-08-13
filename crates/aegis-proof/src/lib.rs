//! # aegis-proof
//!
//! Cryptographic hashing and Merkle-tree proof infrastructure for AegisMCP-Gateway.
//!
//! This crate provides the audit-trail layer: every proxied request/response
//! pair is hashed and inserted into an append-only Merkle tree whose root can
//! be attested at any time.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic, clippy::nursery)]
#![warn(missing_docs)]

pub mod error;
pub mod hash;
pub mod ledger;
pub mod merkle;
pub mod proof;
pub mod tree;

pub use error::ProofError;
pub use hash::Sha256Digest;
pub use ledger::AuditLedger;
pub use merkle::{MerkleProof, MerkleTree};
pub use proof::AuditMerkleProof;
pub use tree::IncrementalMerkleTree;
