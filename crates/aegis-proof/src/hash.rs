//! SHA-256 hashing utilities.

use sha2::{Digest, Sha256};

/// A 32-byte SHA-256 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Compute the SHA-256 digest of `data`.
    #[must_use]
    pub fn of(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Combine two digests (for Merkle tree internal nodes).
    ///
    /// Uses `SHA-256(left || right)`.
    #[must_use]
    pub fn combine(left: &Self, right: &Self) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(left.0);
        hasher.update(right.0);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Return the digest as a lowercase hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Return the raw byte array.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_digest_is_deterministic() {
        let a = Sha256Digest::of(b"");
        let b = Sha256Digest::of(b"");
        assert_eq!(a, b);
    }

    #[test]
    fn known_sha256_vector() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469f490816218f9b29
        //                   (well-known test vector)
        let digest = Sha256Digest::of(b"abc");
        assert!(digest.to_hex().starts_with("ba7816bf"));
    }

    #[test]
    fn combine_is_not_commutative() {
        let a = Sha256Digest::of(b"left");
        let b = Sha256Digest::of(b"right");
        assert_ne!(Sha256Digest::combine(&a, &b), Sha256Digest::combine(&b, &a));
    }
}
