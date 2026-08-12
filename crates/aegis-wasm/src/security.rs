//! Ed25519 Signature Verification for WASM Plugin Binaries.

use crate::error::WasmError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Verifies that the provided WASM binary payload matches an Ed25519 signature using a trusted public key.
///
/// # Errors
///
/// Returns [`WasmError::SignatureVerification`] if key parsing, signature decoding, or verification fails.
pub fn verify_plugin_signature(
    wasm_bytes: &[u8],
    signature_bytes: &[u8; 64],
    public_key_bytes: &[u8; 32],
) -> Result<(), WasmError> {
    let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|e| WasmError::SignatureVerification(format!("Invalid public key bytes: {e}")))?;

    let signature = Signature::from_bytes(signature_bytes);

    verifying_key
        .verify(wasm_bytes, &signature)
        .map_err(|e| WasmError::SignatureVerification(format!("Ed25519 signature verification failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn test_valid_ed25519_signature_verification() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let wasm_payload = b"\0asm\x0d\x00\x01\x00_test_wasm_bytes";
        let signature: Signature = signing_key.sign(wasm_payload);

        let res = verify_plugin_signature(
            wasm_payload,
            &signature.to_bytes(),
            verifying_key.as_bytes(),
        );

        assert!(res.is_ok());
    }

    #[test]
    fn test_invalid_ed25519_signature_rejected() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let wasm_payload = b"\0asm\x0d\x00\x01\x00_test_wasm_bytes";
        let mut bad_signature_bytes = signing_key.sign(wasm_payload).to_bytes();
        bad_signature_bytes[0] ^= 0xFF; // Corrupt signature byte

        let res = verify_plugin_signature(
            wasm_payload,
            &bad_signature_bytes,
            verifying_key.as_bytes(),
        );

        assert!(res.is_err());
    }
}
