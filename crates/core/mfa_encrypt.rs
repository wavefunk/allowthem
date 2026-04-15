//! AES-256-GCM encryption for TOTP secrets at rest.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64ct::{Base64, Encoding};
use rand::rngs::OsRng;
use rand::TryRngCore;

use crate::error::AuthError;

/// Encrypt plaintext bytes with AES-256-GCM.
///
/// Generates a random 96-bit nonce and returns `base64(nonce || ciphertext || tag)`.
/// The nonce is prepended to the ciphertext so it can be extracted during decryption.
pub(crate) fn encrypt_secret(plaintext: &[u8], key: &[u8; 32]) -> Result<String, AuthError> {
    let cipher = Aes256Gcm::new(key.into());

    let mut nonce_bytes = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| AuthError::MfaEncryption(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AuthError::MfaEncryption(e.to_string()))?;

    // nonce (12) || ciphertext+tag
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(Base64::encode_string(&combined))
}

/// Decrypt a stored secret produced by `encrypt_secret`.
///
/// Decodes base64, splits the first 12 bytes as the nonce, and decrypts
/// the remainder with AES-256-GCM.
pub(crate) fn decrypt_secret(stored: &str, key: &[u8; 32]) -> Result<Vec<u8>, AuthError> {
    let combined =
        Base64::decode_vec(stored).map_err(|e| AuthError::MfaEncryption(e.to_string()))?;

    if combined.len() < 13 {
        return Err(AuthError::MfaEncryption("ciphertext too short".into()));
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AuthError::MfaEncryption(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: [u8; 32] = [0x42; 32];
    const KEY_B: [u8; 32] = [0x99; 32];

    #[test]
    fn encrypt_decrypt_round_trip() {
        let plaintext = b"JBSWY3DPEHPK3PXP";
        let encrypted = encrypt_secret(plaintext, &KEY_A).expect("encrypt");
        let decrypted = decrypt_secret(&encrypted, &KEY_A).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_encryptions_differ() {
        let plaintext = b"same-secret";
        let enc1 = encrypt_secret(plaintext, &KEY_A).expect("encrypt 1");
        let enc2 = encrypt_secret(plaintext, &KEY_A).expect("encrypt 2");
        assert_ne!(enc1, enc2, "different nonces must produce different ciphertext");
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let plaintext = b"secret-data";
        let encrypted = encrypt_secret(plaintext, &KEY_A).expect("encrypt");
        let result = decrypt_secret(&encrypted, &KEY_B);
        assert!(result.is_err(), "wrong key must fail decryption");
    }

    #[test]
    fn decrypt_garbage_fails() {
        let result = decrypt_secret("not-valid-base64!!!", &KEY_A);
        assert!(result.is_err(), "garbage input must fail");
    }

    #[test]
    fn decrypt_truncated_fails() {
        let short = Base64::encode_string(&[0u8; 10]);
        let result = decrypt_secret(&short, &KEY_A);
        assert!(result.is_err(), "truncated ciphertext must fail");
    }
}
