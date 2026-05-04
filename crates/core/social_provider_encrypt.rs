//! AES-256-GCM encryption for social provider client secrets.
//!
//! Sibling to `mfa_encrypt`. Differs only in the storage shape:
//! returns nonce and ciphertext as separate byte vectors so they can
//! bind directly to the `client_secret_enc` and `client_secret_nonce`
//! BLOB columns in `allowthem_social_providers`.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::TryRngCore;
use rand::rngs::OsRng;

use crate::error::AuthError;

pub(crate) struct EncryptedSecret {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub(crate) fn encrypt_split(
    plaintext: &[u8],
    key: &[u8; 32],
) -> Result<EncryptedSecret, AuthError> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| AuthError::MfaEncryption(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AuthError::MfaEncryption(e.to_string()))?;
    Ok(EncryptedSecret {
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub(crate) fn decrypt_split(
    nonce: &[u8],
    ciphertext: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, AuthError> {
    if nonce.len() != 12 {
        return Err(AuthError::MfaEncryption("nonce must be 12 bytes".into()));
    }
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AuthError::MfaEncryption(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [42u8; 32];

    #[test]
    fn round_trip() {
        let secret = b"shhh-its-a-secret";
        let enc = encrypt_split(secret, &KEY).unwrap();
        let dec = decrypt_split(&enc.nonce, &enc.ciphertext, &KEY).unwrap();
        assert_eq!(dec, secret);
    }

    #[test]
    fn wrong_key_fails() {
        let enc = encrypt_split(b"secret", &KEY).unwrap();
        let bad_key = [7u8; 32];
        assert!(decrypt_split(&enc.nonce, &enc.ciphertext, &bad_key).is_err());
    }

    #[test]
    fn nonce_is_random_per_call() {
        let a = encrypt_split(b"x", &KEY).unwrap();
        let b = encrypt_split(b"x", &KEY).unwrap();
        assert_ne!(a.nonce, b.nonce);
    }

    #[test]
    fn rejects_wrong_length_nonce() {
        assert!(decrypt_split(&[0u8; 11], b"ct", &KEY).is_err());
    }
}
