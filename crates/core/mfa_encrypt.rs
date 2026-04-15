//! AES-256-GCM encryption for TOTP secrets at rest.

use crate::error::AuthError;

pub(crate) fn encrypt_secret(_plaintext: &[u8], _key: &[u8; 32]) -> Result<String, AuthError> {
    todo!()
}

pub(crate) fn decrypt_secret(_stored: &str, _key: &[u8; 32]) -> Result<Vec<u8>, AuthError> {
    todo!()
}
