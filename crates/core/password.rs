use argon2::{Argon2, PasswordVerifier};
use password_hash::{PasswordHash as PhcHash, PasswordHasher, SaltString, rand_core::OsRng};

use crate::error::AuthError;
use crate::types::PasswordHash;

/// Hash a plaintext password with Argon2id.
///
/// Uses `Argon2::default()` (Argon2id, OWASP-recommended params: m=19456, t=2, p=1).
/// Returns the PHC string wrapped in the `PasswordHash` newtype.
pub fn hash_password(plaintext: &str) -> Result<PasswordHash, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let phc = Argon2::default()
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| AuthError::InvalidPasswordHash(e.to_string()))?;
    Ok(PasswordHash::new_unchecked(phc.to_string()))
}

/// Verify a plaintext password against a stored `PasswordHash`.
///
/// Returns `Ok(true)` if the password matches, `Ok(false)` if it does not.
/// Returns `Err` only for structural errors such as a corrupt or unparseable hash string.
pub fn verify_password(plaintext: &str, hash: &PasswordHash) -> Result<bool, AuthError> {
    let phc =
        PhcHash::new(hash.as_str()).map_err(|e| AuthError::InvalidPasswordHash(e.to_string()))?;
    match Argon2::default().verify_password(plaintext.as_bytes(), &phc) {
        Ok(()) => Ok(true),
        Err(password_hash::Error::Password) => Ok(false),
        Err(e) => Err(AuthError::InvalidPasswordHash(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_correct_password() {
        let hash = hash_password("correct-horse-battery-staple").expect("hash_password");
        let result =
            verify_password("correct-horse-battery-staple", &hash).expect("verify_password");
        assert!(result, "correct password must verify as true");
    }

    #[test]
    fn test_verify_wrong_password_returns_false() {
        let hash = hash_password("the-real-password").expect("hash_password");
        let result = verify_password("wrong-password", &hash).expect("verify_password");
        assert!(
            !result,
            "wrong password must return Ok(false), not an error"
        );
    }

    #[test]
    fn test_verify_garbage_hash_returns_error() {
        let garbage = PasswordHash::new_unchecked("not-a-phc-string".to_string());
        let result = verify_password("anything", &garbage);
        assert!(result.is_err(), "corrupt hash must return Err");
    }

    #[test]
    fn test_two_hashes_of_same_password_differ() {
        let h1 = hash_password("same-input").expect("hash 1");
        let h2 = hash_password("same-input").expect("hash 2");
        assert_ne!(
            h1.as_str(),
            h2.as_str(),
            "each hash must have a unique salt — identical outputs would indicate missing salt"
        );
    }
}
