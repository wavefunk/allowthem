//! TOTP core: secret management, code validation, and recovery codes.

use crate::db::Db;
use crate::error::AuthError;
use crate::types::UserId;

/// Build an `otpauth://totp/` URI from a base32 secret.
pub fn totp_uri(_secret_base32: &str, _account_name: &str, _issuer: &str) -> String {
    todo!()
}
