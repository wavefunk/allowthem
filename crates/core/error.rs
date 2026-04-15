#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("invalid email format")]
    InvalidEmail,

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("invalid password hash: {0}")]
    InvalidPasswordHash(String),

    #[error("email error: {0}")]
    Email(String),

    #[error("jwt error: {0}")]
    Jwt(String),
}
