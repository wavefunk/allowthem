use allowthem_core::AuthError;

#[derive(Debug, thiserror::Error)]
pub enum SaasError {
    #[error("slug is already taken")]
    SlugTaken,
    #[error("slug is invalid: {0}")]
    SlugInvalid(&'static str),
    #[error("slug is reserved")]
    SlugReserved,
    #[error("tenant not found")]
    TenantNotFound,
    #[error("slug cannot be changed after first login")]
    SlugChangeAfterFirstLogin,
    #[error("provisioning failed: {0}")]
    ProvisionFailed(String),
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db_err) if db_err.is_unique_violation())
}

pub(crate) fn map_slug_conflict(e: sqlx::Error) -> SaasError {
    if is_unique_violation(&e) {
        SaasError::SlugTaken
    } else {
        SaasError::Db(e)
    }
}
