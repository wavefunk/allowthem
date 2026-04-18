pub use allowthem_server::branding::{compute_accent_variants, default_accents};

use allowthem_core::applications::BrandingConfig;
use allowthem_core::types::ClientId;

use crate::state::AppState;

pub async fn lookup_branding(
    state: &AppState,
    client_id: Option<&ClientId>,
) -> Option<BrandingConfig> {
    allowthem_server::branding::lookup_branding(&state.ath, client_id).await
}
