use std::sync::Arc;

use allowthem_core::AllowThem;
use allowthem_core::applications::BrandingConfig;
use allowthem_core::types::{AccentInk, ClientId};
use axum::Extension;

/// Default allowthem accent (white on dark; black on light).
pub const DEFAULT_ACCENT_HEX: &str = "#ffffff";

/// Pick an AAA-safe text color to pair with an accent fill.
///
/// Uses the classic YIQ luminance formula. Threshold 160 was chosen against
/// the standard Wave Funk pastel palette and a fixture of 20 accents: it
/// keeps every pastel above the line (black text) and every saturated deep
/// color below (white text). Invalid hex falls back to white ink — safest
/// for an accent we can't reason about.
pub fn derive_ink(hex: &str) -> AccentInk {
    match parse_hex(hex) {
        Some((r, g, b)) => {
            let y = (u32::from(r) * 299 + u32::from(g) * 587 + u32::from(b) * 114) / 1000;
            if y >= 160 {
                AccentInk::Black
            } else {
                AccentInk::White
            }
        }
        None => AccentInk::White,
    }
}

/// Resolve the accent quad `(accent_dark, accent_ink_dark, accent_light,
/// accent_ink_light)` for template emission across both color modes.
///
/// Falls back to allowthem's monochrome default when the integrator has no
/// branding or no accent set. The default inverts between modes so contrast
/// is AAA either way: white-on-black in dark mode, black-on-white in light
/// mode. When the integrator sets an accent, the same brand color is used
/// in both modes (with YIQ-derived ink) so theme toggles never clobber it.
/// The light-mode pair is computed symmetrically to the dark-mode pair so a
/// future `accent_hex_light` override can slot in without signature churn.
/// Also reads the legacy `primary_color` field so existing tenants keep
/// working until they migrate to `accent_hex`.
pub fn resolve_accent(
    branding: Option<&BrandingConfig>,
) -> (String, &'static str, String, &'static str) {
    let branded = branding.and_then(|b| b.accent_hex.as_deref().or(b.primary_color.as_deref()));
    match branded {
        Some(hex) => {
            let accent = hex.to_string();
            let ink = branding
                .and_then(|b| b.accent_ink)
                .unwrap_or_else(|| derive_ink(&accent));
            let accent_light = accent.clone();
            let ink_light = branding
                .and_then(|b| b.accent_ink)
                .unwrap_or_else(|| derive_ink(&accent_light));
            (accent, ink.as_hex(), accent_light, ink_light.as_hex())
        }
        None => (
            DEFAULT_ACCENT_HEX.to_string(),
            "#000000",
            "#000000".to_string(),
            "#ffffff",
        ),
    }
}

/// Look up branding for an application by client_id.
///
/// Returns `None` for missing or inactive applications.
/// Logs a warning on unexpected DB errors and falls back to `None`.
pub async fn lookup_branding(
    ath: &AllowThem,
    client_id: Option<&ClientId>,
) -> Option<BrandingConfig> {
    let cid = client_id?;
    match ath.db().get_branding_by_client_id(cid).await {
        Ok(branding) => branding,
        Err(e) => {
            tracing::warn!(client_id = %cid, error = %e, "branding lookup failed");
            None
        }
    }
}

/// Embedder-provided fallback branding, attached to the router via
/// `Extension<Arc<DefaultBranding>>` when the embedder calls
/// `AllRoutesBuilder::default_branding`.
///
/// Wrapping the `BrandingConfig` in a newtype keeps it disjoint from any
/// handler that takes `Extension<BrandingConfig>` directly.
#[derive(Debug, Clone)]
pub struct DefaultBranding(pub BrandingConfig);

/// Resolve branding for a handler: per-client row if the lookup matches,
/// else the embedder-supplied default, else `None`.
pub async fn resolve_branding(
    ath: &AllowThem,
    client_id: Option<&ClientId>,
    default: Option<&BrandingConfig>,
) -> Option<BrandingConfig> {
    if let Some(b) = lookup_branding(ath, client_id).await {
        return Some(b);
    }
    default.cloned()
}

/// Projection of `BrandingConfig` into the flat context keys every pre-auth
/// template reads directly (not via `branding.*` dotted access): `app_name`,
/// `logo_url`, and the accent quad.
///
/// Handlers also emit `branding => branding` as a separate context key so
/// templates keep their existing dotted access to `splash_*`, `forced_mode`,
/// and `font_*` fields.
pub struct BrandingCtx<'a> {
    pub app_name: &'a str,
    pub accent: String,
    pub accent_ink: &'static str,
    pub accent_light: String,
    pub accent_ink_light: &'static str,
    pub logo_url: Option<&'a str>,
}

impl<'a> BrandingCtx<'a> {
    pub fn from_branding(branding: Option<&'a BrandingConfig>) -> Self {
        let (accent, accent_ink, accent_light, accent_ink_light) = resolve_accent(branding);
        Self {
            app_name: branding
                .map(|b| b.application_name.as_str())
                .unwrap_or("allowthem"),
            accent,
            accent_ink,
            accent_light,
            accent_ink_light,
            logo_url: branding.and_then(|b| b.logo_url.as_deref()),
        }
    }
}

/// Flatten the embedder default-branding extension into the plain reference
/// form handlers need to feed into `resolve_branding`.
///
/// Handlers declare the extractor as
/// `Option<Extension<Arc<DefaultBranding>>>`; they all then need the inner
/// `&BrandingConfig`. This helper removes the per-site `as_ref().map(|Extension(d)| &d.0)`
/// boilerplate.
pub fn default_branding_ref(
    ext: &Option<Extension<Arc<DefaultBranding>>>,
) -> Option<&BrandingConfig> {
    ext.as_ref().map(|Extension(d)| &d.0)
}

/// Project branding into the flat template keys every pre-auth page reads:
/// `branding` (raw, for dotted access to `splash_*`/`forced_mode`/`font_*`),
/// `app_name`, `logo_url`, and the accent quad.
///
/// Use with minijinja's spread syntax to compose with page-specific keys:
/// `context! { ..branding_context(b), csrf_token, next, ... }`.
pub fn branding_context(branding: Option<&BrandingConfig>) -> minijinja::Value {
    let ctx = BrandingCtx::from_branding(branding);
    minijinja::context! {
        branding,
        app_name => ctx.app_name,
        logo_url => ctx.logo_url,
        accent => ctx.accent,
        accent_ink => ctx.accent_ink,
        accent_light => ctx.accent_light,
        accent_ink_light => ctx.accent_ink_light,
    }
}

fn parse_hex(hex: &str) -> Option<(u8, u8, u8)> {
    let bytes = hex.as_bytes();
    if bytes.len() != 7 || bytes[0] != b'#' {
        return None;
    }
    let r = u8::from_str_radix(&hex[1..3], 16).ok()?;
    let g = u8::from_str_radix(&hex[3..5], 16).ok()?;
    let b = u8::from_str_radix(&hex[5..7], 16).ok()?;
    Some((r, g, b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::applications::BrandingConfig;
    use allowthem_core::types::AccentInk;
    use allowthem_core::{AllowThem, AllowThemBuilder};

    async fn test_ath() -> AllowThem {
        AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .csrf_key(*b"test-csrf-key-for-binary-tests!!")
            .build()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn resolve_branding_returns_default_when_client_id_is_none() {
        let ath = test_ath().await;
        let default = BrandingConfig::new("Fallback Co");
        let result = resolve_branding(&ath, None, Some(&default)).await;
        assert_eq!(
            result.as_ref().map(|b| b.application_name.as_str()),
            Some("Fallback Co")
        );
    }

    #[tokio::test]
    async fn resolve_branding_returns_none_when_no_client_and_no_default() {
        let ath = test_ath().await;
        let result = resolve_branding(&ath, None, None).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn resolve_branding_returns_default_when_client_id_does_not_match() {
        let ath = test_ath().await;
        let default = BrandingConfig::new("Fallback Co");
        let unknown: allowthem_core::types::ClientId =
            serde_json::from_str("\"ath_does_not_exist\"").unwrap();
        let result = resolve_branding(&ath, Some(&unknown), Some(&default)).await;
        assert_eq!(
            result.as_ref().map(|b| b.application_name.as_str()),
            Some("Fallback Co")
        );
    }

    #[test]
    fn derive_ink_pastels_pair_with_black() {
        // Pastel violet, pastel peach, pastel mint — all light enough for black.
        assert_eq!(derive_ink("#cba6f7"), AccentInk::Black);
        assert_eq!(derive_ink("#fab387"), AccentInk::Black);
        assert_eq!(derive_ink("#a6e3a1"), AccentInk::Black);
    }

    #[test]
    fn derive_ink_saturated_darks_pair_with_white() {
        // Deep purple, indigo, near-black — need white ink.
        assert_eq!(derive_ink("#5b21b6"), AccentInk::White);
        assert_eq!(derive_ink("#1e1b4b"), AccentInk::White);
        assert_eq!(derive_ink("#000000"), AccentInk::White);
    }

    #[test]
    fn derive_ink_pure_white_pairs_with_black() {
        assert_eq!(derive_ink("#ffffff"), AccentInk::Black);
    }

    #[test]
    fn derive_ink_invalid_hex_defaults_to_white() {
        // YIQ of an unknown color shouldn't panic; default to White ink
        // (accent interpreted as near-black).
        assert_eq!(derive_ink("not-a-color"), AccentInk::White);
        assert_eq!(derive_ink("#zz"), AccentInk::White);
    }

    #[test]
    fn resolve_accent_defaults_without_branding() {
        let (accent, ink, accent_light, ink_light) = resolve_accent(None);
        assert_eq!(accent, "#ffffff");
        assert_eq!(ink, "#000000");
        assert_eq!(accent_light, "#000000");
        assert_eq!(ink_light, "#ffffff");
    }

    #[test]
    fn resolve_accent_branded_quad_pins_color_in_both_modes() {
        let b = BrandingConfig {
            application_name: "test".into(),
            logo_url: None,
            primary_color: None,
            accent_hex: Some("#ff6600".into()),
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        };
        let (accent, ink, accent_light, ink_light) = resolve_accent(Some(&b));
        // Same brand color in both modes — theme toggles must not clobber it.
        assert_eq!(accent, "#ff6600");
        assert_eq!(accent_light, "#ff6600");
        // YIQ-derived ink is stable across the symmetric call sites.
        assert_eq!(ink, ink_light);
    }

    #[test]
    fn resolve_accent_uses_accent_hex_over_primary_color() {
        let b = BrandingConfig {
            application_name: "test".into(),
            logo_url: None,
            primary_color: Some("#ff0000".into()),
            accent_hex: Some("#00ff00".into()),
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        };
        let (accent, _ink, _accent_light, _ink_light) = resolve_accent(Some(&b));
        assert_eq!(accent, "#00ff00");
    }

    #[test]
    fn resolve_accent_falls_back_to_primary_color() {
        let b = BrandingConfig {
            application_name: "test".into(),
            logo_url: None,
            primary_color: Some("#ff0000".into()),
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        };
        let (accent, _ink, _accent_light, _ink_light) = resolve_accent(Some(&b));
        assert_eq!(accent, "#ff0000");
    }

    #[test]
    fn resolve_accent_honors_explicit_ink() {
        let b = BrandingConfig {
            application_name: "test".into(),
            logo_url: None,
            primary_color: None,
            accent_hex: Some("#ffffff".into()), // would derive Black ink
            accent_ink: Some(AccentInk::White), // but explicitly White
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        };
        let (_accent, ink, _accent_light, _ink_light) = resolve_accent(Some(&b));
        assert_eq!(ink, "#ffffff");
    }

    #[test]
    fn branding_ctx_none_gives_allowthem_defaults() {
        let ctx = BrandingCtx::from_branding(None);
        assert_eq!(ctx.app_name, "allowthem");
        assert_eq!(ctx.accent, "#ffffff");
        assert_eq!(ctx.accent_ink, "#000000");
        assert_eq!(ctx.accent_light, "#000000");
        assert_eq!(ctx.accent_ink_light, "#ffffff");
        assert!(ctx.logo_url.is_none());
    }

    #[test]
    fn branding_ctx_some_projects_fields() {
        let b = BrandingConfig::new("Fixture Co")
            .with_accent("#ff00aa", AccentInk::Black)
            .with_logo_url("https://cdn.example/logo.svg");
        let ctx = BrandingCtx::from_branding(Some(&b));
        assert_eq!(ctx.app_name, "Fixture Co");
        assert_eq!(ctx.accent, "#ff00aa");
        assert_eq!(ctx.accent_ink, "#000000"); // YIQ pastel → black ink
        assert_eq!(ctx.logo_url, Some("https://cdn.example/logo.svg"));
    }

    #[test]
    fn default_branding_ref_none_passes_through() {
        let ext: Option<Extension<Arc<DefaultBranding>>> = None;
        assert!(default_branding_ref(&ext).is_none());
    }

    #[test]
    fn default_branding_ref_some_unwraps_to_inner_branding() {
        let branding = BrandingConfig::new("Acme");
        let ext = Some(Extension(Arc::new(DefaultBranding(branding))));
        let got = default_branding_ref(&ext).expect("should unwrap");
        assert_eq!(got.application_name, "Acme");
    }

    #[test]
    fn branding_context_none_emits_allowthem_defaults() {
        let v = branding_context(None);
        assert_eq!(v.get_attr("app_name").unwrap().as_str(), Some("allowthem"));
        assert_eq!(v.get_attr("accent").unwrap().as_str(), Some("#ffffff"));
        assert_eq!(v.get_attr("accent_ink").unwrap().as_str(), Some("#000000"));
        assert_eq!(
            v.get_attr("accent_light").unwrap().as_str(),
            Some("#000000")
        );
        assert_eq!(
            v.get_attr("accent_ink_light").unwrap().as_str(),
            Some("#ffffff")
        );
        assert!(v.get_attr("logo_url").unwrap().is_none());
        // `branding` key must still be present (raw, for dotted access).
        assert!(v.get_attr("branding").is_ok());
    }

    #[test]
    fn branding_context_some_projects_all_keys() {
        let b = BrandingConfig::new("Fixture Co")
            .with_accent("#ff00aa", AccentInk::Black)
            .with_logo_url("https://cdn.example/logo.svg");
        let v = branding_context(Some(&b));
        assert_eq!(v.get_attr("app_name").unwrap().as_str(), Some("Fixture Co"));
        assert_eq!(v.get_attr("accent").unwrap().as_str(), Some("#ff00aa"));
        assert_eq!(v.get_attr("accent_ink").unwrap().as_str(), Some("#000000"));
        assert_eq!(
            v.get_attr("logo_url").unwrap().as_str(),
            Some("https://cdn.example/logo.svg")
        );
        // `branding` serializes the raw struct — dotted access should work.
        let inner = v.get_attr("branding").unwrap();
        assert_eq!(
            inner.get_attr("application_name").unwrap().as_str(),
            Some("Fixture Co")
        );
    }
}
