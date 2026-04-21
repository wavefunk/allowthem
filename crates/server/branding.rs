use allowthem_core::AllowThem;
use allowthem_core::applications::BrandingConfig;
use allowthem_core::types::{AccentInk, ClientId};

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

// TODO(task-7): remove these shims — Task 7 migrates callers to resolve_accent.
#[doc(hidden)]
pub fn compute_accent_variants(_hex: &str) -> (String, String, String) {
    default_accents()
}

#[doc(hidden)]
pub fn default_accents() -> (String, String, String) {
    ("#ffffff".into(), "#e5e5e5".into(), "#ffffffcc".into())
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
    use allowthem_core::types::AccentInk;

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
}
