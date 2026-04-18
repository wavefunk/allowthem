use allowthem_core::AllowThem;
use allowthem_core::applications::BrandingConfig;
use allowthem_core::types::ClientId;

/// Compute accent color variants from a primary hex color.
///
/// Returns `(accent, accent_hover, accent_ring)` as hex strings.
/// Falls back to default blue values if the hex string cannot be parsed.
pub fn compute_accent_variants(hex: &str) -> (String, String, String) {
    match parse_hex(hex) {
        Some((r, g, b)) => {
            let accent = format!("#{:02x}{:02x}{:02x}", r, g, b);
            let hover = darken(r, g, b, 0.15);
            let ring = lighten(r, g, b, 0.25);
            (accent, hover, ring)
        }
        None => default_accents(),
    }
}

pub fn default_accents() -> (String, String, String) {
    ("#2563eb".into(), "#1d4ed8".into(), "#3b82f6".into())
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

fn darken(r: u8, g: u8, b: u8, factor: f32) -> String {
    let scale = 1.0 - factor;
    format!(
        "#{:02x}{:02x}{:02x}",
        (r as f32 * scale) as u8,
        (g as f32 * scale) as u8,
        (b as f32 * scale) as u8,
    )
}

fn lighten(r: u8, g: u8, b: u8, factor: f32) -> String {
    format!(
        "#{:02x}{:02x}{:02x}",
        (r as f32 + (255.0 - r as f32) * factor) as u8,
        (g as f32 + (255.0 - g as f32) * factor) as u8,
        (b as f32 + (255.0 - b as f32) * factor) as u8,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_valid() {
        assert_eq!(compute_accent_variants("#2563eb").0, "#2563eb");
    }

    #[test]
    fn default_accents_are_blue() {
        let (accent, _, _) = default_accents();
        assert_eq!(accent, "#2563eb");
    }

    #[test]
    fn compute_variants_invalid_falls_back() {
        assert_eq!(compute_accent_variants("invalid"), default_accents());
    }
}
