-- Wave Funk branding fields on allowthem_applications.
-- Every column is nullable — integrators supply zero or more;
-- templates fall back to monochrome defaults when unset.
ALTER TABLE allowthem_applications ADD COLUMN accent_hex TEXT;
ALTER TABLE allowthem_applications ADD COLUMN accent_ink TEXT
    CHECK (accent_ink IS NULL OR accent_ink IN ('black', 'white'));
ALTER TABLE allowthem_applications ADD COLUMN forced_mode TEXT
    CHECK (forced_mode IS NULL OR forced_mode IN ('dark', 'light'));
ALTER TABLE allowthem_applications ADD COLUMN font_css_url TEXT;
ALTER TABLE allowthem_applications ADD COLUMN font_family TEXT;
ALTER TABLE allowthem_applications ADD COLUMN splash_text TEXT;
ALTER TABLE allowthem_applications ADD COLUMN splash_image_url TEXT;
ALTER TABLE allowthem_applications ADD COLUMN splash_primitive TEXT
    CHECK (splash_primitive IS NULL
           OR splash_primitive IN ('wordmark', 'circle', 'grid', 'wave'));
ALTER TABLE allowthem_applications ADD COLUMN splash_url TEXT;
ALTER TABLE allowthem_applications ADD COLUMN shader_cell_scale INTEGER
    CHECK (shader_cell_scale IS NULL
           OR (shader_cell_scale >= 8 AND shader_cell_scale <= 128));
