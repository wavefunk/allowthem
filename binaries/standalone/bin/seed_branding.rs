//! Seeds a single branded application for Playwright cross-browser tests.
//! Invoked from tests/e2e/global-setup.ts. Not a production tool.
//! Prints the generated client_id on stdout (single line, no prefix).

use std::str::FromStr;

use allowthem_core::applications::CreateApplicationParams;
use allowthem_core::{AccentInk, ClientType, Db};
use clap::Parser;

#[derive(Parser)]
struct Args {
    /// SQLx database URL — MUST be byte-identical to the server's
    /// ALLOWTHEM_DATABASE_URL so both processes hit the same SQLite file.
    #[arg(long)]
    db_url: String,

    /// Application name (appears in the auth shell eyebrow).
    #[arg(long)]
    name: String,

    /// Accent fill, e.g. "#cba6f7".
    #[arg(long)]
    accent_hex: String,

    /// Accent ink — "black" or "white".
    #[arg(long)]
    ink: String,

    /// Redirect URI registered on the app. A single value is sufficient
    /// for the branding-visible pages the e2e spec exercises.
    #[arg(long)]
    redirect_uri: String,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Args::parse();
    let db = Db::connect(&args.db_url).await?;
    let ink = AccentInk::from_str(&args.ink)?;
    let (app, _secret) = db
        .create_application(CreateApplicationParams {
            name: args.name,
            client_type: ClientType::Public,
            redirect_uris: vec![args.redirect_uri],
            is_trusted: false,
            created_by: None,
            logo_url: None,
            primary_color: None,
            accent_hex: Some(args.accent_hex),
            accent_ink: Some(ink),
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        })
        .await?;
    println!("{}", app.client_id);
    Ok(())
}
