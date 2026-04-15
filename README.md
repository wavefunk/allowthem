# allowthem

An embeddable authentication system for Rust applications. Use it as a library within your Axum app or run it as a standalone auth service with OIDC provider capabilities.

## Modes

**Embedded (library):** Add `allowthem-core` as a dependency, pass your `SqlitePool`, and allowthem manages auth tables in your database (prefixed with `allowthem_` to avoid collisions). Your app calls the API directly for registration, login, session management, and access control.

**Standalone (service):** A self-contained binary with its own database, server-rendered UI, and REST/OIDC endpoints. Functions as a self-hosted identity provider -- external applications authenticate via standard OpenID Connect flows.

Both modes expose the same `AuthClient` trait. Consuming projects code against this trait and can switch between embedded and standalone with a configuration change, no code modifications required.

## Features

- Email + password registration and login (Argon2id hashing)
- Session-based authentication with configurable TTL and sliding-window renewal
- CSRF protection (double-submit cookie pattern)
- Generic roles and permissions (integrator-defined, no enforced hierarchy)
- Audit logging
- JWT generation and validation (HS256 for embedded, RS256 for OIDC)
- Persistent API tokens with bearer authentication
- Password reset flow with time-limited tokens
- OAuth2 login (Google, GitHub) with account linking
- TOTP-based MFA with recovery codes

## Tech Stack

- **Web framework:** Axum
- **Database:** SQLite via SQLx
- **Async runtime:** Tokio
- **Rust toolchain:** nightly (pinned in `rust-toolchain.toml`)

## Project Structure

```
crates/
  core/       # Types, database, auth logic, migrations
  server/     # HTTP routes, middleware, extractors
binaries/     # Standalone server entry point
```

## Quick Start

### Prerequisites

[Nix](https://nixos.org/) with flakes enabled, or the Rust toolchain specified in `rust-toolchain.toml`.

### Build and Test

```sh
just build    # cargo build --workspace
just test     # cargo test --workspace
just check    # cargo check --workspace
just clippy   # cargo clippy --workspace -- -D warnings
```

### Embedded Usage

```rust
use allowthem_core::{AllowThemBuilder, AuthClient};

let auth = AllowThemBuilder::new()
    .with_pool(pool)
    .session_ttl(Duration::from_secs(86400))
    .cookie_name("session")
    .build()
    .await?;
```

The builder accepts configuration for session TTL, cookie name/domain/security, and MFA encryption keys. Once built, the `AllowThem` handle provides methods for user management, session lifecycle, roles, permissions, and token operations.

## License

MIT OR Apache-2.0
