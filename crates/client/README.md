# allowthem-client

Rust client crate for the [allowthem](https://github.com/wavefunk/allowthem)
external-mode auth flow — RS256 JWT verification via JWKS, OAuth 2.0
authorization-code exchange, and a thin `AuthClient` implementation
suitable for embedding inside other services.

## Install

```sh
cargo add allowthem-client
```

## Quickstart

```rust
use allowthem_client::ExternalAuthClientBuilder;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = ExternalAuthClientBuilder::new()
    .base_url("https://your-tenant.allowthem.io")
    .client_id("your_client_id")
    .client_secret("your_client_secret")
    .redirect_uri("https://your-app.example/callback")
    .build()?;

// Build the authorize URL to redirect the user to.
let authorize_url = client.authorize_url(/* state, scope, etc */)?;

// On callback, exchange the authorization code for tokens.
let tokens = client.exchange_code(/* code, code_verifier */).await?;
# Ok(()) }
```

## JWKS verification

Access tokens are RS256-signed; `allowthem-client` validates them
locally by fetching the tenant's JWKS endpoint at
`{base_url}/.well-known/jwks.json` once and caching the keys in process.
Lookups for unknown `kid`s trigger one bounded refresh (10-second
debounce) so a key rotation by the IdP recovers automatically without
server-wide 401s.

The cache lives for the lifetime of the `ExternalAuthClient`; rotation
between cache misses is the only refresh trigger. No proactive TTL —
the cost of a refresh is one HTTP round-trip and rotation is rare.

## Configuration reference

`ExternalAuthClientBuilder` exposes:

| Method                    | Required | Description                                      |
| ------------------------- | -------- | ------------------------------------------------ |
| `base_url(url)`           | yes      | Tenant base URL, e.g. `https://acme.allowthem.io`. |
| `client_id(id)`           | yes      | Registered OIDC client_id.                       |
| `client_secret(secret)`   | for confidential clients | Client secret. Public clients omit. |
| `redirect_uri(uri)`       | yes      | Callback URL registered with the application.    |
| `http_client(client)`     | no       | Custom `reqwest::Client` (TLS, proxy, headers).  |

## Error handling

All operations return `Result<_, AuthError>` where `AuthError` is the
core error enum from `allowthem_core`. Common variants:

- `AuthError::InvalidToken(reason)` — token failed signature, iss, aud,
  or exp validation. Returned by the verify path.
- `AuthError::OAuthHttp(detail)` — network / HTTP / JSON failure during
  token exchange or JWKS refresh. Treat as transient and retry.
- `AuthError::SigningKey(detail)` — JWKS contained no usable key for the
  token's `kid`. Usually transient (rotation in progress); retry once.

## Pointer to the JS SDK

For browsers and Node.js relying parties, see
[`@allowthem/js`](https://www.npmjs.com/package/@allowthem/js) — the
JavaScript / TypeScript SDK with browser PKCE flow and a server-side
JWKS verifier.

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE)
or [MIT License](../../LICENSE-MIT) at your option.
