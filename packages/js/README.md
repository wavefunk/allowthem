# @allowthem/js

Browser SDK for allowthem auth — OIDC authorization-code flow with PKCE,
suitable for single-page applications.

## Install

```sh
npm install @allowthem/js
```

(Publish workflow ships with Epic h6d.4. The package is built from
`packages/js/` in the [allowthem](https://github.com/wavefunk/allowthem)
repo.)

## Quickstart — browser

```ts
import { createAllowthemClient } from "@allowthem/js";

const auth = createAllowthemClient({
  domain: "your-tenant.allowthem.io",
  clientId: "ath_xxx",
  redirectUri: window.location.origin + "/callback",
});

// Kick off login from any page:
await auth.loginWithRedirect();

// On the callback page:
const { appState } = await auth.handleRedirectCallback();

// Anywhere protected:
const accessToken = await auth.getAccessToken();
const user = await auth.getUser();
```

## Quickstart — server

The server entry verifies access tokens from a `Bearer` header without
calling out to the IdP — JWKS keys are fetched once and cached, then
RS256 signatures are checked locally. Express middleware ships in the
package; Fastify / Hono / Next.js Route Handlers consume `verify()`
directly.

```ts
import { createAllowthemVerifier } from "@allowthem/js/server";

const verifier = createAllowthemVerifier({
  domain: "your-tenant.allowthem.io",
  audience: "ath_xxx", // your client_id
});

// Express:
app.use("/api", verifier.middleware());

// Or directly:
const user = await verifier.verify(authorizationHeader);
```

## Configuration reference

### `ClientConfig` (browser)

| Field                    | Type                              | Default                                     | Description                                                       |
| ------------------------ | --------------------------------- | ------------------------------------------- | ----------------------------------------------------------------- |
| `domain`                 | `string`                          | required                                    | Tenant host, no scheme. e.g. `"acme.allowthem.io"`.               |
| `clientId`               | `string`                          | required                                    | OIDC client_id of the registered application.                     |
| `redirectUri`            | `string`                          | required                                    | Default redirect URI (must match the application's registered URIs). |
| `scope`                  | `string`                          | `"openid profile email offline_access"`    | OIDC scope string. `offline_access` requests a refresh token.     |
| `audience`               | `string`                          | unset                                       | Forwarded as `audience` to authorize. No-op against current allowthem. |
| `storage`                | `"memory" \| "session" \| TokenStore` | `"memory"`                              | In-memory by default. `"session"` persists access+id tokens (refresh stays in memory). Custom adapter for IndexedDB / BFF. |
| `expirySkewSeconds`      | `number`                          | `60`                                        | Refresh window before `expiresAt`.                                |
| `proactiveRefresh`       | `boolean`                         | `false`                                     | Schedule a background refresh `expirySkewSeconds` before expiry.  |
| `onTokenExpired`         | `(err) => void \| Promise<void>` | unset                                       | Hook fired when refresh fails. SDK still clears local state regardless. |

### `VerifierConfig` (server)

| Field                              | Type            | Default | Description                                                       |
| ---------------------------------- | --------------- | ------- | ----------------------------------------------------------------- |
| `domain`                           | `string`        | required | Tenant host, no scheme.                                          |
| `audience`                         | `string`        | required | Required. Must match the access token's `aud` claim.             |
| `jwksCacheTtlSeconds`              | `number`        | `3600`  | TTL before the JWKS cache is considered stale.                   |
| `jwksMinRefreshIntervalSeconds`    | `number`        | `60`    | Anti-DoS rate limit on cache-miss refreshes.                     |
| `clockSkewSeconds`                 | `number`        | `60`    | Tolerance for `exp` / `nbf`.                                     |
| `fetch`                            | `typeof fetch`  | `globalThis.fetch` | Override for non-Node runtimes (Workers, etc.).        |

## Browser support

- Chrome 64+
- Firefox 60+
- Safari 11.1+
- Edge 79+

These are the floors required for `crypto.subtle.digest("SHA-256", …)`,
which the PKCE S256 challenge depends on. Web Crypto is available
**only in secure contexts** — your app must be served over HTTPS in
production. `localhost` is treated as secure by browsers, so local
development works without TLS.

## Tokens & storage

By default tokens live in process memory and are lost when the tab
closes. Pass `storage: "session"` to persist `accessToken` + `idToken`
in `sessionStorage` (refresh token always stays in memory regardless,
to keep it off any web-storage surface that survives a reload).

For cross-tab persistence with hardened storage, use the
**Backend-for-Frontend (BFF)** pattern: a same-origin server endpoint
holds the tokens behind an `HttpOnly` cookie and returns just the
access token to the browser when needed. This SDK is BFF-friendly
because it doesn't require persisting refresh tokens in the browser at
all — the BFF handles refresh and only hands the SPA access tokens.

`localStorage` is intentionally **not** offered. A successful XSS into
a long-lived store leaks credentials to every future visit; we keep
the blast radius to the current tab.

## Refreshing tokens

`getAccessToken()` is the only refresh path: it returns the cached
access token if it's still valid (with a 60-second skew), or refreshes
via the refresh token if it's stale. Concurrent calls during a refresh
share one in-flight `POST /oauth/token` (single-flight inside one
tab). Cross-tab coalescing — making a 5-tab dashboard share one
refresh — is added by Epic h6d.2.

If the refresh fails (typically because the refresh token rotated out
from another tab), `getAccessToken()` throws `AuthError("login_required")`
and the app must call `loginWithRedirect()` again.

## Errors

Every public method throws `AuthError`:

```ts
import { AuthError } from "@allowthem/js";

try {
  await auth.handleRedirectCallback();
} catch (err) {
  if (err instanceof AuthError) {
    if (err.code === "invalid_state") { /* state mismatch */ }
    if (err.code === "login_required") { /* prompt re-login */ }
    if (err.code === "invalid_id_token") { /* server config issue */ }
  }
}
```

Common codes: `login_required`, `invalid_state`, `invalid_response`,
`invalid_id_token`, `config_error`. OIDC standard server-side codes
(e.g. `invalid_grant`, `access_denied`) pass through unchanged.

## Security notes

- **Local-only logout.** `logout()` clears the SDK's local state and
  optionally navigates to `returnTo`. It does **not** call any
  server-side end-session endpoint — allowthem doesn't expose one yet.
  Federated logout will land when the server endpoint does.
- **id_token signature is not verified by the SDK.** We trust the bytes
  received over the authenticated TLS channel from the token endpoint;
  the claim checks (issuer, audience, expiry, nonce) guard against
  misconfiguration, not forgery. Server-side relying parties should
  use `@allowthem/js/server` (Epic h6d.3) for full JWS verification.
- **Cache-Control on the callback page.** Set
  `Cache-Control: no-store, Pragma: no-cache` on your `/callback`
  page so the URL with `code` and `state` doesn't get cached.

## TypeScript

Types are bundled in the package; no extra setup. `ClientConfig`,
`LoginOptions`, `LogoutOptions`, `UserClaims`, `TokenResponse`, and
`AllowthemClient` are exported from the package root.

## Status

Pre-1.0. The public API is stable for the PKCE flow; expect additive
changes from h6d.2 (cross-tab refresh, lifecycle events, custom
storage adapters) and h6d.3 (server-side verifier) as those epics
land.

## Spec & development

Design spec lives in the parent repo at
`docs/superpowers/specs/2026-05-01-h6d1-browser-sdk-pkce-design.md`.
Run `npm test` from `packages/js/` for the test suite.
