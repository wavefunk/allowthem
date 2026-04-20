# allowthem — Design Spec

## Purpose

A unified authentication system for all wavefunk projects. Eliminates duplicate auth implementations across speakwith, immersiq, substrukt, is-still-online, transfer-these-files, and sendword by providing a single, well-tested auth library. In standalone mode, serves as a self-hosted auth0 alternative — an OIDC provider that external applications can integrate with for authentication.

## Dual-Mode Architecture

### Embedded Mode (Library)
The integrator adds `allowthem-core` as a Cargo dependency, passes their own `SqlitePool`, and allowthem runs migrations on their database. Tables are prefixed with `allowthem_` to avoid name collisions. The integrator's app tables can foreign-key into `allowthem_users.id` directly.

**API surface:** `AllowThemBuilder::new(pool).table_prefix("allowthem_").build()` returns an `AllowThem` handle exposing `register()`, `login()`, `logout()`, `validate_session()`, `check_role()`, `check_permission()`.

**Axum integration:** `allowthem-server` crate provides reusable extractors (`AuthUser`, `OptionalAuthUser`) and middleware (CSRF, auth-required) for Axum apps.

### Standalone Mode (Service)
A self-contained binary with its own database, server-rendered UI (MiniJinja + HTMX), and REST/OIDC API. Functions as a self-hosted auth0 alternative:

- **OIDC Provider** — implements OpenID Connect. External apps redirect to allowthem for login, receive authorization codes, exchange for access/ID tokens. Standard endpoints: `/oauth/authorize`, `/oauth/token`, `/oauth/userinfo`, `/.well-known/openid-configuration`, `/.well-known/jwks.json`.
- **Application Registry** — external apps register as clients with client_id/client_secret and allowed redirect URIs.
- **Admin Dashboard** — user directory, session management, audit log viewer, application management.
- **Hosted Login Pages** — per-application branding (logo, colors, app name) applied to login/register/MFA pages when accessed via the OIDC flow.
- **User Self-Service** — profile, change password, manage linked OAuth accounts, MFA settings.

Wavefunk projects (speakwith, immersiq, substrukt, is-still-online, transfer-these-files, sendword) use embedded mode. If scaling requires it, a project can switch to external mode by flipping a configuration flag — no code changes needed in the consuming project (see Client Trait below). External apps use standalone mode via OIDC.

## Key Design Decisions

### Client Trait (Mode Abstraction)
Consuming projects code against an `AuthClient` trait, not the `AllowThem` handle directly. This allows flipping between embedded and external mode without changing application code.

**Trait surface:**
- `validate_session(token) -> AuthUser` — embedded: DB lookup; external: JWT validation via JWKS
- `check_role(user_id, role) -> bool` — embedded: DB query; external: JWT claims
- `check_permission(user_id, perm) -> bool` — embedded: DB query; external: JWT claims
- `logout(token)` — embedded: delete session; external: revoke token via API
- `login_url() -> &str` — embedded: returns local path (e.g., `"/login"`); external: returns allowthem authorize URL with client_id and redirect_uri

**Login is mode-aware, not trait-abstracted.** In embedded mode, the consuming project renders its own login form and calls `AllowThem.login(email, password)` directly. In external mode, the consuming project redirects to `auth.login_url()` and handles the OIDC callback. This is intentional — the external mode never sees passwords; only allowthem's hosted login page handles credentials.

**Crate placement:** Trait definition and embedded impl live in `allowthem-core`. External impl will live in a future `allowthem-client` crate, built when standalone mode is ready.

**Configuration:** In external mode, the consuming project provides the allowthem base URL at startup via the builder (e.g., `AllowThemBuilder::new().external("https://auth.wavefunk.io").build()`). The builder returns the appropriate `AuthClient` impl based on whether a pool (embedded) or URL (external) is provided.

### Identity
- **Email required** as the canonical identity (needed for password reset, OAuth, MFA)
- **Username optional** as a display/login alias
- Login accepts either email or username

### Roles and Permissions
- **Generic system** — allowthem stores roles and permissions but does not enforce meaning
- Integrator defines their own role names and permission scopes
- API: `has_role(user_id, role_name)`, `has_permission(user_id, permission_name)`
- Permissions can be assigned to roles or directly to users
- No built-in hierarchy — the integrating app decides what roles mean

### Database
- **Embedded mode:** same database as the integrator, `allowthem_`-prefixed tables
- **Standalone mode:** own SQLite database, no prefix needed
- Table prefix is configurable via builder

### Frontend (Standalone Mode)
- MiniJinja + HTMX
- **Dev:** Tailwind Play CDN (`<script src="https://cdn.tailwindcss.com">`) — zero build step
- **Production:** Tailwind CLI standalone binary generates compiled CSS via `just build-css`
- Templates switch based on `is_production` flag

### Email (Dev Mode)
- `EmailSender` trait abstraction
- Dev default: `LogEmailSender` prints email content to stdout/logs with clickable URLs
- No SMTP setup needed during development
- Integrators provide their own `EmailSender` for production

## Auth Features

### Core
- Email + password registration and login
- Session-based authentication (SHA-256 hashed tokens, HttpOnly cookies)
- Argon2id password hashing
- Configurable session TTL with sliding-window renewal
- CSRF protection (double-submit cookie)
- Generic roles and permissions
- Audit logging (login, logout, registration, password changes)

### API Tokens (Embedded Mode)
- JWT generation and validation (HS256, symmetric secret provided by integrator)
- Persistent API tokens (hashed, stored in DB)
- Bearer token authentication
- Tokens inherit user's roles
- HS256 is for embedded use only (e.g., speakwith room-scoped tokens)

### Token Signing Strategy
- **Embedded mode (HS256):** integrator provides a symmetric secret for JWT signing. Simple, no key management needed on allowthem's side.
- **Standalone/OIDC mode (RS256):** allowthem generates and manages an RSA keypair. ID tokens and access tokens are signed with the private key. Public key is published via JWKS endpoint for token verification by relying parties. The JWT module supports both algorithms — the mode determines which is used.

### Password Reset
- Time-limited reset tokens
- Email-based reset flow
- Dev-mode log sender (no SMTP needed)

### OAuth
- Authorization code flow
- Generic provider trait
- Google and GitHub providers
- Account linking (OAuth identity → allowthem user)
- Auto-register on first OAuth login

### MFA
- TOTP-based 2FA (authenticator app compatible)
- QR code setup flow
- Login challenge (second factor after password)
- One-time recovery codes (10, stored hashed)

### Lifecycle Events
- Integrators can subscribe to auth lifecycle moments (register today; login,
  password change, delete on demand) via a user-supplied
  `tokio::sync::mpsc::UnboundedSender<AuthEvent>` passed to
  `AllRoutesBuilder::events(tx)`
- Fire-and-forget, at-most-once delivery — integrator code never sits in the
  request path
- `AuthEvent` is a `#[non_exhaustive]` enum so new variants never break
  subscribers. Current variants: `Registered` (password + OAuth first-sign-in)
- Integrator contract (summary): missed events are the integrator's problem,
  handlers should be idempotent per user, drainers doing heavy work should
  spawn per event rather than await inline. Full contract:
  `docs/superpowers/specs/2026-04-20-lifecycle-events-design.md`

### Standalone Service Features
- Application registry (client_id/secret, redirect URIs)
- OIDC provider (authorization code flow, RS256-signed tokens)
- Supported OIDC scopes: `openid` (required — returns `sub` claim), `profile` (returns `name`, `username`), `email` (returns `email`, `email_verified`). Custom scopes are not supported initially.
- Consent screen (approve/deny per-app, remembered in `consents` table). First-party apps (marked `trusted` in applications table) skip the consent screen.
- OAuth client login (Google/GitHub) is available on hosted login pages during OIDC authorize flow — users can choose password or social login.
- Admin dashboard (user directory, session viewer, audit log)
- Per-application branding (logo, color, app name on hosted login pages)
- User self-service (profile, change password)

### Testing
- Playwright-based UI/UX testing
- AI-first verification with playwright-cli (find bugs, verify UX)
- Codified playwright/test specs from verified flows (run without AI tokens)

## Tables

All prefixed with `allowthem_` in embedded mode:

- `users` — id, email, username, password_hash, is_active, created_at, updated_at
- `sessions` — id, token_hash, user_id, ip_address, user_agent, expires_at, created_at
- `roles` — id, name, description, created_at
- `user_roles` — user_id, role_id, created_at
- `permissions` — id, name, description, created_at
- `role_permissions` — role_id, permission_id
- `user_permissions` — user_id, permission_id
- `audit_events` — id, actor_id, action, resource_type, resource_id, context (JSON), status, ip_address, created_at
- `api_tokens` — id, user_id, name, token_hash, expires_at (nullable), created_at
- `password_reset_tokens` — id, user_id, token_hash, expires_at, used_at, created_at
- `oauth_accounts` — id, user_id, provider, provider_user_id, email, created_at
- `mfa_secrets` — id, user_id, secret (encrypted), enabled, created_at
- `mfa_recovery_codes` — id, user_id, code_hash, used_at, created_at
- `applications` — id, name, client_id (unique), client_secret_hash, redirect_uris (JSON array), logo_url, primary_color, is_trusted (bool, skip consent), created_by, is_active, created_at, updated_at
- `authorization_codes` — id, application_id, user_id, code_hash, redirect_uri, scopes (JSON), expires_at, used_at, created_at
- `refresh_tokens` — id, application_id, user_id, token_hash, scopes (JSON), expires_at, revoked_at, created_at
- `consents` — id, user_id, application_id, scopes (JSON), created_at, updated_at

## Milestones

Priority: embedded-first, early integration with sendword, standalone/OIDC later. First integration target: sendword (simplest auth surface — session-based, no roles, no OAuth/MFA).

### Block 1: Core (data + auth primitives)
1. Core types and database schema
2. DB handle and migration runner
3. Password hashing module
4. User CRUD
5. Session token generation and storage
6. Session lifecycle and cookie helpers
7. Roles — CRUD and user assignment
8. Permissions — CRUD and role/user assignment

### Block 2: Embeddable API + Axum Integration
9. Builder and AllowThem handle
10. AuthUser extractor
11. CSRF middleware
12. Auth-required middleware
13. Email sending abstraction (EmailSender trait + LogEmailSender for dev)
14. Password reset — backend (tokens, validation)
15. Password reset — reusable Axum route handlers (mountable by consuming projects in embedded mode)

### Block 3: Client Trait
16. AuthClient trait definition + embedded impl + login_url() helper

### Block 4: Sendword Integration
17. Migrate sendword to allowthem (first integration — validates embedded API)

### Block 5: Audit + API Tokens
18. Audit logging
19. JWT token generation and validation (HS256 for embedded)
20. API token management and bearer extractor

### Block 6: OAuth
21. OAuth2 core and provider trait
22. Google OAuth provider
23. GitHub OAuth provider
24. OAuth account linking

### Block 7: MFA
25. TOTP core
26. MFA setup flow
27. MFA login challenge
28. MFA recovery codes

### Block 8: Standalone Server
29. Server bootstrap
30. Template engine and CSS switching
31. Registration route and form
32. Login route and form
33. Logout route
34. User settings page and change password

### Block 9: Application Registry
35. Application model and OIDC database tables
36. Application CRUD in core
37. Application management admin UI

### Block 10: OIDC Provider
38. RS256 key management, JWKS endpoint, and OIDC discovery
39. Authorization endpoint
40. Consent screen
41. Token endpoint — authorization code grant
42. Token endpoint — refresh token grant
43. UserInfo endpoint

### Block 11: External Client
44. allowthem-client crate — AuthClient external impl (JWT validation via JWKS, HTTP calls for logout/revoke)

### Block 12: Admin Dashboard
45. User directory
46. Session viewer
47. Audit log viewer

### Block 13: Hosted Login Branding
48. Per-application branding config
49. Branded auth pages

### Block 14: Playwright Testing
50. Playwright test infrastructure
51. AI-verify + codify auth flows (register, login, logout)
52. AI-verify + codify password reset flow
53. AI-verify + codify OAuth login flows
54. AI-verify + codify MFA flows
55. AI-verify + codify admin dashboard flows
56. AI-verify + codify OIDC provider flows

## Derived From

Auth patterns extracted from:
- **speakwith** — Rust/Axum, session + JWT, Argon2, role-based (admin/user), room-scoped permissions, audit logging
- **immersiq** — Rust/Axum, multi-tier session auth, CSRF, 14 permission modules, audit logging
- **substrukt** — Rust/Axum, session + API tokens, invitation system, role hierarchy (admin/editor/viewer)
