# allowthem — Design Spec

## Purpose

A unified authentication system for all wavefunk projects. Eliminates duplicate auth implementations across speakwith, immersiq, and substrukt by providing a single, well-tested auth library. In standalone mode, serves as a self-hosted auth0 alternative — an OIDC provider that external applications can integrate with for authentication.

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

Wavefunk projects (speakwith, immersiq, substrukt) use embedded mode. External apps use standalone mode via OIDC.

## Key Design Decisions

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

### Phase 1: Data Foundation
1. Core types and database schema
2. Db handle and migration runner
3. Password hashing module
4. User CRUD

### Phase 2: Sessions
5. Session token generation and storage
6. Session lifecycle and cookie helpers

### Phase 3: Roles and Permissions
7. Roles — CRUD and user assignment
8. Permissions — CRUD and role/user assignment

### Phase 4: Embeddable Library API
9. Builder and AllowThem handle

### Phase 5: Axum Integration
10. AuthUser extractor
11. CSRF middleware
12. Auth-required middleware

### Phase 6: Standalone Server
13. Server bootstrap
14. Template engine and CSS switching
15. Registration route and form
16. Login route and form
17. Logout route

### Phase 7: Audit
18. Audit logging

### Phase 8: API Tokens
19. JWT token generation and validation
20. API token management and bearer extractor

### Phase 9: Password Reset
21. Email sending abstraction
22. Password reset — backend
23. Password reset — routes and forms

### Phase 10: OAuth
24. OAuth2 core and provider trait
25. Google OAuth provider
26. GitHub OAuth provider
27. OAuth account linking

### Phase 11: MFA
28. TOTP core
29. MFA setup flow
30. MFA login challenge
31. MFA recovery codes

### Phase 6b: User Self-Service (depends on Phase 6, not Phase 12)
32. User settings page and change password

### Phase 12: Integration (Embedded — can proceed in parallel with Phases 13+)
33. First integration — migrate one project

### Phase 13: Application Registry
34. Application model and OIDC database tables
35. Application CRUD in core
36. Application management admin UI

### Phase 14: OIDC Provider
37. RS256 key management, JWKS endpoint, and OIDC discovery
38. Authorization endpoint
39. Consent screen
40. Token endpoint — authorization code grant
41. Token endpoint — refresh token grant
42. UserInfo endpoint

### Phase 15: Admin Dashboard
43. User directory
44. Session viewer
45. Audit log viewer

### Phase 16: Hosted Login Branding
46. Per-application branding config
47. Branded auth pages

### Phase 17: Playwright Testing
48. Playwright test infrastructure
49. AI-verify + codify auth flows (register, login, logout)
50. AI-verify + codify password reset flow
51. AI-verify + codify OAuth login flows
52. AI-verify + codify MFA flows
53. AI-verify + codify admin dashboard flows
54. AI-verify + codify OIDC provider flows

## Derived From

Auth patterns extracted from:
- **speakwith** — Rust/Axum, session + JWT, Argon2, role-based (admin/user), room-scoped permissions, audit logging
- **immersiq** — Rust/Axum, multi-tier session auth, CSRF, 14 permission modules, audit logging
- **substrukt** — Rust/Axum, session + API tokens, invitation system, role hierarchy (admin/editor/viewer)
