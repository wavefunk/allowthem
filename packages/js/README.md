# @allowthem/js

Browser SDK for allowthem auth (OIDC + PKCE for SPAs).

Requires HTTPS in production (Web Crypto needs a secure context;
`localhost` is exempt). Final layout, build, and publishing are
defined by Epic h6d.4 — this directory ships the runtime + tests
for the v1 PKCE flow only.

See `docs/superpowers/specs/2026-05-01-h6d1-browser-sdk-pkce-design.md`.
