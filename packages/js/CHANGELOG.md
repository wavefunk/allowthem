# Changelog

All notable changes to `@allowthem/js` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.0.5] — 2026-05-XX

### Added

- Initial browser SDK (`@allowthem/js`) with the OIDC authorization-code
  + PKCE flow: `loginWithRedirect`, `handleRedirectCallback`,
  `getAccessToken`, `getUser`, `logout`.
- Cross-tab refresh coalescing via `navigator.locks` (primary) +
  `BroadcastChannel` (fallback).
- Lifecycle event emitter: `'login' | 'logout' | 'token_refreshed' | 'error'`.
- Optional proactive refresh timer (`proactiveRefresh: true`).
- Pluggable `TokenStore` adapter via `ClientConfig.storage`.
- Initial server SDK (`@allowthem/js/server`) with JWKS RS256
  verification: `createAllowthemVerifier`, `verify`, `requireRole`,
  `hasPermission`, Express middleware factory.
- Dual ESM + CJS distribution via `tsup`. Two entry points:
  `@allowthem/js` (browser) and `@allowthem/js/server` (Node/edge).

### Notes

- Pre-1.0 — public API may change. Breaking changes will bump the minor.
- Manual `npm publish` at v1; GitHub Actions release workflow + npm
  package provenance ship in a v2 follow-up.
