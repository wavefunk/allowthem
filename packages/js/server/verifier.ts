/**
 * Server-entry token verifier for `@allowthem/js`.
 *
 * Step 3 ships the public types, the constructor, and config-error validation.
 * The `verify()` body and JWKS-cache integration land in Step 5; the role
 * helpers ship there too because the verifier object's methods reference
 * them as named exports.
 */
import { AuthError } from "./errors.js";

/**
 * Construction-time configuration for the server SDK verifier.
 *
 * Mirrors the Rust client's `ExternalAuthClient` builder shape (see
 * `crates/client/client.rs`), with TypeScript-side enhancements (TTL,
 * configurable rate-limit, fetch override) called out per field.
 */
export interface VerifierConfig {
  /**
   * Tenant host, no scheme, no trailing slash. e.g. `"acme.allowthem.io"`.
   * Internally normalised to `issuer = "https://" + domain`.
   */
  domain: string;

  /**
   * Required. Audience the token must list (or equal). Typically the
   * `client_id` of the relying-party application.
   */
  audience: string;

  /**
   * JWKS cache TTL in seconds. Default: 3600 (1 hour).
   *
   * The Rust client at `crates/client/jwks.rs` does not have a TTL — it only
   * refreshes on cache miss for an unknown kid. The TS client adds a
   * time-based refresh window so long-running edge workers eventually pick
   * up rotated keys even if all in-flight tokens use the old kid set.
   */
  jwksCacheTtlSeconds?: number;

  /**
   * Minimum interval (seconds) between forced JWKS refreshes after a cache
   * miss. Default: 60. Prevents an attacker from spamming the JWKS endpoint
   * by sending tokens with bogus kids.
   */
  jwksMinRefreshIntervalSeconds?: number;

  /**
   * Optional clock skew tolerance for `exp`/`iat` in seconds. Default: 60.
   */
  clockSkewSeconds?: number;

  /**
   * Optional fetch override for non-Node runtimes (Cloudflare Workers, Deno,
   * Bun) where the global `fetch` may need to be a service-binding-bound
   * version. Defaults to global `fetch`.
   */
  fetch?: typeof fetch;
}

/**
 * The verified user surface returned by `verify()`. Standard claims are
 * mapped to typed top-level fields; `raw` holds the unmodified verified
 * payload so callers can read custom or namespaced claims.
 */
export interface AllowthemUser {
  sub: string;
  email: string;
  emailVerified: boolean;
  username?: string;
  roles: string[];
  permissions: string[];
  raw: Record<string, unknown>;
}

/**
 * Verifier instance returned by {@link createAllowthemVerifier}.
 *
 * The `middleware` method is added by the Step 7 commit (which also widens
 * this interface). Do **not** declare it here — referencing
 * `import("./middleware.js").MiddlewareOptions` or
 * `import("express").RequestHandler` from this file before Step 7 lands
 * breaks per-commit typecheck (the module doesn't exist yet and
 * `@types/express` isn't installed until Step 7).
 */
export interface AllowthemVerifier {
  verify(bearerToken: string): Promise<AllowthemUser>;
  requireRole(user: AllowthemUser, role: string): void;
  hasPermission(user: AllowthemUser, perm: string): boolean;
}

/**
 * Defaults applied when a {@link VerifierConfig} field is omitted. Exported
 * for tests; do not mutate.
 */
export const DEFAULTS = {
  jwksCacheTtlSeconds: 3600,
  jwksMinRefreshIntervalSeconds: 60,
  clockSkewSeconds: 60,
} as const;

/**
 * Build a server-side token verifier for the given tenant.
 *
 * @param config — see {@link VerifierConfig}.
 * @returns A configured verifier; call `verify(bearer)` to validate an
 *   access token.
 *
 * @throws {AuthError} `config_error` if `domain` is missing, includes a
 *   scheme, or has a trailing slash; or if `audience` is missing.
 */
export function createAllowthemVerifier(config: VerifierConfig): AllowthemVerifier {
  if (!config.domain) {
    throw new AuthError("config_error", "domain is required");
  }
  if (/^https?:\/\//i.test(config.domain)) {
    throw new AuthError("config_error", "domain must not include a scheme");
  }
  if (config.domain.endsWith("/")) {
    throw new AuthError("config_error", "domain must not have a trailing slash");
  }
  if (config.domain.includes("/")) {
    throw new AuthError("config_error", "domain must not include a path");
  }
  if (!config.audience) {
    throw new AuthError("config_error", "audience is required");
  }
  // verify() body lands in Step 5.
  throw new Error("not yet implemented (Step 5)");
}
