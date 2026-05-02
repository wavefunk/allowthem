/**
 * Server-entry token verifier for `@allowthem/js`.
 *
 * Verifies allowthem-issued RS256 JWT access tokens (`typ: at+jwt`,
 * RFC 9068) against a JWKS endpoint, with single-flight caching + a
 * narrowed refresh-and-retry path for legitimate key rotation.
 */
import {
  decodeProtectedHeader,
  errors as joseErrors,
  jwtVerify,
  type JWTPayload,
} from "jose";
import { AuthError } from "./errors.js";
import { JwksCache } from "./jwks.js";

/**
 * Construction-time configuration. See spec §2.
 */
export interface VerifierConfig {
  /** Tenant host, no scheme, no trailing slash. e.g. `"acme.allowthem.io"`. */
  domain: string;
  /** Required. Audience the token must list (or equal). */
  audience: string;
  /** JWKS cache TTL in seconds. Default: 3600. */
  jwksCacheTtlSeconds?: number;
  /** Min seconds between forced JWKS refreshes (anti-DoS). Default: 60. */
  jwksMinRefreshIntervalSeconds?: number;
  /** Clock skew tolerance for `exp`/`iat` in seconds. Default: 60. */
  clockSkewSeconds?: number;
  /** Optional fetch override for non-Node runtimes. */
  fetch?: typeof fetch;
}

/**
 * Verified user surface returned by {@link AllowthemVerifier.verify}.
 *
 * `raw` holds the unmodified verified payload — apps that need custom or
 * namespaced claims read from there. The typed top-level fields are
 * conveniences, not the contract.
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
 * Step 7 widens this interface to add `middleware(opts?): RequestHandler`
 * — added there so this file's typecheck doesn't depend on `middleware.ts`
 * or `@types/express` at Step 3/5 commit time.
 */
export interface AllowthemVerifier {
  verify(bearerToken: string): Promise<AllowthemUser>;
  requireRole(user: AllowthemUser, role: string): void;
  hasPermission(user: AllowthemUser, perm: string): boolean;
}

/** Defaults applied when a {@link VerifierConfig} field is omitted. */
export const DEFAULTS = {
  jwksCacheTtlSeconds: 3600,
  jwksMinRefreshIntervalSeconds: 60,
  clockSkewSeconds: 60,
} as const;

/**
 * Throw if `user` does not list `role`. Pure; same input always yields the
 * same result.
 *
 * @throws {AuthError} `forbidden` with description `"missing role: <role>"`.
 */
export function requireRole(user: AllowthemUser, role: string): void {
  if (!user.roles.includes(role)) {
    throw new AuthError("forbidden", `missing role: ${role}`);
  }
}

/** Return whether `user` lists `perm`. Pure. */
export function hasPermission(user: AllowthemUser, perm: string): boolean {
  return user.permissions.includes(perm);
}

/**
 * Build a server-side token verifier for the given tenant.
 *
 * @param config — see {@link VerifierConfig}.
 * @returns Configured verifier. Call `verify(bearer)` to validate a token.
 *
 * @throws {AuthError} `config_error` for invalid `domain` shape or missing
 *   `audience`.
 *
 * @example
 * ```ts
 * import { createAllowthemVerifier } from "@allowthem/js/server";
 *
 * const verifier = createAllowthemVerifier({
 *   domain: "acme.allowthem.io",
 *   audience: "ath_xxx",
 * });
 *
 * const user = await verifier.verify(req.headers.authorization);
 * verifier.requireRole(user, "admin");
 * ```
 */
export function createAllowthemVerifier(config: VerifierConfig): AllowthemVerifier {
  validateConfig(config);

  const issuer = `https://${config.domain}`;
  const jwksUri = `${issuer}/.well-known/jwks.json`;
  const fetchFn = config.fetch ?? fetch;
  const skewS = config.clockSkewSeconds ?? DEFAULTS.clockSkewSeconds;

  const jwks = new JwksCache({
    jwksUri,
    cacheTtlSeconds: config.jwksCacheTtlSeconds ?? DEFAULTS.jwksCacheTtlSeconds,
    minRefreshIntervalSeconds:
      config.jwksMinRefreshIntervalSeconds ?? DEFAULTS.jwksMinRefreshIntervalSeconds,
    fetch: fetchFn,
  });

  async function verify(bearerToken: string): Promise<AllowthemUser> {
    // Step 1: strip Bearer prefix (case-insensitive); reject empty.
    const trimmed = bearerToken.trim();
    const token = /^Bearer\s+/i.test(trimmed) ? trimmed.replace(/^Bearer\s+/i, "") : trimmed;
    if (token === "") throw new AuthError("invalid_token", "missing token");

    // Step 2: decode header — algorithm-confusion guard fires before any
    // key lookup or signature work. Defense-in-depth alongside the
    // `algorithms: ["RS256"]` option passed to `jose.jwtVerify` in step 4.
    let header: { kid?: string; alg?: string; typ?: string };
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new AuthError("invalid_token", "malformed JWT");
    }
    if (header.alg !== "RS256") {
      throw new AuthError("invalid_token", "unsupported algorithm");
    }
    const kid = header.kid;
    if (kid === undefined || kid === "") {
      throw new AuthError("invalid_token", "missing kid");
    }

    // Steps 3–5: jwtVerify with key from the JWKS cache, narrowed
    // refresh-and-retry on signature failure or unknown-kid.
    const verifyOnce = async (forceRefresh: boolean): Promise<JWTPayload> => {
      if (forceRefresh) await jwks.refresh();
      const key = await jwks.getKey(kid);
      if (key === null) throw new AuthError("invalid_token", "unknown kid");
      const { payload } = await jwtVerify(token, key, {
        issuer,
        audience: config.audience,
        algorithms: ["RS256"],
        typ: "at+jwt",
        clockTolerance: skewS,
      });
      return payload;
    };

    let payload: JWTPayload;
    try {
      payload = await verifyOnce(false);
    } catch (firstErr) {
      const isUnknownKid =
        firstErr instanceof AuthError && firstErr.description === "unknown kid";
      const isSignatureFailure =
        firstErr instanceof joseErrors.JWSSignatureVerificationFailed;

      if (!isUnknownKid && !isSignatureFailure) {
        // Claim/typ/exp/iss/aud failures aren't helped by a JWKS refresh —
        // refreshing on those would burn the rate-limit budget on every 401.
        if (firstErr instanceof AuthError) throw firstErr;
        throw new AuthError("invalid_token", asMessage(firstErr));
      }
      try {
        payload = await verifyOnce(true);
      } catch (secondErr) {
        if (secondErr instanceof AuthError) throw secondErr;
        throw new AuthError("invalid_token", asMessage(secondErr));
      }
    }

    // Step 6: manual iat-future check. `jose.jwtVerify`'s `clockTolerance`
    // covers `exp`/`nbf` only — `iat` is informational and not validated.
    const nowS = Math.floor(Date.now() / 1000);
    const iat = typeof payload.iat === "number" ? payload.iat : 0;
    if (iat > nowS + skewS) {
      throw new AuthError("invalid_token", "iat in the future");
    }

    // Step 7: claim mapping.
    return mapClaims(payload);
  }

  return {
    verify,
    requireRole,
    hasPermission,
  };
}

function validateConfig(config: VerifierConfig): void {
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
}

function mapClaims(payload: JWTPayload): AllowthemUser {
  const sub = typeof payload.sub === "string" ? payload.sub : "";
  if (sub === "") throw new AuthError("invalid_token", "sub claim required");

  const claims = payload as Record<string, unknown>;

  const email = typeof claims["email"] === "string" ? (claims["email"] as string) : "";
  if (email === "") throw new AuthError("invalid_token", "email claim required");

  const usernameRaw = claims["username"];
  const rolesRaw = claims["roles"];
  const permsRaw = claims["permissions"];

  // exactOptionalPropertyTypes: only include `username` when it's a real
  // string; otherwise omit the key entirely.
  const user: AllowthemUser = {
    sub,
    email,
    emailVerified: claims["email_verified"] === true,
    roles: Array.isArray(rolesRaw) ? rolesRaw.filter((r): r is string => typeof r === "string") : [],
    permissions: Array.isArray(permsRaw)
      ? permsRaw.filter((p): p is string => typeof p === "string")
      : [],
    raw: claims,
  };
  if (typeof usernameRaw === "string") {
    user.username = usernameRaw;
  }
  return user;
}

function asMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}
