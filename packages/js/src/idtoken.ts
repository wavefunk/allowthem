/**
 * id_token claim parsing and verification.
 *
 * The SDK does **not** verify the JWS signature — that's the IdP's job
 * via TLS to the token endpoint. We trust the bytes we receive over the
 * authenticated TLS channel; the claim checks here guard against
 * accidental misconfiguration (wrong issuer, wrong audience), not
 * forgery.
 *
 * Server-side relying parties (Epic h6d.3) verify signatures via JWKS.
 */

import { AuthError } from "./errors.js";

/**
 * Standard OIDC id_token claims plus passthrough.
 */
export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat?: number;
  nonce?: string;
  /**
   * Authorized Party — REQUIRED by OIDC Core §3.1.3.7 step 4 when `aud` is
   * an array. When present, MUST equal `clientId` of this RP.
   */
  azp?: string;
  [k: string]: unknown;
}

/**
 * Inputs to {@link validateIdToken}.
 */
export interface ValidateOptions {
  issuer: string;
  clientId: string;
  /** If undefined, the nonce check is skipped (refresh path). */
  nonce?: string;
  /** Default 60 seconds. */
  skewSeconds?: number;
  /** Injectable for tests. Returns ms-since-epoch. */
  now?: () => number;
}

/**
 * Decode the claim segment of a JWT without verifying its signature.
 * Throws `AuthError("invalid_id_token", ...)` if the JWT is malformed.
 */
export function parseIdTokenClaims(idToken: string): IdTokenClaims {
  const parts = idToken.split(".");
  if (parts.length !== 3) {
    throw new AuthError("invalid_id_token", "id_token must have 3 segments");
  }
  return decodeJsonSegment(parts[1]!) as IdTokenClaims;
}

/**
 * Validate the standard claims on an id_token.
 *
 * - `iss` must match `opts.issuer` exactly.
 * - `aud` must equal `opts.clientId` or include it (string-or-array).
 * - `exp` must be in the future relative to `now - skew`.
 * - If `opts.nonce` is provided, `nonce` claim must match.
 *
 * Does **not** verify the JWS signature — see file-level note.
 */
export function validateIdToken(
  idToken: string,
  opts: ValidateOptions,
): IdTokenClaims {
  const claims = parseIdTokenClaims(idToken);
  const skew = opts.skewSeconds ?? 60;
  const now = Math.floor((opts.now ?? Date.now)() / 1000);

  if (claims.iss !== opts.issuer) {
    throw new AuthError("invalid_id_token", `iss mismatch: ${claims.iss}`);
  }

  const audOk = Array.isArray(claims.aud)
    ? claims.aud.includes(opts.clientId)
    : claims.aud === opts.clientId;
  if (!audOk) {
    throw new AuthError("invalid_id_token", "aud mismatch");
  }

  // OIDC Core §3.1.3.7 step 4: when `aud` is an array, `azp` MUST be
  // present and MUST equal `clientId`. Defends against token substitution
  // — an attacker holding a token legitimately issued for a different
  // client in a multi-aud token can't replay it here.
  if (Array.isArray(claims.aud)) {
    if (typeof claims.azp !== "string" || claims.azp.length === 0) {
      throw new AuthError("invalid_id_token", "azp claim required when aud is an array");
    }
    if (claims.azp !== opts.clientId) {
      throw new AuthError("invalid_id_token", "azp mismatch");
    }
  }

  if (typeof claims.exp !== "number" || claims.exp < now - skew) {
    throw new AuthError("invalid_id_token", "id_token expired");
  }

  if (opts.nonce !== undefined && claims.nonce !== opts.nonce) {
    throw new AuthError("invalid_id_token", "nonce mismatch");
  }

  return claims;
}

function decodeJsonSegment(seg: string): unknown {
  const padding = (4 - (seg.length % 4)) % 4;
  const b64 = seg.replace(/-/g, "+").replace(/_/g, "/").padEnd(seg.length + padding, "=");
  let binary: string;
  try {
    binary = atob(b64);
  } catch {
    throw new AuthError("invalid_id_token", "claims segment is not valid base64url");
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new AuthError("invalid_id_token", "claims segment is not valid JSON");
  }
}
