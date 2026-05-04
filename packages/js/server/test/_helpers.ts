/**
 * Test infrastructure for server-SDK tests.
 *
 * - {@link makeTestKeypair} — RS256 keypair via jose, returns the public JWK
 *   ready to drop into a JWKS response.
 * - {@link signTestToken} — sign a JWT with allowthem-shaped claims; used by
 *   verifier and middleware tests.
 * - {@link makeJwksResponse} — wrap public JWKs into the `{ keys: [...] }`
 *   shape the server emits.
 * - {@link makeUnsignedTokenWithHeader} — hand-construct a JWT with arbitrary
 *   header (used for negative tests, e.g. `alg: HS256` in header). jose's
 *   `SignJWT` validates that the signing key matches the declared alg, so
 *   it can't produce a malicious-header token; this helper bypasses that.
 *
 * Underscore prefix keeps vitest's `**\/*.test.ts` glob from picking this
 * file up as a test suite.
 */
import { exportJWK, generateKeyPair, SignJWT, type JWK, type KeyLike } from "jose";

export interface TestKeypair {
  kid: string;
  privateKey: KeyLike;
  publicKey: KeyLike;
  publicJwk: JWK;
}

/** Generate an RS256 keypair and the matching public JWK (alg/use/kid set). */
export async function makeTestKeypair(kid = "test-kid-1"): Promise<TestKeypair> {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";
  publicJwk.kid = kid;
  return { kid, privateKey, publicKey, publicJwk };
}

export interface SignTokenArgs {
  kp: TestKeypair;
  iss: string;
  aud: string | string[];
  sub?: string;
  email?: string;
  email_verified?: boolean;
  username?: string;
  roles?: string[];
  permissions?: string[];
  scope?: string;
  /** Unix seconds; default `now + 300`. */
  exp?: number;
  /** Unix seconds; default `now`. */
  iat?: number;
  /** JWT `typ` header; default `"at+jwt"`. */
  typ?: string;
  /** Override for negative tests; default `"RS256"`. Must match the kp's key. */
  alg?: string;
  /** Extra claims merged into the body. */
  extra?: Record<string, unknown>;
}

/** Sign a token shaped like an allowthem access token. */
export async function signTestToken(args: SignTokenArgs): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const body: Record<string, unknown> = {
    sub: args.sub ?? "user-123",
    email: args.email ?? "u@example.com",
    email_verified: args.email_verified ?? true,
    roles: args.roles ?? [],
    permissions: args.permissions ?? [],
    ...(args.username !== undefined ? { username: args.username } : {}),
    ...(args.scope !== undefined ? { scope: args.scope } : {}),
    ...(args.extra ?? {}),
  };
  return new SignJWT(body)
    .setProtectedHeader({
      alg: args.alg ?? "RS256",
      kid: args.kp.kid,
      typ: args.typ ?? "at+jwt",
    })
    .setIssuer(args.iss)
    .setAudience(args.aud)
    .setExpirationTime(args.exp ?? now + 300)
    .setIssuedAt(args.iat ?? now)
    .sign(args.kp.privateKey);
}

/** Wrap one or more public JWKs into the JWKS response envelope. */
export function makeJwksResponse(kps: TestKeypair[]): { keys: JWK[] } {
  return { keys: kps.map((kp) => kp.publicJwk) };
}

/**
 * Hand-construct a JWT-shaped string with arbitrary header — bypasses jose's
 * key/alg validation. Used for the algorithm-confusion negative test where
 * the header lies about the algorithm.
 *
 * NOTE: base64url, not base64 — JWS wire format requires `+` → `-`, `/` → `_`,
 * trailing `=` removed. Node's `Buffer.toString("base64url")` does this.
 */
export function makeUnsignedTokenWithHeader(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): string {
  const enc = (obj: Record<string, unknown>): string =>
    Buffer.from(JSON.stringify(obj)).toString("base64url");
  // Bogus signature — verifier rejects on alg before signature check, so
  // this is unreachable. Real base64url just to keep the JWS shape valid.
  const sig = "AAAA";
  return `${enc(header)}.${enc(payload)}.${sig}`;
}

/**
 * Build a `fetch`-shaped mock that returns the given JWKS body for any URL.
 * Returns the spy so tests can assert call count / args.
 */
export function makeJwksFetch(body: { keys: JWK[] } | string | (() => { keys: JWK[] } | string), status = 200): typeof fetch {
  const fn = async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => {
    const resolved = typeof body === "function" ? body() : body;
    if (typeof resolved === "string") {
      return new Response(resolved, { status, headers: { "content-type": "application/json" } });
    }
    return new Response(JSON.stringify(resolved), {
      status,
      headers: { "content-type": "application/json" },
    });
  };
  return fn as typeof fetch;
}
