/**
 * PKCE (RFC 7636) primitives for the authorization-code flow.
 *
 * - Verifier: 32 random bytes → 43-char base64url string.
 * - Challenge: SHA-256 of the verifier, base64url-encoded (S256).
 *
 * All operations use the platform Web Crypto API (`crypto.getRandomValues`,
 * `crypto.subtle.digest`). HTTPS is required in production; `localhost`
 * is exempt (browsers treat it as a secure context).
 */

/**
 * Cryptographically secure random bytes via Web Crypto.
 */
export function randomBytes(len: number): Uint8Array {
  const out = new Uint8Array(len);
  if (len > 0) {
    crypto.getRandomValues(out);
  }
  return out;
}

/**
 * SHA-256 of a UTF-8 encoded string.
 */
async function sha256(input: string): Promise<Uint8Array> {
  const buf = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return new Uint8Array(digest);
}

/**
 * Base64url-encode a byte array (RFC 4648 §5, no padding).
 */
export function base64url(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += String.fromCharCode(bytes[i]!);
  }
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Generate a PKCE code verifier: 32 random bytes → 43 base64url chars.
 *
 * RFC 7636 §4.1 mandates 43–128 chars; 43 is the floor and the only
 * length that makes sense from a 32-byte secret (3×ceil(8/6) → 4 chars).
 */
export function generateVerifier(): string {
  return base64url(randomBytes(32));
}

/**
 * Compute the S256 challenge for a given verifier:
 * `BASE64URL(SHA256(verifier))`.
 */
export async function generateChallenge(verifier: string): Promise<string> {
  return base64url(await sha256(verifier));
}

/**
 * Generate a random base64url-encoded string from `byteLen` random bytes.
 * Used for `state` and `nonce` parameters; default 32 bytes (43 chars).
 */
export function generateRandomString(byteLen = 32): string {
  return base64url(randomBytes(byteLen));
}
