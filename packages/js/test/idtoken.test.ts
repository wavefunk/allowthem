import { describe, it, expect } from "vitest";
import { AuthError } from "../src/errors.js";
import {
  parseIdTokenClaims,
  validateIdToken,
  type IdTokenClaims,
} from "../src/idtoken.js";

/**
 * Hand-rolled JWT helper. Header + payload + a fixed-string signature
 * (the SDK does not verify the JWS signature, so any non-empty third
 * segment passes parseIdTokenClaims's segment count check).
 */
function makeJwt(claims: IdTokenClaims): string {
  const header = base64urlEncode(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const body = base64urlEncode(JSON.stringify(claims));
  return `${header}.${body}.fake-signature`;
}

function base64urlEncode(s: string): string {
  return btoa(unescape(encodeURIComponent(s)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

const ISSUER = "https://acme.allowthem.io";
const CLIENT_ID = "client_abc";
const NONCE = "nonce_123";
const NOW_SECONDS = 1_750_000_000;
const NOW_MS = NOW_SECONDS * 1000;

function baseClaims(): IdTokenClaims {
  return {
    iss: ISSUER,
    sub: "user_xyz",
    aud: CLIENT_ID,
    exp: NOW_SECONDS + 3600,
    iat: NOW_SECONDS,
    nonce: NONCE,
  };
}

describe("parseIdTokenClaims", () => {
  it("decodes a well-formed JWT", () => {
    const jwt = makeJwt(baseClaims());
    const c = parseIdTokenClaims(jwt);
    expect(c.iss).toBe(ISSUER);
    expect(c.sub).toBe("user_xyz");
  });

  it("throws on a 2-segment input", () => {
    expect(() => parseIdTokenClaims("a.b")).toThrow(AuthError);
    expect(() => parseIdTokenClaims("a.b")).toThrow(/3 segments/);
  });

  it("throws on a malformed base64url segment", () => {
    expect(() => parseIdTokenClaims("a.!!!.c")).toThrow(AuthError);
  });

  it("throws on a non-JSON claims segment", () => {
    const header = base64urlEncode("{}");
    const notJson = base64urlEncode("not json");
    expect(() => parseIdTokenClaims(`${header}.${notJson}.sig`)).toThrow(/JSON/);
  });
});

describe("validateIdToken", () => {
  const opts = {
    issuer: ISSUER,
    clientId: CLIENT_ID,
    nonce: NONCE,
    now: () => NOW_MS,
  };

  it("accepts a valid token", () => {
    const c = validateIdToken(makeJwt(baseClaims()), opts);
    expect(c.sub).toBe("user_xyz");
  });

  it("rejects iss mismatch", () => {
    const jwt = makeJwt({ ...baseClaims(), iss: "https://evil.example" });
    expect(() => validateIdToken(jwt, opts)).toThrow(/iss mismatch/);
  });

  it("rejects aud mismatch (string form)", () => {
    const jwt = makeJwt({ ...baseClaims(), aud: "different_client" });
    expect(() => validateIdToken(jwt, opts)).toThrow(/aud/);
  });

  it("accepts aud as array containing clientId (with required azp)", () => {
    // OIDC §3.1.3.7 step 4: array aud requires azp = clientId. The
    // dedicated azp-enforcement describe-block tests the negative paths.
    const jwt = makeJwt({
      ...baseClaims(),
      aud: ["other", CLIENT_ID],
      azp: CLIENT_ID,
    });
    const c = validateIdToken(jwt, opts);
    expect(Array.isArray(c.aud)).toBe(true);
  });

  it("rejects aud as array missing clientId", () => {
    const jwt = makeJwt({ ...baseClaims(), aud: ["other", "another"] });
    expect(() => validateIdToken(jwt, opts)).toThrow(/aud/);
  });

  it("rejects expired token outside skew", () => {
    // exp 120s before now; default skew is 60s
    const jwt = makeJwt({ ...baseClaims(), exp: NOW_SECONDS - 120 });
    expect(() => validateIdToken(jwt, opts)).toThrow(/expired/);
  });

  it("accepts token within skew window", () => {
    // exp 30s before now; within default skew of 60s
    const jwt = makeJwt({ ...baseClaims(), exp: NOW_SECONDS - 30 });
    expect(() => validateIdToken(jwt, opts)).not.toThrow();
  });

  it("rejects nonce mismatch", () => {
    const jwt = makeJwt({ ...baseClaims(), nonce: "different" });
    expect(() => validateIdToken(jwt, opts)).toThrow(/nonce/);
  });

  it("skips nonce check when nonce is undefined in opts (refresh path)", () => {
    const jwt = makeJwt({ ...baseClaims(), nonce: "anything" });
    expect(() =>
      validateIdToken(jwt, { issuer: ISSUER, clientId: CLIENT_ID, now: () => NOW_MS }),
    ).not.toThrow();
  });

  it("rejects token with non-numeric exp", () => {
    const jwt = makeJwt({ ...baseClaims(), exp: "soon" as unknown as number });
    expect(() => validateIdToken(jwt, opts)).toThrow(/expired/);
  });
});

/**
 * OIDC Core §3.1.3.7 step 4: when `aud` is an array (or contains multiple
 * values), `azp` (Authorized Party) MUST be present and equal `clientId`.
 * Without this check, an attacker who legitimately holds a token issued for
 * a *different* client in a multi-aud token could replay it against this
 * relying party. This is the canonical OIDC token-substitution attack.
 */
describe("validateIdToken — azp (authorized party) enforcement", () => {
  it("rejects array aud when azp is missing", () => {
    const jwt = makeJwt({
      ...baseClaims(),
      aud: [CLIENT_ID, "other_client"],
      // azp omitted intentionally
    });
    expect(() =>
      validateIdToken(jwt, { issuer: ISSUER, clientId: CLIENT_ID, nonce: NONCE, now: () => NOW_MS }),
    ).toThrowError(new AuthError("invalid_id_token", "azp claim required when aud is an array"));
  });

  it("rejects array aud when azp does not equal clientId", () => {
    const jwt = makeJwt({
      ...baseClaims(),
      aud: [CLIENT_ID, "other_client"],
      azp: "other_client",
    });
    expect(() =>
      validateIdToken(jwt, { issuer: ISSUER, clientId: CLIENT_ID, nonce: NONCE, now: () => NOW_MS }),
    ).toThrowError(new AuthError("invalid_id_token", "azp mismatch"));
  });

  it("accepts array aud when azp equals clientId", () => {
    const jwt = makeJwt({
      ...baseClaims(),
      aud: [CLIENT_ID, "other_client"],
      azp: CLIENT_ID,
    });
    expect(() =>
      validateIdToken(jwt, { issuer: ISSUER, clientId: CLIENT_ID, nonce: NONCE, now: () => NOW_MS }),
    ).not.toThrow();
  });

  it("accepts string aud without requiring azp", () => {
    // Single-aud case: azp is optional per OIDC §3.1.3.7. The existing
    // happy-path tests cover this; this test makes the contract explicit.
    const jwt = makeJwt({ ...baseClaims(), aud: CLIENT_ID });
    expect(() =>
      validateIdToken(jwt, { issuer: ISSUER, clientId: CLIENT_ID, nonce: NONCE, now: () => NOW_MS }),
    ).not.toThrow();
  });

  it("rejects single-element array aud when azp is missing", () => {
    // OIDC Core §3.1.3.7 step 4 requires azp whenever aud is an *array* —
    // a one-element array is still an array, and a paranoid IdP that always
    // emits arrays should still get the azp check.
    const jwt = makeJwt({ ...baseClaims(), aud: [CLIENT_ID] });
    expect(() =>
      validateIdToken(jwt, { issuer: ISSUER, clientId: CLIENT_ID, nonce: NONCE, now: () => NOW_MS }),
    ).toThrowError(new AuthError("invalid_id_token", "azp claim required when aud is an array"));
  });
});
