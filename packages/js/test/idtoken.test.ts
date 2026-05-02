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

  it("accepts aud as array containing clientId", () => {
    const jwt = makeJwt({ ...baseClaims(), aud: ["other", CLIENT_ID] });
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
