import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { errors as joseErrors } from "jose";
import { AuthError } from "../errors.js";
import { createAllowthemVerifier } from "../verifier.js";
import {
  makeJwksResponse,
  makeTestKeypair,
  makeUnsignedTokenWithHeader,
  signTestToken,
  type TestKeypair,
} from "./_helpers.js";

const DOMAIN = "acme.allowthem.io";
const ISSUER = `https://${DOMAIN}`;
const AUDIENCE = "ath_xxx";

let kp: TestKeypair;
let kp2: TestKeypair;

beforeEach(async () => {
  kp = await makeTestKeypair("kid-1");
  kp2 = await makeTestKeypair("kid-2");
});
afterEach(() => {
  vi.useRealTimers();
});

function jwksFetch(bodyFn: () => unknown, status = 200): {
  fetch: typeof fetch;
  calls: () => number;
} {
  let count = 0;
  const fn = async (): Promise<Response> => {
    count += 1;
    const body = bodyFn();
    return new Response(typeof body === "string" ? body : JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  };
  return { fetch: fn as unknown as typeof fetch, calls: () => count };
}

function makeVerifier(fetchFn: typeof fetch, opts: { minRefresh?: number } = {}) {
  return createAllowthemVerifier({
    domain: DOMAIN,
    audience: AUDIENCE,
    fetch: fetchFn,
    ...(opts.minRefresh !== undefined ? { jwksMinRefreshIntervalSeconds: opts.minRefresh } : {}),
  });
}

describe("verify — happy path", () => {
  it("returns AllowthemUser with mapped fields and full raw payload", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    const token = await signTestToken({
      kp,
      iss: ISSUER,
      aud: AUDIENCE,
      sub: "user-42",
      email: "alice@example.com",
      email_verified: true,
      username: "alice",
      roles: ["admin"],
      permissions: ["users:read"],
      extra: { "https://acme.com/dept": "eng" },
    });

    const user = await verifier.verify(token);
    expect(user.sub).toBe("user-42");
    expect(user.email).toBe("alice@example.com");
    expect(user.emailVerified).toBe(true);
    expect(user.username).toBe("alice");
    expect(user.roles).toEqual(["admin"]);
    expect(user.permissions).toEqual(["users:read"]);
    expect(user.raw["https://acme.com/dept"]).toBe("eng");
  });

  it("accepts both `Bearer x` and bare `x`", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    const token = await signTestToken({ kp, iss: ISSUER, aud: AUDIENCE });

    const user1 = await verifier.verify(token);
    const user2 = await verifier.verify(`Bearer ${token}`);
    const user3 = await verifier.verify(`bearer ${token}`); // case-insensitive
    expect(user1.sub).toBe(user2.sub);
    expect(user2.sub).toBe(user3.sub);
  });

  it("omits `username` when claim absent (exactOptionalPropertyTypes contract)", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    const token = await signTestToken({ kp, iss: ISSUER, aud: AUDIENCE });
    const user = await verifier.verify(token);
    expect("username" in user).toBe(false);
  });

  it("non-destructive cache: a flapping JWKS endpoint doesn't break verify", async () => {
    let returnEmpty = false;
    const f = jwksFetch(() => (returnEmpty ? { keys: [] } : makeJwksResponse([kp])));
    const verifier = makeVerifier(f.fetch);

    // Prime cache with kid-1.
    const token = await signTestToken({ kp, iss: ISSUER, aud: AUDIENCE });
    await verifier.verify(token);

    // Endpoint goes flappy: returns empty keys.
    returnEmpty = true;

    // A fresh verify with the same token still succeeds — cache preserved.
    const user = await verifier.verify(token);
    expect(user.sub).toBeDefined();
  });
});

describe("verify — reject cases", () => {
  it("tampered signature → invalid_token + retry-after-refresh fired (signature path)", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    const token = await signTestToken({ kp, iss: ISSUER, aud: AUDIENCE });
    // Mutate the last segment to break the signature.
    const parts = token.split(".");
    const tampered = `${parts[0]}.${parts[1]}.AAAA`;

    await expect(verifier.verify(tampered)).rejects.toMatchObject({ code: "invalid_token" });
    // Signature failure triggers the refresh-and-retry path: 1 cold fetch + 1 forced refresh.
    expect(f.calls()).toBe(2);
  });

  it("iss mismatch → invalid_token (NO refresh — guards over-broad-retry regression)", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    const token = await signTestToken({ kp, iss: "https://evil.example.com", aud: AUDIENCE });

    await expect(verifier.verify(token)).rejects.toMatchObject({ code: "invalid_token" });
    expect(f.calls()).toBe(1); // claim failure must NOT refresh JWKS
  });

  it("aud mismatch (string) → invalid_token + no refresh", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    const token = await signTestToken({ kp, iss: ISSUER, aud: "wrong-aud" });

    await expect(verifier.verify(token)).rejects.toMatchObject({ code: "invalid_token" });
    expect(f.calls()).toBe(1);
  });

  it("aud mismatch (array) → invalid_token", async () => {
    // Defensive: server emits string aud today, but the verifier must handle
    // the array form correctly if the server widens.
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    const token = await signTestToken({
      kp,
      iss: ISSUER,
      aud: ["wrong-1", "wrong-2"],
    });

    await expect(verifier.verify(token)).rejects.toMatchObject({ code: "invalid_token" });
  });

  it("aud match (array containing audience) → success", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    const token = await signTestToken({
      kp,
      iss: ISSUER,
      aud: ["other-app", AUDIENCE, "another-app"],
    });
    const user = await verifier.verify(token);
    expect(user.sub).toBeDefined();
  });

  it("exp past more than skew → invalid_token", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    const past = Math.floor(Date.now() / 1000) - 3600;
    const token = await signTestToken({ kp, iss: ISSUER, aud: AUDIENCE, exp: past });

    await expect(verifier.verify(token)).rejects.toMatchObject({ code: "invalid_token" });
  });

  it("exp within skew → success", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    // exp is 30s in the past but skew is 60s → accepted.
    const exp = Math.floor(Date.now() / 1000) - 30;
    const token = await signTestToken({ kp, iss: ISSUER, aud: AUDIENCE, exp });
    const user = await verifier.verify(token);
    expect(user.sub).toBeDefined();
  });

  it("iat in future more than skew → invalid_token (manual check)", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    const farFuture = Math.floor(Date.now() / 1000) + 600;
    const token = await signTestToken({
      kp,
      iss: ISSUER,
      aud: AUDIENCE,
      iat: farFuture,
      exp: farFuture + 300,
    });

    await expect(verifier.verify(token)).rejects.toThrowError(
      new AuthError("invalid_token", "iat in the future"),
    );
  });

  it("alg HS256 in header → invalid_token, fetch never called", async () => {
    // jose.SignJWT can't produce this (key/alg validation), so hand-construct.
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    const token = makeUnsignedTokenWithHeader(
      { alg: "HS256", kid: "kid-1", typ: "at+jwt" },
      { iss: ISSUER, aud: AUDIENCE, sub: "x", exp: Math.floor(Date.now() / 1000) + 300 },
    );

    await expect(verifier.verify(token)).rejects.toThrowError(
      new AuthError("invalid_token", "unsupported algorithm"),
    );
    expect(f.calls()).toBe(0); // step-2 alg guard rejects before key lookup
  });

  it("missing kid → invalid_token", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    const token = makeUnsignedTokenWithHeader(
      { alg: "RS256", typ: "at+jwt" },
      { iss: ISSUER, aud: AUDIENCE, sub: "x" },
    );

    await expect(verifier.verify(token)).rejects.toThrowError(
      new AuthError("invalid_token", "missing kid"),
    );
  });

  it("malformed JWT (not 3 segments) → invalid_token", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);

    await expect(verifier.verify("not-a-jwt")).rejects.toMatchObject({ code: "invalid_token" });
    await expect(verifier.verify("a.b")).rejects.toMatchObject({ code: "invalid_token" });
  });

  it("empty / whitespace-only token → invalid_token", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);

    await expect(verifier.verify("")).rejects.toThrowError(
      new AuthError("invalid_token", "missing token"),
    );
    await expect(verifier.verify("   ")).rejects.toThrowError(
      new AuthError("invalid_token", "missing token"),
    );
    // `Bearer  ` trims to `Bearer` (no token body), which doesn't match the
    // `Bearer\s+` strip regex; it falls through to header-decode and fails
    // as "malformed JWT". Either failure mode is acceptably 401-equivalent.
    await expect(verifier.verify("Bearer  ")).rejects.toMatchObject({
      code: "invalid_token",
    });
  });

  it("typ JWT (not at+jwt) → invalid_token", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    const token = await signTestToken({
      kp,
      iss: ISSUER,
      aud: AUDIENCE,
      typ: "JWT",
    });

    await expect(verifier.verify(token)).rejects.toMatchObject({ code: "invalid_token" });
  });
});

describe("verify — claim shape guards", () => {
  it("missing sub → invalid_token", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    const token = await signTestToken({ kp, iss: ISSUER, aud: AUDIENCE, sub: "" });

    await expect(verifier.verify(token)).rejects.toThrowError(
      new AuthError("invalid_token", "sub claim required"),
    );
  });

  it("missing email → invalid_token", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    const token = await signTestToken({ kp, iss: ISSUER, aud: AUDIENCE, email: "" });

    await expect(verifier.verify(token)).rejects.toThrowError(
      new AuthError("invalid_token", "email claim required"),
    );
  });

  it("non-array roles/permissions are coerced to []", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp]));
    const verifier = makeVerifier(f.fetch);
    // `roles` and `permissions` claims defaulted to []; remove via extra to
    // hide them from the protected payload.
    const token = await signTestToken({
      kp,
      iss: ISSUER,
      aud: AUDIENCE,
      // override with non-array values
      extra: { roles: "admin", permissions: 42 },
    });
    const user = await verifier.verify(token);
    // signTestToken sets roles/permissions arrays; extra overrides them.
    expect(user.roles).toEqual([]);
    expect(user.permissions).toEqual([]);
  });
});

describe("verify — rotation recovery", () => {
  it("token signed with newly-rotated kid succeeds after forced refresh", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let bodyKps: TestKeypair[] = [kp];
    const f = jwksFetch(() => makeJwksResponse(bodyKps));
    const verifier = makeVerifier(f.fetch, { minRefresh: 60 });

    // Prime cache with kp (kid-1).
    const t1 = await signTestToken({ kp, iss: ISSUER, aud: AUDIENCE });
    await verifier.verify(t1);

    // Endpoint rotates: kp2 (kid-2) only.
    bodyKps = [kp2];

    // Token signed by new key; cache only has kid-1. Without past-rate-limit,
    // first attempt returns null → AuthError(unknown kid) → forced refresh →
    // retry succeeds because refresh fetches kid-2.
    vi.setSystemTime(new Date(Date.now() + 61_000));
    const t2 = await signTestToken({ kp: kp2, iss: ISSUER, aud: AUDIENCE });
    const user = await verifier.verify(t2);
    expect(user.sub).toBeDefined();
  });

  it("after rate-limit-blocked unknown-kid, force refresh resolves new key", async () => {
    let bodyKps: TestKeypair[] = [kp];
    const f = jwksFetch(() => makeJwksResponse(bodyKps));
    const verifier = makeVerifier(f.fetch, { minRefresh: 60 });

    // Prime cache.
    await verifier.verify(await signTestToken({ kp, iss: ISSUER, aud: AUDIENCE }));
    expect(f.calls()).toBe(1);

    // Endpoint rotates immediately. Sign with new key.
    bodyKps = [kp2];
    const t2 = await signTestToken({ kp: kp2, iss: ISSUER, aud: AUDIENCE });

    // First getKey hits rate-limit (recent fetchedAt) → null → unknown kid →
    // catch fires retry → refresh → key found → verify succeeds.
    const user = await verifier.verify(t2);
    expect(user.sub).toBeDefined();
    // 1 cold + 1 forced refresh from the retry path.
    expect(f.calls()).toBe(2);
  });
});

describe("verify — concurrent verify under refresh (single-flight at verify level)", () => {
  it("two concurrent verifies with unknown-kid trigger one combined refresh", async () => {
    // Both calls miss on a kid that lands only after a refresh. The
    // jwks.refresh() single-flight should coalesce the two concurrent
    // forced refreshes into one network fetch.
    let resolveFetch: (() => void) | null = null;
    const fetchGate = new Promise<void>((res) => { resolveFetch = res; });
    let calls = 0;
    const inner = async (): Promise<Response> => {
      calls += 1;
      // Hold the first fetch open so the second verify gets to call refresh
      // while the first is in flight.
      if (calls === 1) await fetchGate;
      return new Response(JSON.stringify(makeJwksResponse([kp])), { status: 200 });
    };
    const verifier = makeVerifier(inner as unknown as typeof fetch);

    const t1 = await signTestToken({ kp, iss: ISSUER, aud: AUDIENCE });
    const t2 = await signTestToken({ kp, iss: ISSUER, aud: AUDIENCE, sub: "user-2" });

    const both = Promise.all([verifier.verify(t1), verifier.verify(t2)]);
    // Allow microtasks to schedule both refresh calls behind the gate.
    await new Promise<void>((r) => setTimeout(r, 0));
    expect(calls).toBe(1); // only one fetch in flight despite two verifies
    resolveFetch!();
    const [u1, u2] = await both;
    expect(u1.sub).toBeDefined();
    expect(u2.sub).toBe("user-2");
    expect(calls).toBe(1); // single-flight ate the second refresh
  });

  it("forced refresh during signature-failure retry coalesces with concurrent verify", async () => {
    // First verify hits a tampered token → JWSSignatureVerificationFailed
    // → forces a refresh. A second verify arrives during that refresh and
    // also passes the cache miss (because cache was already primed but the
    // refresh resets `inFlight`). Should not double-fetch.
    let calls = 0;
    let releaseFirst: (() => void) | null = null;
    const firstGate = new Promise<void>((res) => { releaseFirst = res; });
    const inner = async (): Promise<Response> => {
      calls += 1;
      // Hold ONLY the second call (the forced refresh) so the third caller
      // joins the in-flight refresh.
      if (calls === 2) await firstGate;
      return new Response(JSON.stringify(makeJwksResponse([kp])), { status: 200 });
    };
    const verifier = makeVerifier(inner as unknown as typeof fetch);

    // Prime cache.
    const goodToken = await signTestToken({ kp, iss: ISSUER, aud: AUDIENCE });
    await verifier.verify(goodToken);
    expect(calls).toBe(1);

    // Tamper a token and kick off concurrent retries.
    const t = await signTestToken({ kp, iss: ISSUER, aud: AUDIENCE });
    const parts = t.split(".");
    const tampered = `${parts[0]}.${parts[1]}.AAAA`;

    const a = verifier.verify(tampered).catch((e) => e);
    // The first verify enters the refresh-and-retry path; let it begin the
    // refresh fetch (call #2).
    await new Promise<void>((r) => setTimeout(r, 0));
    // Concurrent: a fresh verify with another tampered copy. It will also
    // hit a signature failure (cache key still resolves) and join the
    // already-in-flight refresh.
    const b = verifier.verify(tampered).catch((e) => e);
    await new Promise<void>((r) => setTimeout(r, 0));
    releaseFirst!();
    const [errA, errB] = await Promise.all([a, b]);
    expect(errA).toBeInstanceOf(AuthError);
    expect(errB).toBeInstanceOf(AuthError);
    // 1 cold + 1 forced refresh shared by both retries = 2 fetches.
    expect(calls).toBe(2);
  });
});

describe("verify — error class introspection (regression guards)", () => {
  it("joseErrors.JWSSignatureVerificationFailed export is present", () => {
    // If jose 6+ moves the class, the verifier's `instanceof` silently goes
    // false and the retry never fires. This test catches the move at the
    // package surface level.
    expect(joseErrors.JWSSignatureVerificationFailed).toBeDefined();
    expect(typeof joseErrors.JWSSignatureVerificationFailed).toBe("function");
  });
});
