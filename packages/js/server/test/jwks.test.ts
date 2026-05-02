import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { JwksCache } from "../jwks.js";
import { AuthError } from "../errors.js";
import { makeJwksResponse, makeTestKeypair, type TestKeypair } from "./_helpers.js";

const JWKS_URI = "https://acme.allowthem.io/.well-known/jwks.json";

let kp1: TestKeypair;
let kp2: TestKeypair;

beforeEach(async () => {
  kp1 = await makeTestKeypair("kid-1");
  kp2 = await makeTestKeypair("kid-2");
});

afterEach(() => {
  vi.useRealTimers();
});

/** Build a fetch spy that returns the JWKS body produced by `bodyFn`. */
function jwksFetch(bodyFn: () => unknown, status = 200): { fetch: typeof fetch; calls: () => number } {
  const spy = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => {
    const body = bodyFn();
    return new Response(typeof body === "string" ? body : JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  });
  return { fetch: spy as unknown as typeof fetch, calls: () => spy.mock.calls.length };
}

function makeCache(opts: {
  fetch: typeof fetch;
  ttl?: number;
  minRefresh?: number;
}): JwksCache {
  return new JwksCache({
    jwksUri: JWKS_URI,
    cacheTtlSeconds: opts.ttl ?? 3600,
    minRefreshIntervalSeconds: opts.minRefresh ?? 60,
    fetch: opts.fetch,
  });
}

describe("JwksCache", () => {
  it("cold fetch — first lookup triggers exactly one fetch and returns the key", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp1]));
    const cache = makeCache({ fetch: f.fetch });

    const key = await cache.getKey("kid-1");
    expect(key).not.toBeNull();
    expect(f.calls()).toBe(1);
  });

  it("warm cache — second lookup reuses cached key without refetch", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp1]));
    const cache = makeCache({ fetch: f.fetch });

    await cache.getKey("kid-1");
    await cache.getKey("kid-1");
    expect(f.calls()).toBe(1);
  });

  it("unknown kid + recent fetch — rate-limit returns null without refetch", async () => {
    const f = jwksFetch(() => makeJwksResponse([kp1]));
    const cache = makeCache({ fetch: f.fetch });

    await cache.getKey("kid-1"); // primes fetchedAt
    expect(f.calls()).toBe(1);

    const missing = await cache.getKey("does-not-exist");
    expect(missing).toBeNull();
    expect(f.calls()).toBe(1); // anti-DoS — no extra fetch
  });

  it("unknown kid + stale fetch — refresh past minRefreshInterval finds the rotated key", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let bodyKps: TestKeypair[] = [kp1];
    const f = jwksFetch(() => makeJwksResponse(bodyKps));
    const cache = makeCache({ fetch: f.fetch, minRefresh: 60 });

    await cache.getKey("kid-1");
    expect(f.calls()).toBe(1);

    // Endpoint rotates: only kid-2 advertised now.
    bodyKps = [kp2];
    // Past the rate-limit window.
    vi.setSystemTime(new Date(Date.now() + 61_000));

    const key2 = await cache.getKey("kid-2");
    expect(key2).not.toBeNull();
    expect(f.calls()).toBe(2);
  });

  it("single-flight — concurrent misses on cold cache trigger exactly one fetch", async () => {
    let resolveFetch: (() => void) | null = null;
    const fetchGate = new Promise<void>((res) => { resolveFetch = res; });
    const inner = vi.fn(async (): Promise<Response> => {
      await fetchGate;
      return new Response(JSON.stringify(makeJwksResponse([kp1, kp2])), { status: 200 });
    });
    const f = inner as unknown as typeof fetch;
    const cache = makeCache({ fetch: f });

    const all = Promise.all([
      cache.getKey("kid-1"),
      cache.getKey("kid-1"),
      cache.getKey("kid-2"),
    ]);
    // All three should be queued behind the single in-flight refresh.
    expect(inner).toHaveBeenCalledTimes(1);
    resolveFetch!();
    const [a, b, c] = await all;
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
    expect(c).not.toBeNull();
    expect(inner).toHaveBeenCalledTimes(1);
  });

  it("rotation recovery — old kid stays valid in cache after rotation refresh", async () => {
    // After Step 5 lands, the verifier-level rotation test asserts end-to-end
    // verify(token) success. Here we cover the cache-state contract.
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let bodyKps: TestKeypair[] = [kp1];
    const f = jwksFetch(() => makeJwksResponse(bodyKps));
    const cache = makeCache({ fetch: f.fetch, minRefresh: 60 });

    await cache.getKey("kid-1");

    bodyKps = [kp1, kp2]; // rotation: both advertised
    vi.setSystemTime(new Date(Date.now() + 61_000));
    const k2 = await cache.getKey("kid-2");
    expect(k2).not.toBeNull();
    const k1again = await cache.getKey("kid-1");
    expect(k1again).not.toBeNull();
  });

  it("network error — throws jwks_fetch_failed and leaves fetchedAt unchanged", async () => {
    const fetchFn: typeof fetch = (async () => {
      throw new TypeError("ECONNREFUSED");
    }) as typeof fetch;
    const cache = makeCache({ fetch: fetchFn });

    await expect(cache.getKey("kid-1")).rejects.toMatchObject({
      code: "jwks_fetch_failed",
    });
    expect(cache._stateForTests().fetchedAt).toBeNull();
  });

  it("non-2xx response — throws jwks_fetch_failed and SETS fetchedAt", async () => {
    const f = jwksFetch(() => "service unavailable", 503);
    const cache = makeCache({ fetch: f.fetch });

    await expect(cache.getKey("kid-1")).rejects.toThrowError(
      new AuthError("jwks_fetch_failed", "JWKS endpoint returned 503"),
    );
    expect(cache._stateForTests().fetchedAt).not.toBeNull();
  });

  it("malformed JSON — throws jwks_fetch_failed and SETS fetchedAt", async () => {
    const f = jwksFetch(() => "not-json{{{", 200);
    const cache = makeCache({ fetch: f.fetch });

    await expect(cache.getKey("kid-1")).rejects.toMatchObject({
      code: "jwks_fetch_failed",
    });
    expect(cache._stateForTests().fetchedAt).not.toBeNull();
  });

  it("zero usable keys after a 200 — preserves the previous key map", async () => {
    let returnEmpty = false;
    const f = jwksFetch(() => (returnEmpty ? { keys: [] } : makeJwksResponse([kp1])));
    const cache = makeCache({ fetch: f.fetch, minRefresh: 60 });

    // Prime cache with kid-1.
    expect(await cache.getKey("kid-1")).not.toBeNull();
    const before = cache._stateForTests().keys.size;
    expect(before).toBe(1);

    // Force a refresh that returns empty keys.
    returnEmpty = true;
    await cache.refresh();

    // Existing kid-1 is still resolvable — non-destructive replacement.
    const k1again = cache._stateForTests().keys.get("kid-1");
    expect(k1again).toBeDefined();
    expect(cache._stateForTests().keys.size).toBe(1);
  });

  it("ttl expiry — proactive refresh on next lookup even for known kids", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const f = jwksFetch(() => makeJwksResponse([kp1]));
    const cache = makeCache({ fetch: f.fetch, ttl: 5, minRefresh: 1 });

    await cache.getKey("kid-1");
    expect(f.calls()).toBe(1);

    // Within TTL — no extra fetch.
    vi.setSystemTime(new Date(Date.now() + 2_000));
    await cache.getKey("kid-1");
    expect(f.calls()).toBe(1);

    // Past TTL — proactive refresh fires.
    vi.setSystemTime(new Date(Date.now() + 10_000));
    await cache.getKey("kid-1");
    expect(f.calls()).toBe(2);
  });

  it("filters non-RS256 / non-RSA / kid-less JWKs", async () => {
    const f = jwksFetch(() => ({
      keys: [
        kp1.publicJwk,
        { kty: "EC", alg: "ES256", kid: "ec-1", crv: "P-256", x: "x", y: "y" },
        { ...kp2.publicJwk, alg: "PS256" },
        { ...kp1.publicJwk, kid: undefined },
      ],
    }));
    const cache = makeCache({ fetch: f.fetch });

    expect(await cache.getKey("kid-1")).not.toBeNull();
    expect(await cache.getKey("ec-1")).toBeNull();
    expect(await cache.getKey("kid-2")).toBeNull(); // alg PS256 filtered
  });
});
