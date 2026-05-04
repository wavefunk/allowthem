/**
 * JWKS fetch + cache + single-flight refresh for the server SDK.
 *
 * Mirrors the semantics of `crates/client/jwks.rs`: refresh-on-miss for an
 * unknown kid, anti-DoS rate-limit between forced refreshes, single-flight
 * coalescing of concurrent refresh requests. The TS client adds a TTL
 * (`jwksCacheTtlSeconds`) on top of the Rust semantics so long-running edge
 * workers eventually pick up rotated keys even when no kid miss occurs.
 *
 * Non-destructive replacement: a 200-with-empty-or-all-filtered response
 * preserves the existing key map; this keeps known-kid tokens verifying
 * during a flapping-endpoint outage.
 */
import { importJWK, type JWK, type KeyLike } from "jose";
import { AuthError } from "./errors.js";

interface JwksCacheState {
  keys: Map<string, KeyLike>;
  fetchedAt: number | null;
}

export interface JwksCacheConfig {
  jwksUri: string;
  cacheTtlSeconds: number;
  minRefreshIntervalSeconds: number;
  fetch: typeof fetch;
}

export class JwksCache {
  private state: JwksCacheState = { keys: new Map(), fetchedAt: null };
  private inFlight: Promise<void> | null = null;

  constructor(private readonly cfg: JwksCacheConfig) {}

  /**
   * Resolve a public key by `kid`.
   *
   * - Hit: returns the cached key, but if the cache is older than `cacheTtlSeconds`
   *   triggers a refresh first so long-running consumers eventually pick up
   *   rotated keys.
   * - Miss: triggers a refresh if past the `minRefreshIntervalSeconds`
   *   anti-DoS window; otherwise returns null without hitting the network.
   */
  async getKey(kid: string): Promise<KeyLike | null> {
    const now = Date.now();
    const ttlMs = this.cfg.cacheTtlSeconds * 1000;
    const minMs = this.cfg.minRefreshIntervalSeconds * 1000;
    const fetchedAt = this.state.fetchedAt;

    // TTL gate — proactive refresh after the cache window expires. By
    // construction TTL ≫ minRefresh, so the rate-limit window doesn't apply.
    if (fetchedAt !== null && now - fetchedAt > ttlMs) {
      await this.refresh();
    }

    const cached = this.state.keys.get(kid);
    if (cached !== undefined) return cached;

    // Miss — refresh if past the rate-limit window, else return null.
    if (this.state.fetchedAt !== null && Date.now() - this.state.fetchedAt < minMs) {
      return null;
    }
    await this.refresh();
    return this.state.keys.get(kid) ?? null;
  }

  /**
   * Force a refresh now. Multiple concurrent callers coalesce onto a single
   * network fetch; subsequent calls after that fetch resolves trigger fresh
   * fetches subject to the {@link getKey} rate-limit policy.
   */
  async refresh(): Promise<void> {
    if (this.inFlight !== null) return this.inFlight;
    this.inFlight = (async () => {
      try {
        await this.doRefresh();
      } finally {
        this.inFlight = null;
      }
    })();
    return this.inFlight;
  }

  /** Snapshot of internal state for tests. Do not use in production code. */
  _stateForTests(): { keys: Map<string, KeyLike>; fetchedAt: number | null } {
    return { keys: new Map(this.state.keys), fetchedAt: this.state.fetchedAt };
  }

  private async doRefresh(): Promise<void> {
    let resp: Response;
    try {
      resp = await this.cfg.fetch(this.cfg.jwksUri, {
        headers: { accept: "application/json" },
      });
    } catch (e) {
      // Network error — leave fetchedAt as-is so the next request can retry
      // immediately rather than waiting for the rate-limit window. We treat
      // a connectivity blip as recoverable.
      throw new AuthError("jwks_fetch_failed", asMessage(e));
    }
    if (!resp.ok) {
      // Definitive bad answer; rate-limit applies so we don't pummel a
      // misbehaving endpoint.
      this.state.fetchedAt = Date.now();
      throw new AuthError("jwks_fetch_failed", `JWKS endpoint returned ${resp.status}`);
    }
    let body: unknown;
    try {
      body = await resp.json();
    } catch (e) {
      this.state.fetchedAt = Date.now();
      throw new AuthError("jwks_fetch_failed", `JWKS body was not valid JSON: ${asMessage(e)}`);
    }

    const next = await parseJwks(body);

    // Non-destructive replacement: only swap in `next` when we actually got
    // at least one usable key. A 200 with `keys: []` (or all-filtered) keeps
    // the previous cache so existing kids still verify; an unknown-kid
    // request 401s until a healthy refresh. Always update `fetchedAt` so
    // the rate limit kicks in regardless — otherwise a flapping endpoint
    // would let an attacker pump unknown-kid tokens to retry-storm us.
    if (next.size > 0) {
      this.state.keys = next;
    }
    this.state.fetchedAt = Date.now();
  }
}

async function parseJwks(body: unknown): Promise<Map<string, KeyLike>> {
  const out = new Map<string, KeyLike>();
  if (!isJwksShape(body)) return out;
  for (const jwk of body.keys) {
    if (jwk.alg !== undefined && jwk.alg !== "RS256") continue;
    if (jwk.kty !== "RSA") continue;
    if (jwk.kid === undefined || jwk.kid === "") continue;
    try {
      const key = await importJWK(jwk, "RS256");
      // jose's importJWK can return a `Uint8Array` for symmetric secrets, but
      // RS256 always lands on a KeyLike. Guard against the union just in case.
      if (key instanceof Uint8Array) continue;
      out.set(jwk.kid, key);
    } catch {
      // Malformed individual JWK — skip silently. The endpoint is the
      // authority on key shape; we filter rather than fail the whole batch.
    }
  }
  return out;
}

function isJwksShape(body: unknown): body is { keys: JWK[] } {
  return (
    typeof body === "object" &&
    body !== null &&
    "keys" in body &&
    Array.isArray((body as { keys: unknown }).keys)
  );
}

function asMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}
