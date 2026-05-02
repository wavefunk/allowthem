/**
 * `@allowthem/js` browser client.
 *
 * The exported `createAllowthemClient` returns an {@link AllowthemClient}
 * configured for one tenant + one OIDC application. Subsequent steps in
 * the build progressively add `getAccessToken`, `getUser`, `logout`.
 */

import { refreshAcrossTabs } from "./cross_tab.js";
import { AuthError } from "./errors.js";
import { EventEmitter } from "./events.js";
import { parseIdTokenClaims, validateIdToken } from "./idtoken.js";
import { ProactiveTimer } from "./proactive.js";
import {
  generateChallenge,
  generateRandomString,
  generateVerifier,
} from "./pkce.js";
import {
  popTransaction,
  storeTransaction,
  sweepStaleTransactions,
} from "./transactions.js";
import {
  createMemoryStore,
  createSessionStore,
  type TokenStore,
} from "./tokens.js";
import type {
  AllowthemClient,
  ClientConfig,
  LoginOptions,
  LogoutOptions,
  TokenResponse,
  UserClaims,
} from "./types.js";

const DEFAULT_SCOPE = "openid profile email offline_access";
const DEFAULT_SKEW_SECONDS = 60;

/**
 * Build a browser auth client for the given tenant.
 *
 * @example
 * ```ts
 * const auth = createAllowthemClient({
 *   domain: "acme.allowthem.io",
 *   clientId: "ath_xxx",
 *   redirectUri: window.location.origin + "/callback",
 * });
 * await auth.loginWithRedirect();
 * ```
 *
 * @throws {AuthError} `config_error` if `domain` includes a scheme,
 * or required fields are missing.
 */
export function createAllowthemClient(config: ClientConfig): AllowthemClient {
  validateConfig(config);
  sweepStaleTransactions();

  const issuer = `https://${config.domain}`;
  const authorizeEndpoint = `${issuer}/oauth/authorize`;
  const tokenEndpoint = `${issuer}/oauth/token`;
  const userinfoEndpoint = `${issuer}/oauth/userinfo`;

  const skewSeconds = config.expirySkewSeconds ?? DEFAULT_SKEW_SECONDS;
  const store: TokenStore = resolveStore(config.storage);

  const events = new EventEmitter();
  const proactive = new ProactiveTimer();

  // In-tab single-flight: concurrent getAccessToken calls during a refresh
  // share one Promise so only one POST /oauth/token fires. Cross-tab
  // coalescing lands in h6d.2.
  let inFlight: Promise<TokenSetState> | null = null;

  interface TokenSetState {
    accessToken: string;
    idToken: string;
    refreshToken?: string;
    expiresAt: number;
  }

  async function loginWithRedirect(opts?: LoginOptions): Promise<never> {
    const codeVerifier = generateVerifier();
    const codeChallenge = await generateChallenge(codeVerifier);
    const state = generateRandomString();
    const nonce = generateRandomString();

    const redirectUri = opts?.redirectUri ?? config.redirectUri;
    const scope = opts?.scope ?? config.scope ?? DEFAULT_SCOPE;

    storeTransaction(state, {
      codeVerifier,
      nonce,
      redirectUri,
      scope,
      appState: opts?.appState ?? null,
      createdAt: Date.now(),
    });

    const url = new URL(authorizeEndpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", config.clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("scope", scope);
    url.searchParams.set("state", state);
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    // NB: the allowthem authorize endpoint does not currently parse
    // `audience` or `prompt`; serde silently ignores unknown query
    // fields, so sending them is forward-compat — no effect today.
    if (config.audience) url.searchParams.set("audience", config.audience);
    if (opts?.prompt) url.searchParams.set("prompt", opts.prompt);

    window.location.assign(url.toString());
    // The page navigates away; the returned Promise never resolves so
    // callers can `await loginWithRedirect()` without falling through.
    return new Promise<never>(() => {});
  }

  async function handleRedirectCallback(): Promise<{ appState: unknown }> {
    const params = new URLSearchParams(window.location.search);
    const stateFromUrl = params.get("state");
    if (!stateFromUrl) {
      throw new AuthError("invalid_state", "missing state parameter");
    }

    if (params.has("error")) {
      const code = params.get("error")!;
      const description = params.get("error_description") ?? undefined;
      const txn = popTransaction(stateFromUrl);
      // Without a matching transaction, surface invalid_state instead of the
      // attacker-supplied `error` code — prevents an attacker from steering
      // the caller's error-handling branch via a forged redirect.
      if (!txn) {
        throw new AuthError("invalid_state", "state did not match any pending login");
      }
      cleanQueryString();
      throw new AuthError(code, description, txn.appState);
    }

    const code = params.get("code");
    if (!code) {
      throw new AuthError("invalid_response", "neither code nor error in callback");
    }

    const txn = popTransaction(stateFromUrl);
    if (!txn) {
      throw new AuthError("invalid_state", "state did not match any pending login");
    }

    const tokens = await tokenExchange({
      grantType: "authorization_code",
      code,
      codeVerifier: txn.codeVerifier,
      redirectUri: txn.redirectUri,
    });

    validateIdToken(tokens.id_token, {
      issuer,
      clientId: config.clientId,
      nonce: txn.nonce,
    });

    const stored = {
      accessToken: tokens.access_token,
      idToken: tokens.id_token,
      ...(tokens.refresh_token !== undefined
        ? { refreshToken: tokens.refresh_token }
        : {}),
      expiresAt: Date.now() + tokens.expires_in * 1000,
    };
    store.put(stored);
    rescheduleProactive(stored.expiresAt);

    // h6d.1 already ran validateIdToken above, so id_token is guaranteed
    // present and parseable here.
    const claims = parseIdTokenClaims(tokens.id_token);
    events.emit("login", { user: claims as unknown as UserClaims });

    cleanQueryString();
    return { appState: txn.appState };
  }

  /**
   * (Re-)schedule the proactive timer when `proactiveRefresh: true`.
   * No-op otherwise.
   */
  function rescheduleProactive(expiresAt: number): void {
    if (!config.proactiveRefresh) return;
    const skewMs = skewSeconds * 1000;
    const ms = expiresAt - Date.now() - skewMs;
    proactive.schedule(ms, () => {
      // Fire-and-forget. Errors route through handleRefreshFailure
      // (proactive source: no caller to rethrow to).
      void (async () => {
        try {
          if (!inFlight) {
            inFlight = (async () => {
              try {
                return await refreshAcrossTabs({
                  store,
                  expirySkewMs: skewMs,
                  refreshOnce,
                });
              } finally {
                inFlight = null;
              }
            })();
          }
          await inFlight;
        } catch (err) {
          if (err instanceof AuthError) {
            await handleRefreshFailure(err, "proactive");
          }
        }
      })();
    });
  }

  interface TokenExchangeArgs {
    grantType: "authorization_code" | "refresh_token";
    code?: string;
    codeVerifier?: string;
    redirectUri?: string;
    refreshToken?: string;
  }

  async function tokenExchange(args: TokenExchangeArgs): Promise<TokenResponse> {
    const body = new URLSearchParams();
    body.set("grant_type", args.grantType);
    body.set("client_id", config.clientId);
    if (args.grantType === "authorization_code") {
      body.set("code", args.code!);
      body.set("code_verifier", args.codeVerifier!);
      body.set("redirect_uri", args.redirectUri!);
    } else {
      body.set("refresh_token", args.refreshToken!);
    }

    const resp = await fetch(tokenEndpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
      credentials: "omit",
    });

    if (!resp.ok) {
      let payload: { error?: string; error_description?: string } = {};
      try {
        payload = (await resp.json()) as typeof payload;
      } catch {
        // body was empty / non-JSON; payload stays empty.
      }
      throw new AuthError(
        payload.error ?? `http_${resp.status}`,
        payload.error_description ?? `token endpoint returned ${resp.status}`,
      );
    }

    return (await resp.json()) as TokenResponse;
  }

  function isAuthenticated(): boolean {
    return store.get() !== null;
  }

  async function getAccessToken(): Promise<string> {
    const tokens = store.get();
    if (!tokens) {
      throw new AuthError("login_required", "no active session");
    }
    const skewMs = skewSeconds * 1000;
    if (Date.now() < tokens.expiresAt - skewMs) {
      return tokens.accessToken;
    }
    if (!tokens.refreshToken) {
      throw new AuthError(
        "login_required",
        "access token expired and no refresh_token",
      );
    }
    // In-tab single-flight wraps the entire cross-tab path so concurrent
    // in-tab callers join one promise — no per-caller BroadcastChannel
    // election overhead, no five POSTs racing the lock.
    if (!inFlight) {
      inFlight = (async () => {
        try {
          return await refreshAcrossTabs({
            store,
            expirySkewMs: skewMs,
            refreshOnce,
          });
        } finally {
          inFlight = null;
        }
      })();
    }
    try {
      const fresh = await inFlight;
      return fresh.accessToken;
    } catch (err) {
      if (err instanceof AuthError) {
        await handleRefreshFailure(err, "ondemand");
      }
      throw err;
    }
  }

  /**
   * Refresh-failure handler.
   *
   * Always: emit `'error'`, run the user callback (if supplied), then
   * clear local state and emit `'logout' { reason: "expired" }`. The
   * callback runs before clear so it can read remaining state, but the
   * cleanup is fail-closed — a stale tab must not claim authenticated.
   *
   * @param source — "ondemand" rethrows the original error to the
   *   `getAccessToken` caller; "proactive" swallows (no caller).
   */
  async function handleRefreshFailure(
    err: AuthError,
    source: "ondemand" | "proactive",
  ): Promise<void> {
    events.emit("error", {
      code: err.code,
      ...(err.description !== undefined ? { description: err.description } : {}),
    });
    if (config.onTokenExpired) {
      try {
        await config.onTokenExpired(err);
      } catch (cbErr) {
        // eslint-disable-next-line no-console
        console.error("[allowthem] onTokenExpired callback threw:", cbErr);
      }
    }
    store.clear();
    inFlight = null;
    proactive.cancel();
    events.emit("logout", { reason: "expired" });
    void source; // marker for future telemetry split
  }

  async function refreshOnce(): Promise<TokenSetState> {
    const cur = store.get();
    if (!cur?.refreshToken) {
      throw new AuthError("login_required", "no refresh token");
    }
    const resp = await tokenExchange({
      grantType: "refresh_token",
      refreshToken: cur.refreshToken,
    });
    // No nonce on refresh-issued id_tokens (OIDC core: `nonce` is for
    // identity-of-this-flow; refresh doesn't restart the flow).
    validateIdToken(resp.id_token, {
      issuer,
      clientId: config.clientId,
    });
    const fresh: TokenSetState = {
      accessToken: resp.access_token,
      idToken: resp.id_token,
      ...(resp.refresh_token !== undefined
        ? { refreshToken: resp.refresh_token }
        : cur.refreshToken !== undefined
          ? { refreshToken: cur.refreshToken }
          : {}),
      expiresAt: Date.now() + resp.expires_in * 1000,
    };
    store.put(fresh);
    rescheduleProactive(fresh.expiresAt);
    events.emit("token_refreshed", { expiresAt: fresh.expiresAt });
    return fresh;
  }

  async function getUser(): Promise<UserClaims | null> {
    const tokens = store.get();
    if (!tokens) return null;
    try {
      const accessToken = await getAccessToken();
      const resp = await fetch(userinfoEndpoint, {
        headers: { authorization: `Bearer ${accessToken}` },
        credentials: "omit",
      });
      if (resp.ok) {
        return (await resp.json()) as UserClaims;
      }
      // 401 etc. — fall through to id_token claims.
    } catch {
      // Network error or refresh failure — fall through to id_token claims.
    }
    return parseIdTokenClaims(tokens.idToken) as unknown as UserClaims;
  }

  async function logout(opts?: LogoutOptions): Promise<void> {
    store.clear();
    inFlight = null;
    proactive.cancel();
    sessionStorage.removeItem("allowthem:txn");
    // Emit AFTER clear so a handler that calls isAuthenticated() / getUser()
    // sees the post-logout state.
    events.emit("logout", { reason: "user" });
    if (opts?.returnTo) {
      window.location.assign(opts.returnTo);
    }
  }

  return {
    on: events.on.bind(events),
    loginWithRedirect,
    handleRedirectCallback,
    isAuthenticated,
    getUser,
    getAccessToken,
    logout,
  };
}

function resolveStore(
  storage: ClientConfig["storage"],
): TokenStore {
  if (storage === undefined || storage === "memory") return createMemoryStore();
  if (storage === "session") return createSessionStore();
  if (isTokenStore(storage)) return storage;
  throw new AuthError("config_error", "invalid storage");
}

function isTokenStore(v: unknown): v is TokenStore {
  if (typeof v !== "object" || v === null) return false;
  const o = v as { get?: unknown; put?: unknown; clear?: unknown };
  return (
    typeof o.get === "function" &&
    typeof o.put === "function" &&
    typeof o.clear === "function"
  );
}

function validateConfig(c: ClientConfig): void {
  if (!c.domain) {
    throw new AuthError("config_error", "domain is required");
  }
  if (c.domain.startsWith("http://") || c.domain.startsWith("https://")) {
    throw new AuthError("config_error", "domain must not include a scheme");
  }
  if (!c.clientId) throw new AuthError("config_error", "clientId is required");
  if (!c.redirectUri) {
    throw new AuthError("config_error", "redirectUri is required");
  }
}

function cleanQueryString(): void {
  // Strip the auth callback params so they don't survive a refresh and
  // don't leak via the address bar.
  window.history.replaceState({}, "", window.location.pathname);
}

