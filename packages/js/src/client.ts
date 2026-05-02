/**
 * `@allowthem/js` browser client.
 *
 * The exported `createAllowthemClient` returns an {@link AllowthemClient}
 * configured for one tenant + one OIDC application. Subsequent steps in
 * the build progressively add `handleRedirectCallback`, `getAccessToken`,
 * `getUser`, `logout`. This file is mutated across multiple commits;
 * each handler lands as its own atomic change.
 */

import { AuthError } from "./errors.js";
import {
  generateChallenge,
  generateRandomString,
  generateVerifier,
} from "./pkce.js";
import { storeTransaction, sweepStaleTransactions } from "./transactions.js";
import {
  createMemoryStore,
  createSessionStore,
  type TokenStore,
} from "./tokens.js";
import type {
  AllowthemClient,
  ClientConfig,
  LoginOptions,
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
  // tokenEndpoint and userinfoEndpoint will land with subsequent steps.

  const skewSeconds = config.expirySkewSeconds ?? DEFAULT_SKEW_SECONDS;
  const store: TokenStore =
    config.storage === "session" ? createSessionStore() : createMemoryStore();

  // The skew is wired in as later steps add getAccessToken; reference it
  // here so TS doesn't drop it on the floor before then.
  void skewSeconds;
  void store;

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
    // NB (review): the allowthem authorize endpoint does not currently
    // parse `audience` or `prompt`; serde silently ignores unknown query
    // fields, so sending them is forward-compat — no effect today.
    if (config.audience) url.searchParams.set("audience", config.audience);
    if (opts?.prompt) url.searchParams.set("prompt", opts.prompt);

    window.location.assign(url.toString());
    // The page navigates away; the returned Promise never resolves so
    // callers can `await loginWithRedirect()` without falling through.
    return new Promise<never>(() => {});
  }

  return {
    loginWithRedirect,
    handleRedirectCallback: stub("handleRedirectCallback"),
    isAuthenticated: stub("isAuthenticated"),
    getUser: stub("getUser"),
    getAccessToken: stub("getAccessToken"),
    logout: stub("logout"),
  };
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

function stub<T>(name: string): () => T {
  return () => {
    throw new AuthError("invalid_response", `${name} not yet implemented`);
  };
}
