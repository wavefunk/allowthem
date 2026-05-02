/**
 * Public TypeScript types for `@allowthem/js`.
 *
 * This module is type-only — no runtime code, no side effects. Imported by
 * consumers who want to ship typed configuration without bringing in the
 * full SDK runtime.
 */

/**
 * Construction-time configuration for {@link createAllowthemClient}.
 */
export interface ClientConfig {
  /**
   * Tenant host without scheme or trailing slash. e.g. `"acme.allowthem.io"`.
   * Throws `AuthError("config_error", ...)` if it includes `http://` or `https://`.
   */
  domain: string;

  /**
   * OIDC client_id for the registered application.
   */
  clientId: string;

  /**
   * Default redirect URI. Must match one of the application's registered
   * redirect URIs on the server. Can be overridden per call to
   * {@link AllowthemClient.loginWithRedirect}.
   */
  redirectUri: string;

  /**
   * Default scope. If unset, the SDK uses
   * `"openid profile email offline_access"`. The `offline_access` scope
   * requests a refresh token; required to keep sessions alive past the
   * access-token TTL.
   */
  scope?: string;

  /**
   * Optional `audience` parameter included in the authorize request. The
   * allowthem authorize endpoint silently ignores unknown query params
   * today; this is forward-compat for future audience-based scoping.
   */
  audience?: string;

  /**
   * Where to keep tokens. Default `"memory"` — gone on tab close.
   * `"session"` persists access + id tokens in `sessionStorage` (refresh
   * token stays in memory regardless, per spec §5.2).
   */
  storage?: "memory" | "session";

  /**
   * How many seconds before `expiresAt` to treat the token as expired
   * and trigger a refresh. Default 60.
   */
  expirySkewSeconds?: number;

  /**
   * Hook fired when a token refresh fails (typically `invalid_grant`
   * because the refresh token rotated out from another tab). The
   * callback runs *before* the SDK clears local state and emits
   * `'logout'`; cleanup always happens regardless of what the callback
   * does. Use it to redirect the user to a re-login flow or show a
   * "session expired" banner — but don't try to recover here, the SDK
   * is already fail-closed.
   */
  onTokenExpired?: (err: import("./errors.js").AuthError) => void | Promise<void>;
}

/**
 * Per-call options for {@link AllowthemClient.loginWithRedirect}.
 */
export interface LoginOptions {
  /**
   * Arbitrary state restored on the post-callback `handleRedirectCallback`
   * resolution. Use to remember which page the user came from, etc.
   */
  appState?: unknown;

  /**
   * Override the default scope for this login call.
   */
  scope?: string;

  /**
   * Override the default redirect URI for this login call.
   */
  redirectUri?: string;

  /**
   * OIDC `prompt` parameter. Forwarded to the authorize endpoint as-is;
   * silently ignored by the current allowthem authorize endpoint. Future
   * support is forward-compat.
   */
  prompt?: "none" | "login" | "consent" | "select_account";
}

/**
 * Per-call options for {@link AllowthemClient.logout}.
 */
export interface LogoutOptions {
  /**
   * If supplied, the SDK navigates to this URL after clearing local state.
   * Without it, logout is silent (the caller decides what happens next).
   */
  returnTo?: string;
}

/**
 * Standard OIDC user claims returned by the userinfo endpoint or parsed
 * from the id_token. Custom claims pass through unchanged via the index
 * signature.
 */
export interface UserClaims {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  picture?: string;
  [k: string]: unknown;
}

/**
 * Raw token response from `POST /oauth/token`.
 */
export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token?: string;
  id_token: string;
  scope?: string;
}

/**
 * The browser auth client. Created via {@link createAllowthemClient}.
 */
export interface AllowthemClient {
  /**
   * Subscribe to a lifecycle event. Returns an unsubscribe function.
   * Events: `'login' | 'logout' | 'token_refreshed' | 'error'`.
   */
  on<E extends import("./events.js").EventName>(
    event: E,
    handler: import("./events.js").EventHandler<E>,
  ): () => void;

  /**
   * Redirect the browser to the authorize endpoint with PKCE parameters.
   * Resolves never — the page navigates away.
   */
  loginWithRedirect(options?: LoginOptions): Promise<never>;

  /**
   * Process the authorize-callback query parameters, exchange the code
   * for tokens, validate the id_token, and store the result.
   *
   * @returns `{ appState }` — the value passed in to the matching
   * `loginWithRedirect` call, or `null` if none was provided.
   */
  handleRedirectCallback(): Promise<{ appState: unknown }>;

  /**
   * Whether the client currently holds a (non-expired-from-its-pov)
   * token set. Synchronous; does not refresh.
   */
  isAuthenticated(): boolean;

  /**
   * Best-effort fetch of the current user. Calls userinfo if a valid
   * access token is available; falls back to id_token claims on network
   * error or 401. Returns `null` if no session exists.
   */
  getUser(): Promise<UserClaims | null>;

  /**
   * Returns a current access token, refreshing if necessary. Throws
   * `AuthError("login_required", ...)` if no session exists or refresh
   * fails without recovery.
   */
  getAccessToken(): Promise<string>;

  /**
   * Clear local token state. Optionally navigate to `returnTo`.
   * Local-only — does not call any server-side end-session endpoint.
   */
  logout(options?: LogoutOptions): Promise<void>;
}
