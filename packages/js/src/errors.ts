/**
 * Error types thrown by the SDK.
 *
 * `AuthError` is the only thrown type; every public SDK method that can
 * fail throws this. The `code` is either an SDK-defined constant
 * (see {@link ERROR_CODES}) or an OIDC standard error code passed
 * through unchanged from the server (e.g. `"invalid_grant"`).
 */

/**
 * SDK-defined error codes. OIDC standard codes (e.g. `"access_denied"`,
 * `"invalid_grant"`) are passed through unchanged from the authorization
 * server, so they are not enumerated here.
 */
export const ERROR_CODES = {
  /** State parameter missing, mismatched, or did not correspond to a pending login. */
  INVALID_STATE: "invalid_state",
  /** Response shape was invalid (e.g. missing both code and error). */
  INVALID_RESPONSE: "invalid_response",
  /** id_token failed claim validation (iss/aud/exp/nonce/format). */
  INVALID_ID_TOKEN: "invalid_id_token",
  /** No active session, or refresh failed and no recovery is available. */
  LOGIN_REQUIRED: "login_required",
  /** SDK construction-time configuration is invalid. */
  CONFIG_ERROR: "config_error",
} as const;

/**
 * The set of allowed `code` values. Loose-typed so OIDC standard codes
 * pass through (e.g. the token endpoint returning `error: "invalid_grant"`).
 */
export type AuthErrorCode = string;

/**
 * The single error type thrown by every public SDK method.
 *
 * `code` is either a constant from {@link ERROR_CODES} or an OIDC standard
 * error code from the authorization server. `description` is for logs and
 * developer-facing UI; never contains tokens or signatures.
 *
 * `appState` is populated only on errors that surface from
 * `handleRedirectCallback` for an OIDC error response (e.g. the user
 * cancelled at the consent screen) — it carries the `appState` value the
 * caller passed into `loginWithRedirect`, allowing UI restoration.
 */
export class AuthError extends Error {
  readonly code: AuthErrorCode;
  readonly description?: string;
  readonly appState?: unknown;

  constructor(code: AuthErrorCode, description?: string, appState?: unknown) {
    super(description ? `${code}: ${description}` : code);
    this.name = "AuthError";
    this.code = code;
    if (description !== undefined) this.description = description;
    if (appState !== undefined) this.appState = appState;
  }
}
