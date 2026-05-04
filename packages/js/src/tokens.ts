/**
 * Token storage backends.
 *
 * Two implementations ship at v1:
 * - {@link createMemoryStore} — closure-scoped, gone on tab close. Default.
 * - {@link createSessionStore} — `sessionStorage` for access + id token,
 *   in-memory for refresh token (refresh stays out of any web-storage
 *   surface that survives a reload, per spec §5.2).
 *
 * `localStorage` is intentionally not offered — refresh tokens leaking
 * via XSS to a long-lived store is the threat we're avoiding.
 *
 * Custom adapters (Epic h6d.2) consume the same `TokenStore` interface
 * via `ClientConfig.storage`.
 */

const KEY = "allowthem:tokens";

/**
 * In-memory token state.
 */
export interface TokenSet {
  accessToken: string;
  idToken: string;
  refreshToken?: string;
  /** Epoch ms — when the access token expires. */
  expiresAt: number;
}

/**
 * Storage interface for token sets.
 */
export interface TokenStore {
  get(): TokenSet | null;
  put(t: TokenSet): void;
  clear(): void;
}

/**
 * In-memory store. Tokens never touch web storage. This is the default —
 * appropriate for SPAs that only need a session within the current tab.
 */
export function createMemoryStore(): TokenStore {
  let current: TokenSet | null = null;
  return {
    get: () => current,
    put: (t: TokenSet): void => {
      current = t;
    },
    clear: (): void => {
      current = null;
    },
  };
}

/**
 * sessionStorage-backed store. Persists `accessToken`, `idToken`,
 * `expiresAt` across reloads within the tab; the refresh token stays
 * in memory and is lost on reload. After reload, the access token is
 * still valid (until expiry); the refresh path is unavailable until
 * the next interactive login.
 */
export function createSessionStore(): TokenStore {
  let refresh: string | undefined;
  return {
    get(): TokenSet | null {
      const raw = sessionStorage.getItem(KEY);
      if (!raw) return null;
      let persisted: Omit<TokenSet, "refreshToken">;
      try {
        const parsed = JSON.parse(raw) as unknown;
        if (
          !parsed ||
          typeof parsed !== "object" ||
          typeof (parsed as { accessToken?: unknown }).accessToken !== "string"
        ) {
          return null;
        }
        persisted = parsed as Omit<TokenSet, "refreshToken">;
      } catch {
        return null;
      }
      return refresh !== undefined
        ? { ...persisted, refreshToken: refresh }
        : persisted;
    },
    put(t: TokenSet): void {
      const { refreshToken, ...persisted } = t;
      sessionStorage.setItem(KEY, JSON.stringify(persisted));
      refresh = refreshToken;
    },
    clear(): void {
      sessionStorage.removeItem(KEY);
      refresh = undefined;
    },
  };
}
