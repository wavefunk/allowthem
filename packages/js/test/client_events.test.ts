import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createAllowthemClient } from "../src/client.js";
import type { ClientConfig, UserClaims } from "../src/types.js";

const TXN_KEY = "allowthem:txn";

const config: ClientConfig = {
  domain: "acme.allowthem.io",
  clientId: "ath_test",
  redirectUri: "https://app.example/callback",
};

function base64urlEncode(s: string): string {
  return btoa(unescape(encodeURIComponent(s)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function makeIdToken(claims: Record<string, unknown>): string {
  const header = base64urlEncode(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const body = base64urlEncode(JSON.stringify(claims));
  return `${header}.${body}.fake-signature`;
}

function setLocation(search: string): void {
  Object.defineProperty(window, "location", {
    value: { search, pathname: "/callback", assign: () => {} },
    writable: true,
  });
  Object.defineProperty(window.history, "replaceState", {
    value: vi.fn(),
    writable: true,
    configurable: true,
  });
}

const NOW_S = Math.floor(Date.now() / 1000);
let fetchSpy: ReturnType<typeof vi.fn>;

interface TestTxn {
  codeVerifier: string;
  nonce: string;
  redirectUri: string;
  scope: string;
  appState: unknown;
  createdAt: number;
}

function seedTxn(state: string, nonce: string): void {
  const txn: TestTxn = {
    codeVerifier: "v",
    nonce,
    redirectUri: config.redirectUri,
    scope: "openid",
    appState: null,
    createdAt: Date.now(),
  };
  sessionStorage.setItem(TXN_KEY, JSON.stringify({ [state]: txn }));
}

beforeEach(() => {
  sessionStorage.clear();
  fetchSpy = vi.fn();
  Object.defineProperty(globalThis, "fetch", {
    value: fetchSpy,
    writable: true,
    configurable: true,
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function loggedIn() {
  seedTxn("st", "n");
  setLocation("?code=abc&state=st");
  fetchSpy.mockResolvedValueOnce({
    ok: true,
    json: async () => ({
      access_token: "at-1",
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: "rt-1",
      id_token: makeIdToken({
        iss: "https://acme.allowthem.io",
        sub: "user-1",
        aud: "ath_test",
        exp: NOW_S + 3600,
        iat: NOW_S,
        nonce: "n",
        email: "u@example.com",
        email_verified: true,
      }),
      scope: "openid",
    }),
  });
  const client = createAllowthemClient(config);
  await client.handleRedirectCallback();
  return client;
}

describe("client lifecycle events", () => {
  it("emits 'login' after a successful handleRedirectCallback", async () => {
    seedTxn("st", "n");
    setLocation("?code=abc&state=st");
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        access_token: "at-1",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "rt-1",
        id_token: makeIdToken({
          iss: "https://acme.allowthem.io",
          sub: "user-99",
          aud: "ath_test",
          exp: NOW_S + 3600,
          iat: NOW_S,
          nonce: "n",
        }),
        scope: "openid",
      }),
    });

    const client = createAllowthemClient(config);
    const handler = vi.fn<[{ user: UserClaims }], void>();
    client.on("login", handler);

    await client.handleRedirectCallback();

    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler.mock.calls[0]![0].user.sub).toBe("user-99");
  });

  it("emits 'logout' with reason 'user' after client.logout()", async () => {
    const client = await loggedIn();
    const handler = vi.fn();
    client.on("logout", handler);

    await client.logout();

    expect(handler).toHaveBeenCalledWith({ reason: "user" });
    // Subscriber sees post-clear state.
    expect(client.isAuthenticated()).toBe(false);
  });

  it("emits 'token_refreshed' when getAccessToken triggers a refresh", async () => {
    seedTxn("st", "n");
    setLocation("?code=abc&state=st");
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        access_token: "at-1",
        token_type: "Bearer",
        expires_in: 1, // immediately stale
        refresh_token: "rt-1",
        id_token: makeIdToken({
          iss: "https://acme.allowthem.io",
          sub: "user-1",
          aud: "ath_test",
          exp: NOW_S + 3600,
          iat: NOW_S,
          nonce: "n",
        }),
        scope: "openid",
      }),
    });
    const client = createAllowthemClient(config);
    await client.handleRedirectCallback();

    const handler = vi.fn();
    client.on("token_refreshed", handler);

    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        access_token: "at-2",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "rt-2",
        id_token: makeIdToken({
          iss: "https://acme.allowthem.io",
          sub: "user-1",
          aud: "ath_test",
          exp: NOW_S + 7200,
          iat: NOW_S,
        }),
        scope: "openid",
      }),
    });

    await client.getAccessToken();
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler.mock.calls[0]![0].expiresAt).toBeTypeOf("number");
  });

  it("returned unsubscribe stops further deliveries", async () => {
    const client = await loggedIn();
    const handler = vi.fn();
    const off = client.on("logout", handler);
    off();
    await client.logout();
    expect(handler).not.toHaveBeenCalled();
  });
});
