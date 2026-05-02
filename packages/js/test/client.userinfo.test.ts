import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createAllowthemClient } from "../src/client.js";
import type { ClientConfig } from "../src/types.js";

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

const idTokenClaims = {
  iss: "https://acme.allowthem.io",
  sub: "user-1",
  aud: "ath_test",
  exp: NOW_S + 3600,
  iat: NOW_S,
  nonce: "n",
  email: "u@example.com",
  email_verified: true,
};

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
      id_token: makeIdToken(idTokenClaims),
      scope: "openid",
    }),
  });
  const client = createAllowthemClient(config);
  await client.handleRedirectCallback();
  return client;
}

describe("getUser", () => {
  it("returns null when no session exists", async () => {
    const client = createAllowthemClient(config);
    expect(await client.getUser()).toBeNull();
  });

  it("calls /oauth/userinfo with the bearer token and returns the JSON body", async () => {
    const client = await loggedIn();
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ sub: "user-1", email: "u@example.com", custom: "x" }),
    });

    const user = await client.getUser();
    expect(user).toEqual({ sub: "user-1", email: "u@example.com", custom: "x" });

    const [url, init] = fetchSpy.mock.calls[1]!;
    expect(url).toBe("https://acme.allowthem.io/oauth/userinfo");
    expect((init as RequestInit).headers).toMatchObject({
      authorization: "Bearer at-1",
    });
  });

  it("falls back to id_token claims when userinfo returns 401", async () => {
    const client = await loggedIn();
    fetchSpy.mockResolvedValueOnce({
      ok: false,
      status: 401,
      json: async () => ({}),
    });

    const user = await client.getUser();
    expect(user?.sub).toBe("user-1");
    expect(user?.email).toBe("u@example.com");
  });

  it("falls back to id_token claims on network error", async () => {
    const client = await loggedIn();
    fetchSpy.mockRejectedValueOnce(new TypeError("network"));

    const user = await client.getUser();
    expect(user?.sub).toBe("user-1");
  });
});
