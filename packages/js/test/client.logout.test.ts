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

function setLocation(search: string): { assignSpy: ReturnType<typeof vi.fn> } {
  const assignSpy = vi.fn();
  Object.defineProperty(window, "location", {
    value: { search, pathname: "/callback", assign: assignSpy },
    writable: true,
  });
  Object.defineProperty(window.history, "replaceState", {
    value: vi.fn(),
    writable: true,
    configurable: true,
  });
  return { assignSpy };
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
      }),
      scope: "openid",
    }),
  });
  const client = createAllowthemClient(config);
  await client.handleRedirectCallback();
  return client;
}

describe("logout", () => {
  it("clears the token store", async () => {
    const client = await loggedIn();
    expect(client.isAuthenticated()).toBe(true);
    await client.logout();
    expect(client.isAuthenticated()).toBe(false);
  });

  it("removes any pending transactions from sessionStorage", async () => {
    const client = await loggedIn();
    sessionStorage.setItem(
      TXN_KEY,
      JSON.stringify({ leftover: { codeVerifier: "x" } }),
    );
    await client.logout();
    expect(sessionStorage.getItem(TXN_KEY)).toBeNull();
  });

  it("does not navigate without returnTo", async () => {
    const client = await loggedIn();
    const { assignSpy } = setLocation("");
    await client.logout();
    expect(assignSpy).not.toHaveBeenCalled();
  });

  it("navigates to returnTo when supplied", async () => {
    const client = await loggedIn();
    const { assignSpy } = setLocation("");
    await client.logout({ returnTo: "https://app.example/bye" });
    expect(assignSpy).toHaveBeenCalledWith("https://app.example/bye");
  });
});
