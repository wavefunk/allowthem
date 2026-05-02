import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { AuthError } from "../src/errors.js";
import { createAllowthemClient } from "../src/client.js";
import type { ClientConfig } from "../src/types.js";

const TXN_KEY = "allowthem:txn";

const config: ClientConfig = {
  domain: "acme.allowthem.io",
  clientId: "ath_test",
  redirectUri: "https://app.example/callback",
};

interface TestTxn {
  codeVerifier: string;
  nonce: string;
  redirectUri: string;
  scope: string;
  appState: unknown;
  createdAt: number;
}

function seedTransaction(state: string, nonce: string, appState: unknown = null): void {
  const txn: TestTxn = {
    codeVerifier: "test-verifier",
    nonce,
    redirectUri: config.redirectUri,
    scope: "openid",
    appState,
    createdAt: Date.now(),
  };
  sessionStorage.setItem(TXN_KEY, JSON.stringify({ [state]: txn }));
}

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

function setLocation(search: string, hash = ""): void {
  Object.defineProperty(window, "location", {
    value: { search, pathname: "/callback", hash, assign: () => {} },
    writable: true,
  });
  // Prevent jsdom's history navigation from throwing on replaceState
  // with the synthetic location.
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

function mockTokenResponse(idToken: string): void {
  fetchSpy.mockResolvedValue({
    ok: true,
    json: async () => ({
      access_token: "at-1",
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: "rt-1",
      id_token: idToken,
      scope: "openid",
    }),
  });
}

describe("handleRedirectCallback — happy path", () => {
  it("exchanges the code, validates id_token, stores tokens, returns appState", async () => {
    seedTransaction("st1", "n1", { from: "/dashboard" });
    setLocation("?code=abc&state=st1");
    const idToken = makeIdToken({
      iss: "https://acme.allowthem.io",
      sub: "user-1",
      aud: "ath_test",
      exp: NOW_S + 3600,
      iat: NOW_S,
      nonce: "n1",
    });
    mockTokenResponse(idToken);

    const client = createAllowthemClient(config);
    const result = await client.handleRedirectCallback();

    expect(result.appState).toEqual({ from: "/dashboard" });
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    const [tokenUrl, tokenInit] = fetchSpy.mock.calls[0]!;
    expect(tokenUrl).toBe("https://acme.allowthem.io/oauth/token");

    const body = (tokenInit as RequestInit).body as URLSearchParams;
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("client_id")).toBe("ath_test");
    expect(body.get("code")).toBe("abc");
    expect(body.get("code_verifier")).toBe("test-verifier");
    expect(body.get("redirect_uri")).toBe(config.redirectUri);
    expect(body.has("client_secret")).toBe(false); // public client
  });

  it("clears the callback query string after success", async () => {
    seedTransaction("st1", "n1");
    setLocation("?code=abc&state=st1");
    const idToken = makeIdToken({
      iss: "https://acme.allowthem.io",
      sub: "user-1",
      aud: "ath_test",
      exp: NOW_S + 3600,
      iat: NOW_S,
      nonce: "n1",
    });
    mockTokenResponse(idToken);

    const client = createAllowthemClient(config);
    await client.handleRedirectCallback();
    expect(window.history.replaceState).toHaveBeenCalled();
  });
});

describe("handleRedirectCallback — error paths", () => {
  it("throws invalid_state when state is missing from callback URL", async () => {
    setLocation("?code=abc"); // no state
    const client = createAllowthemClient(config);
    await expect(client.handleRedirectCallback()).rejects.toMatchObject({
      code: "invalid_state",
    });
  });

  it("throws invalid_response when both code and error are missing", async () => {
    seedTransaction("st1", "n1");
    setLocation("?state=st1");
    const client = createAllowthemClient(config);
    await expect(client.handleRedirectCallback()).rejects.toMatchObject({
      code: "invalid_response",
    });
  });

  it("forwards OIDC error code when state matches a stored txn", async () => {
    seedTransaction("st1", "n1", { from: "/x" });
    setLocation("?error=access_denied&error_description=user+cancelled&state=st1");
    const client = createAllowthemClient(config);
    try {
      await client.handleRedirectCallback();
      throw new Error("expected throw");
    } catch (e) {
      const err = e as AuthError;
      expect(err.code).toBe("access_denied");
      expect(err.description).toContain("user");
      expect(err.appState).toEqual({ from: "/x" });
    }
  });

  it("masks attacker-supplied error code as invalid_state when state does not match", async () => {
    setLocation("?error=evil_code&state=unknown");
    const client = createAllowthemClient(config);
    await expect(client.handleRedirectCallback()).rejects.toMatchObject({
      code: "invalid_state",
    });
  });

  it("throws invalid_id_token when nonce in id_token mismatches the txn", async () => {
    seedTransaction("st1", "expected_nonce");
    setLocation("?code=abc&state=st1");
    const idToken = makeIdToken({
      iss: "https://acme.allowthem.io",
      sub: "user-1",
      aud: "ath_test",
      exp: NOW_S + 3600,
      iat: NOW_S,
      nonce: "wrong_nonce",
    });
    mockTokenResponse(idToken);

    const client = createAllowthemClient(config);
    await expect(client.handleRedirectCallback()).rejects.toMatchObject({
      code: "invalid_id_token",
    });
  });

  it("propagates invalid_grant from a 400 token response", async () => {
    seedTransaction("st1", "n1");
    setLocation("?code=abc&state=st1");
    fetchSpy.mockResolvedValue({
      ok: false,
      status: 400,
      json: async () => ({ error: "invalid_grant", error_description: "rotated" }),
    });

    const client = createAllowthemClient(config);
    await expect(client.handleRedirectCallback()).rejects.toMatchObject({
      code: "invalid_grant",
    });
  });

  it("synthesizes http_<status> when token endpoint returns no JSON", async () => {
    seedTransaction("st1", "n1");
    setLocation("?code=abc&state=st1");
    fetchSpy.mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => {
        throw new Error("not json");
      },
    });

    const client = createAllowthemClient(config);
    await expect(client.handleRedirectCallback()).rejects.toMatchObject({
      code: "http_500",
    });
  });
});

describe("handleRedirectCallback — cleanQueryString preserves location.hash", () => {
  // Regression guard: the impl-review (#27) flagged that `cleanQueryString`
  // must call `replaceState({}, "", pathname + hash)` so callers using SPA
  // hash-routing don't lose their `#section` after the auth redirect.
  it("on success — replaceState target includes hash", async () => {
    seedTransaction("st1", "n1");
    setLocation("?code=abc&state=st1", "#section");
    const idToken = makeIdToken({
      iss: "https://acme.allowthem.io",
      sub: "user-1",
      aud: "ath_test",
      exp: NOW_S + 3600,
      iat: NOW_S,
      nonce: "n1",
    });
    mockTokenResponse(idToken);

    const client = createAllowthemClient(config);
    await client.handleRedirectCallback();
    const replaceSpy = window.history.replaceState as unknown as ReturnType<typeof vi.fn>;
    expect(replaceSpy).toHaveBeenCalled();
    const target = replaceSpy.mock.calls[0]![2] as string;
    expect(target).toBe("/callback#section");
  });

  it("on OIDC error response — replaceState target includes hash", async () => {
    seedTransaction("st1", "n1");
    setLocation(
      "?error=access_denied&error_description=user-cancelled&state=st1",
      "#section",
    );

    const client = createAllowthemClient(config);
    await expect(client.handleRedirectCallback()).rejects.toMatchObject({
      code: "access_denied",
    });
    const replaceSpy = window.history.replaceState as unknown as ReturnType<typeof vi.fn>;
    expect(replaceSpy).toHaveBeenCalled();
    const target = replaceSpy.mock.calls[0]![2] as string;
    expect(target).toBe("/callback#section");
  });
});
