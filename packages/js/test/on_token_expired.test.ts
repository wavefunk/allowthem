import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { AuthError } from "../src/errors.js";
import { createAllowthemClient } from "../src/client.js";
import type { ClientConfig } from "../src/types.js";
import { installFifoLocks } from "./_helpers/cross_tab_stubs.js";

const TXN_KEY = "allowthem:txn";

const baseConfig: ClientConfig = {
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
    redirectUri: baseConfig.redirectUri,
    scope: "openid",
    appState: null,
    createdAt: Date.now(),
  };
  sessionStorage.setItem(TXN_KEY, JSON.stringify({ [state]: txn }));
}

const NOW_S = Math.floor(Date.now() / 1000);

let fetchSpy: ReturnType<typeof vi.fn>;
let uninstallLocks: (() => void) | null = null;

beforeEach(() => {
  sessionStorage.clear();
  fetchSpy = vi.fn();
  Object.defineProperty(globalThis, "fetch", {
    value: fetchSpy,
    writable: true,
    configurable: true,
  });
  uninstallLocks = installFifoLocks();
});

afterEach(() => {
  vi.restoreAllMocks();
  uninstallLocks?.();
  uninstallLocks = null;
});

async function loggedInClient(config: ClientConfig = baseConfig) {
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
  return client;
}

function mockRefreshFailure(): void {
  fetchSpy.mockResolvedValueOnce({
    ok: false,
    status: 400,
    json: async () => ({ error: "invalid_grant", error_description: "rotated" }),
  });
}

describe("onTokenExpired — default behaviour (no callback)", () => {
  it("clears state, emits error+logout, rethrows the original AuthError", async () => {
    const client = await loggedInClient();
    mockRefreshFailure();

    const errEvents: Array<{ code: string }> = [];
    const logoutEvents: Array<{ reason: string }> = [];
    client.on("error", (e) => errEvents.push(e));
    client.on("logout", (e) => logoutEvents.push(e));

    await expect(client.getAccessToken()).rejects.toMatchObject({
      code: "invalid_grant",
    });

    expect(client.isAuthenticated()).toBe(false);
    expect(errEvents).toContainEqual(
      expect.objectContaining({ code: "invalid_grant" }),
    );
    expect(logoutEvents).toContainEqual({ reason: "expired" });
  });
});

describe("onTokenExpired — override callback", () => {
  it("invokes callback with the AuthError; cleanup still runs after", async () => {
    const onTokenExpired = vi.fn(async () => {
      // No-op: app would typically navigate to /login here.
    });
    const client = await loggedInClient({ ...baseConfig, onTokenExpired });
    mockRefreshFailure();

    await expect(client.getAccessToken()).rejects.toMatchObject({
      code: "invalid_grant",
    });

    expect(onTokenExpired).toHaveBeenCalledTimes(1);
    const call = onTokenExpired.mock.calls[0];
    expect(call).toBeDefined();
    const arg = (call as unknown as [unknown])[0];
    expect(arg).toBeInstanceOf(AuthError);
    expect((arg as AuthError).code).toBe("invalid_grant");
    expect(client.isAuthenticated()).toBe(false);
  });

  it("awaits async callback before clearing state", async () => {
    let resolveCallback: (() => void) | null = null;
    let callbackEntered!: () => void;
    const callbackEnteredP = new Promise<void>((r) => {
      callbackEntered = r;
    });
    const onTokenExpired = vi.fn(async () => {
      await new Promise<void>((r) => {
        resolveCallback = r;
        callbackEntered();
      });
    });
    const client = await loggedInClient({ ...baseConfig, onTokenExpired });
    expect(client.isAuthenticated()).toBe(true);
    mockRefreshFailure();

    const p = client.getAccessToken().catch((e) => e);
    await callbackEnteredP;
    // Callback is suspended; cleanup hasn't run yet.
    expect(client.isAuthenticated()).toBe(true);

    resolveCallback!();
    await p;
    expect(client.isAuthenticated()).toBe(false);
  });

  it("recovers if the callback throws — cleanup still runs", async () => {
    const onTokenExpired = vi.fn(() => {
      throw new Error("user code blew up");
    });
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const client = await loggedInClient({ ...baseConfig, onTokenExpired });
    mockRefreshFailure();

    await expect(client.getAccessToken()).rejects.toMatchObject({
      code: "invalid_grant",
    });
    expect(client.isAuthenticated()).toBe(false);
    expect(errSpy).toHaveBeenCalled();
    errSpy.mockRestore();
  });
});
