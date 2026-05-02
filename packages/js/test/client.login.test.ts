import { describe, it, expect, beforeEach } from "vitest";
import { AuthError } from "../src/errors.js";
import { createAllowthemClient } from "../src/client.js";
import type { ClientConfig } from "../src/types.js";

const TXN_KEY = "allowthem:txn";

const baseConfig: ClientConfig = {
  domain: "acme.allowthem.io",
  clientId: "ath_test",
  redirectUri: "https://app.example/callback",
};

let assigned: string | null;

beforeEach(() => {
  sessionStorage.clear();
  assigned = null;
  // jsdom's window.location.assign is non-overridable; replace via Object.defineProperty.
  Object.defineProperty(window, "location", {
    value: {
      assign: (url: string) => {
        assigned = url;
      },
      search: "",
      pathname: "/",
    },
    writable: true,
  });
});

async function waitForAssign(): Promise<URL> {
  // generateChallenge awaits crypto.subtle.digest, which queues real
  // microtasks. Loop until the navigation fires or we time out.
  for (let i = 0; i < 100; i++) {
    if (assigned) return new URL(assigned);
    await new Promise<void>((r) => setTimeout(r, 0));
  }
  throw new Error("loginWithRedirect did not navigate within 100 ticks");
}

describe("createAllowthemClient — config validation", () => {
  it("returns a client object on a valid config", () => {
    const client = createAllowthemClient(baseConfig);
    expect(typeof client.loginWithRedirect).toBe("function");
  });

  it("throws config_error when domain has a scheme", () => {
    expect(() =>
      createAllowthemClient({ ...baseConfig, domain: "https://acme.allowthem.io" }),
    ).toThrow(AuthError);
  });

  it("throws config_error when domain is empty", () => {
    expect(() => createAllowthemClient({ ...baseConfig, domain: "" })).toThrow(
      /domain is required/,
    );
  });

  it("throws config_error when clientId is missing", () => {
    expect(() => createAllowthemClient({ ...baseConfig, clientId: "" })).toThrow(
      /clientId/,
    );
  });

  it("throws config_error when redirectUri is missing", () => {
    expect(() =>
      createAllowthemClient({ ...baseConfig, redirectUri: "" }),
    ).toThrow(/redirectUri/);
  });
});

describe("loginWithRedirect", () => {
  it("navigates to /oauth/authorize on the configured domain", async () => {
    const client = createAllowthemClient(baseConfig);
    void client.loginWithRedirect();
    const url = await waitForAssign();
    expect(url.host).toBe("acme.allowthem.io");
    expect(url.pathname).toBe("/oauth/authorize");
  });

  it("includes all PKCE + OIDC required parameters", async () => {
    const client = createAllowthemClient(baseConfig);
    void client.loginWithRedirect();
    const url = await waitForAssign();

    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe("ath_test");
    expect(url.searchParams.get("redirect_uri")).toBe(
      "https://app.example/callback",
    );
    expect(url.searchParams.get("scope")).toBe(
      "openid profile email offline_access",
    );
    expect(url.searchParams.get("state")).not.toBeNull();
    expect(url.searchParams.get("nonce")).not.toBeNull();
    expect(url.searchParams.get("code_challenge")).not.toBeNull();
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
  });

  it("stores the transaction under the URL's state", async () => {
    const client = createAllowthemClient(baseConfig);
    void client.loginWithRedirect();
    const url = await waitForAssign();
    const state = url.searchParams.get("state")!;

    const raw = sessionStorage.getItem(TXN_KEY);
    expect(raw).not.toBeNull();
    const map = JSON.parse(raw!) as Record<
      string,
      { codeVerifier: string; nonce: string }
    >;
    expect(map[state]).toBeDefined();
    expect(map[state]!.codeVerifier).toBeTypeOf("string");
    expect(map[state]!.nonce).toBe(url.searchParams.get("nonce"));
  });

  it("round-trips appState through the transaction record", async () => {
    const client = createAllowthemClient(baseConfig);
    const myState = { from: "/dashboard", correlationId: 7 };
    void client.loginWithRedirect({ appState: myState });
    const url = await waitForAssign();
    const state = url.searchParams.get("state")!;
    const map = JSON.parse(sessionStorage.getItem(TXN_KEY)!) as Record<
      string,
      { appState: unknown }
    >;
    expect(map[state]!.appState).toEqual(myState);
  });

  it("includes prompt and audience when configured", async () => {
    const client = createAllowthemClient({
      ...baseConfig,
      audience: "api.acme.test",
    });
    void client.loginWithRedirect({ prompt: "login" });
    const url = await waitForAssign();
    expect(url.searchParams.get("audience")).toBe("api.acme.test");
    expect(url.searchParams.get("prompt")).toBe("login");
  });

  it("respects per-call scope and redirectUri overrides", async () => {
    const client = createAllowthemClient(baseConfig);
    void client.loginWithRedirect({
      scope: "openid",
      redirectUri: "https://app.example/other",
    });
    const url = await waitForAssign();
    expect(url.searchParams.get("scope")).toBe("openid");
    expect(url.searchParams.get("redirect_uri")).toBe(
      "https://app.example/other",
    );
  });
});
