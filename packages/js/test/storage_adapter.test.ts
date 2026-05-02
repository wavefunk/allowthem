import { describe, it, expect } from "vitest";
import { AuthError } from "../src/errors.js";
import { createAllowthemClient } from "../src/client.js";
import type { ClientConfig } from "../src/types.js";
import type { TokenSet, TokenStore } from "../src/tokens.js";

const baseConfig: Omit<ClientConfig, "storage"> = {
  domain: "acme.allowthem.io",
  clientId: "ath_test",
  redirectUri: "https://app.example/callback",
};

function recordingStore(): TokenStore & {
  calls: Array<["get" | "put" | "clear", TokenSet | undefined]>;
} {
  let cur: TokenSet | null = null;
  const calls: Array<["get" | "put" | "clear", TokenSet | undefined]> = [];
  return {
    calls,
    get() {
      calls.push(["get", undefined]);
      return cur;
    },
    put(t: TokenSet) {
      calls.push(["put", t]);
      cur = t;
    },
    clear() {
      calls.push(["clear", undefined]);
      cur = null;
    },
  };
}

describe("ClientConfig.storage", () => {
  it("default (no storage) returns a memory store", () => {
    const client = createAllowthemClient({ ...baseConfig });
    // Memory store: isAuthenticated() → false initially.
    expect(client.isAuthenticated()).toBe(false);
  });

  it("'session' string is accepted (sessionStorage backed)", () => {
    const client = createAllowthemClient({ ...baseConfig, storage: "session" });
    expect(client.isAuthenticated()).toBe(false);
  });

  it("a TokenStore-shaped object is wired through and routes operations to the adapter", async () => {
    const adapter = recordingStore();
    const client = createAllowthemClient({ ...baseConfig, storage: adapter });
    expect(client.isAuthenticated()).toBe(false);
    // isAuthenticated reads via store.get
    expect(adapter.calls.some(([m]) => m === "get")).toBe(true);

    // logout routes through clear()
    await client.logout();
    expect(adapter.calls.some(([m]) => m === "clear")).toBe(true);
  });

  it("invalid storage shape throws config_error at construction", () => {
    expect(() =>
      createAllowthemClient({
        ...baseConfig,
        // missing put + clear
        storage: { get: () => null } as unknown as TokenStore,
      }),
    ).toThrow(AuthError);
  });

  it("non-string non-object storage throws config_error", () => {
    expect(() =>
      createAllowthemClient({
        ...baseConfig,
        storage: 42 as unknown as TokenStore,
      }),
    ).toThrow(/invalid storage/);
  });

  it("null storage throws config_error", () => {
    expect(() =>
      createAllowthemClient({
        ...baseConfig,
        storage: null as unknown as TokenStore,
      }),
    ).toThrow(/invalid storage/);
  });
});
