import { describe, expect, it } from "vitest";
import { AuthError } from "../errors.js";
import { createAllowthemVerifier, DEFAULTS } from "../verifier.js";

describe("createAllowthemVerifier — config validation", () => {
  // Valid base config used by the "reaches stub" test below.
  const valid = { domain: "acme.allowthem.io", audience: "ath_xxx" };

  it("rejects empty domain", () => {
    expect(() => createAllowthemVerifier({ ...valid, domain: "" }))
      .toThrowError(new AuthError("config_error", "domain is required"));
  });

  it("rejects domain with https:// prefix", () => {
    try {
      createAllowthemVerifier({ ...valid, domain: "https://acme.allowthem.io" });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AuthError);
      expect((err as AuthError).code).toBe("config_error");
      expect((err as AuthError).description).toBe("domain must not include a scheme");
    }
  });

  it("rejects domain with http:// prefix (case-insensitive)", () => {
    expect(() => createAllowthemVerifier({ ...valid, domain: "HTTP://acme.allowthem.io" }))
      .toThrow(/scheme/);
  });

  it("rejects domain with trailing slash", () => {
    expect(() => createAllowthemVerifier({ ...valid, domain: "acme.allowthem.io/" }))
      .toThrow(/trailing slash/);
  });

  it("rejects domain with embedded path", () => {
    expect(() => createAllowthemVerifier({ ...valid, domain: "acme.allowthem.io/foo" }))
      .toThrow(/path/);
  });

  it("rejects missing audience", () => {
    expect(() => createAllowthemVerifier({ ...valid, audience: "" }))
      .toThrowError(new AuthError("config_error", "audience is required"));
  });

  it("returns a verifier instance for a valid config", () => {
    const verifier = createAllowthemVerifier(valid);
    expect(typeof verifier.verify).toBe("function");
    expect(typeof verifier.requireRole).toBe("function");
    expect(typeof verifier.hasPermission).toBe("function");
  });

  it("DEFAULTS frozen-ish — values match spec", () => {
    expect(DEFAULTS.jwksCacheTtlSeconds).toBe(3600);
    expect(DEFAULTS.jwksMinRefreshIntervalSeconds).toBe(60);
    expect(DEFAULTS.clockSkewSeconds).toBe(60);
  });
});
