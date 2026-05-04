import { describe, expect, it } from "vitest";
import { AuthError } from "../errors.js";
import {
  type AllowthemUser,
  createAllowthemVerifier,
  hasPermission,
  requireRole,
} from "../verifier.js";

function makeUser(overrides: Partial<AllowthemUser> = {}): AllowthemUser {
  return {
    sub: "user-1",
    email: "u@example.com",
    emailVerified: true,
    roles: [],
    permissions: [],
    raw: {},
    ...overrides,
  };
}

describe("requireRole", () => {
  it("returns silently when role is present", () => {
    const u = makeUser({ roles: ["admin", "owner"] });
    expect(() => requireRole(u, "admin")).not.toThrow();
    expect(() => requireRole(u, "owner")).not.toThrow();
  });

  it("throws AuthError(forbidden, missing role: <role>) when absent", () => {
    const u = makeUser({ roles: ["viewer"] });
    expect(() => requireRole(u, "admin")).toThrowError(
      new AuthError("forbidden", "missing role: admin"),
    );
  });

  it("throws on empty roles array", () => {
    const u = makeUser({ roles: [] });
    expect(() => requireRole(u, "admin")).toThrowError(
      new AuthError("forbidden", "missing role: admin"),
    );
  });

  it("is case-sensitive", () => {
    const u = makeUser({ roles: ["Admin"] });
    expect(() => requireRole(u, "admin")).toThrow();
  });

  it("is pure — same input yields same result twice", () => {
    const u = makeUser({ roles: ["x"] });
    expect(() => requireRole(u, "x")).not.toThrow();
    expect(() => requireRole(u, "x")).not.toThrow();
    expect(() => requireRole(u, "y")).toThrow();
    expect(() => requireRole(u, "y")).toThrow();
  });
});

describe("hasPermission", () => {
  it("returns true when permission present", () => {
    const u = makeUser({ permissions: ["users:read", "users:write"] });
    expect(hasPermission(u, "users:read")).toBe(true);
    expect(hasPermission(u, "users:write")).toBe(true);
  });

  it("returns false when permission absent", () => {
    const u = makeUser({ permissions: ["users:read"] });
    expect(hasPermission(u, "users:write")).toBe(false);
  });

  it("returns false on empty permissions array", () => {
    expect(hasPermission(makeUser({ permissions: [] }), "any")).toBe(false);
  });

  it("is case-sensitive", () => {
    const u = makeUser({ permissions: ["Users:Read"] });
    expect(hasPermission(u, "users:read")).toBe(false);
  });
});

describe("verifier method ↔ named export identity", () => {
  it("verifier.requireRole === named export requireRole", () => {
    const v = createAllowthemVerifier({
      domain: "acme.allowthem.io",
      audience: "ath_xxx",
    });
    expect(v.requireRole).toBe(requireRole);
  });

  it("verifier.hasPermission === named export hasPermission", () => {
    const v = createAllowthemVerifier({
      domain: "acme.allowthem.io",
      audience: "ath_xxx",
    });
    expect(v.hasPermission).toBe(hasPermission);
  });
});
