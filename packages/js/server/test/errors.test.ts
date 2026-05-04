import { describe, expect, it } from "vitest";
import { AuthError as ServerAuthError } from "../errors.js";
import { AuthError as BrowserAuthError } from "../../src/errors.js";

describe("server entry AuthError re-export", () => {
  it("constructs with code + description", () => {
    const err = new ServerAuthError("invalid_token", "test description");
    expect(err.code).toBe("invalid_token");
    expect(err.description).toBe("test description");
    expect(err.message).toBe("invalid_token: test description");
    expect(err.name).toBe("AuthError");
  });

  it("constructs with code only (no description)", () => {
    const err = new ServerAuthError("forbidden");
    expect(err.code).toBe("forbidden");
    expect(err.description).toBeUndefined();
    expect(err.message).toBe("forbidden");
  });

  it("is identity-equal to the browser-entry AuthError class", () => {
    // Identity check guards against the re-export accidentally wrapping or
    // duplicating the class. `instanceof` checks across boundaries depend on
    // this — a parallel class hierarchy would silently break consumers.
    expect(ServerAuthError).toBe(BrowserAuthError);
  });

  it("instances pass instanceof for both AuthError references", () => {
    const err = new ServerAuthError("invalid_token", "x");
    expect(err).toBeInstanceOf(ServerAuthError);
    expect(err).toBeInstanceOf(BrowserAuthError);
    expect(err).toBeInstanceOf(Error);
  });
});
