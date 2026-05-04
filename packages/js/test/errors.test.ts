import { describe, it, expect } from "vitest";
import { AuthError, ERROR_CODES } from "../src/errors.js";

describe("AuthError", () => {
  it("is an Error subclass", () => {
    const e = new AuthError("invalid_state");
    expect(e).toBeInstanceOf(Error);
    expect(e).toBeInstanceOf(AuthError);
    expect(e.name).toBe("AuthError");
  });

  it("formats message as 'code: description' when description is present", () => {
    const e = new AuthError("invalid_grant", "rotated");
    expect(e.message).toBe("invalid_grant: rotated");
    expect(e.code).toBe("invalid_grant");
    expect(e.description).toBe("rotated");
  });

  it("formats message as just the code when description is absent", () => {
    const e = new AuthError("login_required");
    expect(e.message).toBe("login_required");
    expect(e.description).toBeUndefined();
  });

  it("carries appState through unchanged", () => {
    const state = { returnTo: "/profile", flag: 42 };
    const e = new AuthError("access_denied", "user cancelled", state);
    expect(e.appState).toEqual(state);
  });

  it("omits appState when not provided", () => {
    const e = new AuthError("invalid_state", "no match");
    expect(e.appState).toBeUndefined();
  });

  it("exposes ERROR_CODES constants", () => {
    expect(ERROR_CODES.INVALID_STATE).toBe("invalid_state");
    expect(ERROR_CODES.INVALID_RESPONSE).toBe("invalid_response");
    expect(ERROR_CODES.INVALID_ID_TOKEN).toBe("invalid_id_token");
    expect(ERROR_CODES.LOGIN_REQUIRED).toBe("login_required");
    expect(ERROR_CODES.CONFIG_ERROR).toBe("config_error");
  });
});
