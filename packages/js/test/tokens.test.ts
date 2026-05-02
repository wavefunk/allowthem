import { describe, it, expect, beforeEach } from "vitest";
import {
  createMemoryStore,
  createSessionStore,
  type TokenSet,
} from "../src/tokens.js";

const KEY = "allowthem:tokens";

const tokens = (): TokenSet => ({
  accessToken: "at",
  idToken: "it",
  refreshToken: "rt",
  expiresAt: Date.now() + 3600_000,
});

describe("memory token store", () => {
  it("round-trips put → get", () => {
    const s = createMemoryStore();
    expect(s.get()).toBeNull();
    s.put(tokens());
    const got = s.get();
    expect(got?.accessToken).toBe("at");
    expect(got?.refreshToken).toBe("rt");
  });

  it("clear sets state back to null", () => {
    const s = createMemoryStore();
    s.put(tokens());
    s.clear();
    expect(s.get()).toBeNull();
  });
});

describe("session token store", () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  it("persists access + id + expiresAt to sessionStorage", () => {
    const s = createSessionStore();
    s.put(tokens());
    const raw = sessionStorage.getItem(KEY);
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw!);
    expect(parsed.accessToken).toBe("at");
    expect(parsed.idToken).toBe("it");
    expect(parsed.expiresAt).toBeTypeOf("number");
  });

  it("does NOT persist refresh token to sessionStorage", () => {
    const s = createSessionStore();
    s.put(tokens());
    const raw = sessionStorage.getItem(KEY);
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw!);
    expect(parsed.refreshToken).toBeUndefined();
  });

  it("get reconstructs full TokenSet including refresh from memory", () => {
    const s = createSessionStore();
    s.put(tokens());
    const got = s.get();
    expect(got?.accessToken).toBe("at");
    expect(got?.refreshToken).toBe("rt");
  });

  it("loses refresh token across store re-instantiation (simulated reload)", () => {
    const s1 = createSessionStore();
    s1.put(tokens());
    // Simulate page reload by recreating the store; sessionStorage retained.
    const s2 = createSessionStore();
    const got = s2.get();
    expect(got?.accessToken).toBe("at");
    expect(got?.refreshToken).toBeUndefined();
  });

  it("clear removes both backing stores", () => {
    const s = createSessionStore();
    s.put(tokens());
    s.clear();
    expect(s.get()).toBeNull();
    expect(sessionStorage.getItem(KEY)).toBeNull();
  });

  it("get returns null when sessionStorage is empty", () => {
    const s = createSessionStore();
    expect(s.get()).toBeNull();
  });

  it("get returns null on corrupted JSON", () => {
    sessionStorage.setItem(KEY, "not json");
    const s = createSessionStore();
    expect(s.get()).toBeNull();
  });

  it("get returns null when persisted shape is missing accessToken", () => {
    sessionStorage.setItem(KEY, JSON.stringify({ idToken: "x" }));
    const s = createSessionStore();
    expect(s.get()).toBeNull();
  });
});
