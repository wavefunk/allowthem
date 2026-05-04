import { describe, it, expect } from "vitest";
import {
  base64url,
  generateChallenge,
  generateRandomString,
  generateVerifier,
  randomBytes,
} from "../src/pkce.js";

describe("pkce", () => {
  it("randomBytes returns the requested length", () => {
    const a = randomBytes(0);
    expect(a).toBeInstanceOf(Uint8Array);
    expect(a.length).toBe(0);

    const b = randomBytes(32);
    expect(b.length).toBe(32);
  });

  it("base64url uses URL-safe alphabet and no padding", () => {
    // Bytes that would otherwise produce "+" and "/" in standard base64.
    const bytes = new Uint8Array([0xfb, 0xff, 0xff]);
    expect(base64url(bytes)).toBe("-___");
  });

  it("base64url round-trips all 256 byte values", () => {
    const all = new Uint8Array(256);
    for (let i = 0; i < 256; i++) all[i] = i;
    const encoded = base64url(all);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(encoded).not.toContain("=");
  });

  it("generateVerifier returns 43 base64url chars", () => {
    const v = generateVerifier();
    expect(v).toHaveLength(43);
    expect(v).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("two generateVerifier calls produce different strings", () => {
    const a = generateVerifier();
    const b = generateVerifier();
    expect(a).not.toBe(b);
  });

  it("generateChallenge matches RFC 7636 Appendix B fixture", async () => {
    // From RFC 7636 §B: verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    // → challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const challenge = await generateChallenge(verifier);
    expect(challenge).toBe(expected);
  });

  it("generateRandomString produces base64url with default 32 bytes (43 chars)", () => {
    const s = generateRandomString();
    expect(s).toHaveLength(43);
    expect(s).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("generateRandomString respects custom byte length", () => {
    // 16 bytes → ceil(16 * 4 / 3) = 22 chars
    const s = generateRandomString(16);
    expect(s).toHaveLength(22);
  });
});
