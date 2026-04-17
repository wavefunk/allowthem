import { test, expect } from "@playwright/test";

test("discovery > openid-configuration: required OIDC fields present with correct issuer", async ({
  request,
}) => {
  const res = await request.get("/.well-known/openid-configuration");
  expect(res.status()).toBe(200);
  const json = await res.json();

  expect(json.issuer).toBe("http://127.0.0.1:3100");
  expect(typeof json.authorization_endpoint).toBe("string");
  expect(typeof json.token_endpoint).toBe("string");
  expect(typeof json.userinfo_endpoint).toBe("string");
  expect(typeof json.jwks_uri).toBe("string");

  // Verify endpoints use the correct base URL
  expect(json.authorization_endpoint).toContain("127.0.0.1:3100");
  expect(json.token_endpoint).toContain("127.0.0.1:3100");
});

test("discovery > jwks: returns at least one RS256 key", async ({
  request,
}) => {
  const res = await request.get("/.well-known/jwks.json");
  expect(res.status()).toBe(200);
  const json = await res.json();

  expect(Array.isArray(json.keys)).toBe(true);
  expect(json.keys.length).toBeGreaterThan(0);

  const rsaKey = json.keys.find(
    (k: Record<string, string>) => k.kty === "RSA" && k.alg === "RS256"
  );
  expect(rsaKey).toBeDefined();
  expect(typeof rsaKey.kid).toBe("string");
  expect(typeof rsaKey.n).toBe("string");
  expect(typeof rsaKey.e).toBe("string");
});
