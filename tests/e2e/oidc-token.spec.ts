import { test, expect } from "@playwright/test";
import { registerUser } from "./fixtures";
import {
  generatePkce,
  buildAuthorizeUrl,
  armCodeCapture,
  exchangeCode,
  decodeJwtPayload,
} from "./oidc-rp";

const CLIENT_ID = "e2e-test-client";
const CLIENT_SECRET = "e2e-test-secret-1234";
const REDIRECT_URI = "http://127.0.0.1:3100/test-callback";
const BASE_URL = "http://127.0.0.1:3100";

test.describe.configure({ mode: "serial" });

/** Register a user, run the authorize+consent flow, and return the auth code + verifier. */
async function obtainAuthCode(
  page: import("@playwright/test").Page
): Promise<{ code: string; codeVerifier: string; email: string }> {
  const email = `oidc-token-${Date.now()}-${Math.random().toString(36).slice(2, 6)}@example.com`;
  await registerUser(page, email, "Test1234!");

  const { codeVerifier, codeChallenge } = generatePkce();
  const state = `token-state-${Date.now()}`;
  const authorizeUrl = buildAuthorizeUrl({
    baseUrl: BASE_URL,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    scope: "openid email",
    state,
    codeChallenge,
  });

  const collectCode = await armCodeCapture(page, REDIRECT_URI);
  await page.goto(authorizeUrl);
  await page.locator('button[name="consent"][value="approve"]').click();
  const { code } = await collectCode();
  return { code, codeVerifier, email };
}

test("token > authorization_code grant: valid PKCE exchange returns full token response", async ({
  page,
}) => {
  const { code, codeVerifier } = await obtainAuthCode(page);
  const tokens = await exchangeCode(
    page,
    code,
    codeVerifier,
    REDIRECT_URI,
    CLIENT_ID,
    CLIENT_SECRET
  );

  expect(typeof tokens.access_token).toBe("string");
  expect(tokens.token_type).toBe("Bearer");
  expect(typeof tokens.expires_in).toBe("number");
  expect(tokens.expires_in).toBeGreaterThan(0);
  expect(typeof tokens.refresh_token).toBe("string");
  expect(typeof tokens.id_token).toBe("string");
});

test("token > access_token: is a JWT with correct iss, sub, aud, exp, scope claims", async ({
  page,
}) => {
  const { code, codeVerifier } = await obtainAuthCode(page);
  const tokens = await exchangeCode(
    page,
    code,
    codeVerifier,
    REDIRECT_URI,
    CLIENT_ID,
    CLIENT_SECRET
  );

  const payload = decodeJwtPayload(tokens.access_token);
  expect(payload.iss).toBe(BASE_URL);
  expect(typeof payload.sub).toBe("string");
  expect((payload.sub as string).length).toBeGreaterThan(0);
  expect(payload.aud).toBe(CLIENT_ID);
  expect(typeof payload.exp).toBe("number");
  expect((payload.exp as number)).toBeGreaterThan(Date.now() / 1000);
  // scope is a space-separated string
  expect(typeof payload.scope).toBe("string");
  expect((payload.scope as string)).toContain("email");
});

test("token > id_token: is a JWT with iss, sub, aud, exp, iat, at_hash claims", async ({
  page,
}) => {
  const { code, codeVerifier } = await obtainAuthCode(page);
  const tokens = await exchangeCode(
    page,
    code,
    codeVerifier,
    REDIRECT_URI,
    CLIENT_ID,
    CLIENT_SECRET
  );

  const payload = decodeJwtPayload(tokens.id_token);
  expect(payload.iss).toBe(BASE_URL);
  expect(typeof payload.sub).toBe("string");
  expect(payload.aud).toBe(CLIENT_ID);
  expect(typeof payload.exp).toBe("number");
  expect(typeof payload.iat).toBe("number");
  expect(typeof payload.at_hash).toBe("string");
});

test("token > PKCE mismatch: wrong code_verifier returns invalid_grant", async ({
  page,
}) => {
  const { code } = await obtainAuthCode(page);
  const res = await page.request.post("/oauth/token", {
    form: {
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: "wrong-verifier-value-that-does-not-match",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    },
  });

  expect(res.status()).toBe(400);
  const body = await res.json();
  expect(body.error).toBe("invalid_grant");
});

test("token > code replay: reusing authorization code returns invalid_grant", async ({
  page,
}) => {
  const { code, codeVerifier } = await obtainAuthCode(page);

  // First exchange succeeds
  await exchangeCode(
    page,
    code,
    codeVerifier,
    REDIRECT_URI,
    CLIENT_ID,
    CLIENT_SECRET
  );

  // Second exchange with the same code fails
  const res = await page.request.post("/oauth/token", {
    form: {
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    },
  });

  expect(res.status()).toBe(400);
  const body = await res.json();
  expect(body.error).toBe("invalid_grant");
});
