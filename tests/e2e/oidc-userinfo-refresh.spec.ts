import { test, expect } from "@playwright/test";
import { registerUser } from "./fixtures";
import {
  generatePkce,
  buildAuthorizeUrl,
  armCodeCapture,
  exchangeCode,
  refreshTokens,
  fetchUserInfo,
  TokenResponse,
} from "./oidc-rp";

const CLIENT_ID = "e2e-test-client";
const CLIENT_SECRET = "e2e-test-secret-1234";
const REDIRECT_URI = "http://127.0.0.1:3100/test-callback";
const BASE_URL = "http://127.0.0.1:3100";

test.describe.configure({ mode: "serial" });

/** Full authorize+consent+exchange flow. Returns tokens and the registered email. */
async function obtainTokens(
  page: import("@playwright/test").Page
): Promise<{ tokens: TokenResponse; email: string }> {
  const email = `oidc-ui-${Date.now()}-${Math.random().toString(36).slice(2, 6)}@example.com`;
  await registerUser(page, email, "Test1234!");

  const { codeVerifier, codeChallenge } = generatePkce();
  const state = `ui-state-${Date.now()}`;
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

  const tokens = await exchangeCode(
    page,
    code,
    codeVerifier,
    REDIRECT_URI,
    CLIENT_ID,
    CLIENT_SECRET
  );
  return { tokens, email };
}

test("userinfo > happy path: returns sub, email, email_verified for authenticated token", async ({
  page,
}) => {
  const { tokens, email } = await obtainTokens(page);
  const userInfo = await fetchUserInfo(page, tokens.access_token);

  expect(typeof userInfo.sub).toBe("string");
  expect(userInfo.email).toBe(email);
  // Newly registered users have email_verified = false (no verification flow in e2e)
  expect(typeof userInfo.email_verified).toBe("boolean");
});

test("userinfo > no token: returns HTTP 401", async ({ page }) => {
  const res = await page.request.get("/oauth/userinfo");
  expect(res.status()).toBe(401);
});

test("refresh > issues new token set after valid refresh token", async ({
  page,
}) => {
  const { tokens } = await obtainTokens(page);
  const newTokens = await refreshTokens(
    page,
    tokens.refresh_token,
    CLIENT_ID,
    CLIENT_SECRET
  );

  expect(typeof newTokens.access_token).toBe("string");
  expect(typeof newTokens.id_token).toBe("string");
  expect(typeof newTokens.refresh_token).toBe("string");
  expect(newTokens.token_type).toBe("Bearer");
  expect(typeof newTokens.expires_in).toBe("number");
  // Rotation: new refresh token differs from the original
  expect(newTokens.refresh_token).not.toBe(tokens.refresh_token);
});

test("refresh > rotation: reusing old refresh token returns invalid_grant", async ({
  page,
}) => {
  const { tokens } = await obtainTokens(page);

  // First refresh succeeds and rotates the token
  await refreshTokens(page, tokens.refresh_token, CLIENT_ID, CLIENT_SECRET);

  // Attempt to reuse the original (now-consumed) refresh token
  const res = await page.request.post("/oauth/token", {
    form: {
      grant_type: "refresh_token",
      refresh_token: tokens.refresh_token,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    },
  });

  expect(res.status()).toBe(400);
  const body = await res.json();
  expect(body.error).toBe("invalid_grant");
});
