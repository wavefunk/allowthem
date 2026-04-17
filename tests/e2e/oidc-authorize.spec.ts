import { test, expect } from "@playwright/test";
import { registerUser } from "./fixtures";
import {
  generatePkce,
  buildAuthorizeUrl,
  armCodeCapture,
  armRedirectCapture,
} from "./oidc-rp";

const CLIENT_ID = "e2e-test-client";
const REDIRECT_URI = "http://127.0.0.1:3100/test-callback";
const BASE_URL = "http://127.0.0.1:3100";

test.describe.configure({ mode: "serial" });

test("authorize > unauthenticated: redirected to /login with next and client_id params", async ({
  page,
}) => {
  const { codeChallenge } = generatePkce();
  const authorizeUrl = buildAuthorizeUrl({
    baseUrl: BASE_URL,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    scope: "openid email",
    state: "test-unauth-state",
    codeChallenge,
  });

  await page.goto(authorizeUrl);

  // Should land on /login
  await expect(page).toHaveURL(/\/login/);
  const url = new URL(page.url());
  // The redirect preserves client_id for branding
  expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
  // The `next` param preserves the original authorize URL
  expect(url.searchParams.get("next")).toBeTruthy();
});

test("authorize > consent screen: app name and scope descriptions rendered", async ({
  page,
}) => {
  const email = `oidc-consent-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");

  const { codeChallenge } = generatePkce();
  const authorizeUrl = buildAuthorizeUrl({
    baseUrl: BASE_URL,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    scope: "openid email",
    state: "test-consent-state",
    codeChallenge,
  });

  await page.goto(authorizeUrl);

  // Consent screen should show app name and scope descriptions
  await expect(
    page.getByRole("heading", { name: "E2E Test App" })
  ).toBeVisible();
  await expect(page.locator("text=Verify your identity")).toBeVisible();
  await expect(page.locator("text=View your email address")).toBeVisible();
  // Allow and Deny buttons present
  await expect(
    page.locator('button[name="consent"][value="approve"]')
  ).toBeVisible();
  await expect(
    page.locator('button[name="consent"][value="deny"]')
  ).toBeVisible();
});

test("authorize > consent approval: redirected to redirect_uri with code and state", async ({
  page,
}) => {
  const email = `oidc-approve-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");

  const { codeChallenge } = generatePkce();
  const originalState = `approve-state-${Date.now()}`;
  const authorizeUrl = buildAuthorizeUrl({
    baseUrl: BASE_URL,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    scope: "openid email",
    state: originalState,
    codeChallenge,
  });

  const collectCode = await armCodeCapture(page, REDIRECT_URI);
  await page.goto(authorizeUrl);
  // Ensure the consent screen is visible before clicking
  await page.locator('button[name="consent"][value="approve"]').waitFor();
  await page.locator('button[name="consent"][value="approve"]').click();
  const { code, state } = await collectCode();

  expect(code).toBeTruthy();
  expect(state).toBe(originalState);
});

test("authorize > consent denial: redirected to redirect_uri with error=access_denied", async ({
  page,
}) => {
  const email = `oidc-deny-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");

  const { codeChallenge } = generatePkce();
  const originalState = `deny-state-${Date.now()}`;
  const authorizeUrl = buildAuthorizeUrl({
    baseUrl: BASE_URL,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    scope: "openid email",
    state: originalState,
    codeChallenge,
  });

  const collectParams = await armRedirectCapture(page, REDIRECT_URI);
  await page.goto(authorizeUrl);
  await page.locator('button[name="consent"][value="deny"]').click();
  const params = await collectParams();

  expect(params.get("error")).toBe("access_denied");
  expect(params.get("state")).toBe(originalState);
});
