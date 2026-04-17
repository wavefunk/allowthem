import { test, expect } from "@playwright/test";
import { registerUser, oauthLogin } from "./fixtures";

// -------------------------------------------------------------------------
// UI: OAuth buttons on login page
// -------------------------------------------------------------------------

test("oauth > login page renders OAuth provider buttons", async ({ page }) => {
  await page.goto("/login");
  await expect(
    page.getByRole("link", { name: /Log in with Google/i })
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: /Log in with Github/i })
  ).toBeVisible();
});

// -------------------------------------------------------------------------
// Redirect: clicking a provider link leads to mock simulate (not real provider)
// -------------------------------------------------------------------------

test("oauth > Google authorize redirects through mock simulate", async ({
  page,
}) => {
  // Verify the authorize endpoint redirects to the local simulate route
  // by using page.request.get (no redirect following) to inspect the Location header.
  const resp = await page.request.get("/oauth/google/authorize", {
    maxRedirects: 0,
  });
  expect(resp.status()).toBe(307);
  const location = resp.headers()["location"] ?? "";
  expect(location).toContain("/test-oauth/simulate");
  expect(location).not.toContain("accounts.google.com");
});

test("oauth > GitHub authorize redirects through mock simulate", async ({
  page,
}) => {
  const resp = await page.request.get("/oauth/github/authorize", {
    maxRedirects: 0,
  });
  expect(resp.status()).toBe(307);
  const location = resp.headers()["location"] ?? "";
  expect(location).toContain("/test-oauth/simulate");
  expect(location).not.toContain("github.com");
});

// -------------------------------------------------------------------------
// Happy path: auto-register new user
// -------------------------------------------------------------------------

test("oauth > Google login: auto-registers new user and sets session", async ({
  page,
  context,
}) => {
  const email = `test-oauth-new-${Date.now()}@example.com`;
  await oauthLogin(page, "google", { email });
  await expect(page).toHaveURL("/");
  const cookies = await context.cookies();
  expect(cookies.find((c) => c.name === "allowthem_session")).toBeDefined();
});

test("oauth > GitHub login: auto-registers new user and sets session", async ({
  page,
  context,
}) => {
  const email = `test-oauth-gh-${Date.now()}@example.com`;
  await oauthLogin(page, "github", { email });
  await expect(page).toHaveURL("/");
  const cookies = await context.cookies();
  expect(cookies.find((c) => c.name === "allowthem_session")).toBeDefined();
});

// -------------------------------------------------------------------------
// Return login: existing OAuth account -> same session, same user
// -------------------------------------------------------------------------

test("oauth > return login: stable uid returns existing user", async ({
  page,
  context,
}) => {
  const uid = `stable-uid-${Date.now()}`;
  const email = `test-oauth-stable-${Date.now()}@example.com`;
  await oauthLogin(page, "google", { email, uid });
  await expect(page).toHaveURL("/");
  await context.clearCookies();

  await oauthLogin(page, "google", { email, uid });
  await expect(page).toHaveURL("/");
  const cookies = await context.cookies();
  expect(cookies.find((c) => c.name === "allowthem_session")).toBeDefined();
});

// -------------------------------------------------------------------------
// Email-based auto-linking: verified email matches existing password user
// -------------------------------------------------------------------------

test("oauth > email-based linking: verified OAuth email links to existing password account", async ({
  page,
  context,
}) => {
  const email = `test-oauth-link-${Date.now()}@example.com`;
  // Register via password first
  await registerUser(page, email, "Test1234!");
  await context.clearCookies();

  // OAuth login with same email (verified=true) -> auto-links to existing user
  await oauthLogin(page, "google", { email, verified: true });
  await expect(page).toHaveURL("/");
  const cookies = await context.cookies();
  expect(cookies.find((c) => c.name === "allowthem_session")).toBeDefined();

  // Settings page should show Google in linked accounts
  await page.goto("/settings");
  await expect(page.locator("text=google")).toBeVisible();
});

// -------------------------------------------------------------------------
// Account linking flow: authenticated user links provider
// -------------------------------------------------------------------------

test("oauth > link flow: authenticated user links Google account", async ({
  page,
}) => {
  const email = `test-oauth-link-flow-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");

  // The link flow follows a redirect chain:
  //   /oauth/google/link -> /test-oauth/simulate?... -> /oauth/google/callback?... -> /
  // We manually follow the first redirect, inject identity params into the simulate URL,
  // then let the browser follow the rest of the chain.
  const uid = `link-uid-${Date.now()}`;

  // Step 1: Hit the link endpoint to get the redirect to simulate
  const linkResp = await page.request.get("/oauth/google/link", {
    maxRedirects: 0,
  });
  expect(linkResp.status()).toBe(307);
  const simulateUrl = new URL(
    linkResp.headers()["location"]!,
    "http://127.0.0.1:3100"
  );

  // Step 2: Inject identity params into simulate URL
  simulateUrl.searchParams.set("email", email);
  simulateUrl.searchParams.set("verified", "true");
  simulateUrl.searchParams.set("uid", uid);

  // Step 3: Navigate to the modified simulate URL; the browser follows the rest
  await page.goto(simulateUrl.pathname + simulateUrl.search);

  // Verify the link via API
  const apiResp = await page.request.get("/account/linked-providers");
  const body = await apiResp.json();
  expect(body.accounts).toHaveLength(1);
  expect(body.accounts[0].provider).toBe("google");
});

// -------------------------------------------------------------------------
// Unlink: removing a linked provider
// -------------------------------------------------------------------------

test("oauth > unlink: linked account removed via POST /oauth/unlink", async ({
  page,
}) => {
  const email = `test-oauth-unlink-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");

  // Link Google to this password user via the link flow.
  // Manually follow the redirect chain to inject identity params.
  const uid = `link-for-unlink-${Date.now()}`;
  const linkResp = await page.request.get("/oauth/google/link", {
    maxRedirects: 0,
  });
  expect(linkResp.status()).toBe(307);
  const simulateUrl = new URL(
    linkResp.headers()["location"]!,
    "http://127.0.0.1:3100"
  );
  simulateUrl.searchParams.set("email", email);
  simulateUrl.searchParams.set("verified", "true");
  simulateUrl.searchParams.set("uid", uid);
  await page.goto(simulateUrl.pathname + simulateUrl.search);

  // Confirm linked
  await page.goto("/settings");
  await expect(page.locator("text=google")).toBeVisible();

  // Unlink via POST /oauth/unlink (outside csrf_middleware, no CSRF token needed)
  const resp = await page.request.post("/oauth/unlink", {
    headers: { "Content-Type": "application/json" },
    data: JSON.stringify({ provider: "google" }),
  });
  expect(resp.status()).toBe(204);

  // Linked accounts section no longer shows google
  await page.goto("/settings");
  await expect(page.locator("text=google")).not.toBeVisible();
});

// -------------------------------------------------------------------------
// Error cases
// -------------------------------------------------------------------------

test("oauth > error: invalid state returns 400", async ({ page }) => {
  const resp = await page.request.get(
    "/oauth/google/callback?code=x&state=garbage"
  );
  expect(resp.status()).toBe(400);
});

test("oauth > error: missing code returns 400", async ({ page }) => {
  const resp = await page.request.get(
    "/oauth/google/callback?state=garbage"
  );
  expect(resp.status()).toBe(400);
});

test("oauth > error: unknown provider returns 404", async ({ page }) => {
  const resp = await page.request.get("/oauth/unknown/authorize");
  expect(resp.status()).toBe(404);
});

test("oauth > error: provider conflict returns 409 when uid already linked to another user", async ({
  page,
  context,
}) => {
  const uid = `conflict-uid-${Date.now()}`;

  // User A: register and link Google with uid=X
  const emailA = `test-oauth-conflict-a-${Date.now()}@example.com`;
  await registerUser(page, emailA, "Test1234!");
  const linkRespA = await page.request.get("/oauth/google/link", {
    maxRedirects: 0,
  });
  expect(linkRespA.status()).toBe(307);
  const simulateA = new URL(
    linkRespA.headers()["location"]!,
    "http://127.0.0.1:3100"
  );
  simulateA.searchParams.set("email", emailA);
  simulateA.searchParams.set("verified", "true");
  simulateA.searchParams.set("uid", uid);
  await page.goto(simulateA.pathname + simulateA.search);
  await context.clearCookies();

  // User B: register and attempt to link the same uid=X
  const emailB = `test-oauth-conflict-b-${Date.now()}@example.com`;
  await registerUser(page, emailB, "Test1234!");
  const linkRespB = await page.request.get("/oauth/google/link", {
    maxRedirects: 0,
  });
  expect(linkRespB.status()).toBe(307);
  const simulateB = new URL(
    linkRespB.headers()["location"]!,
    "http://127.0.0.1:3100"
  );
  simulateB.searchParams.set("email", emailB);
  simulateB.searchParams.set("verified", "true");
  simulateB.searchParams.set("uid", uid);

  // Follow simulate → callback manually; the callback returns 409 JSON (no redirect)
  const simulateResp = await page.request.get(
    simulateB.pathname + simulateB.search,
    { maxRedirects: 0 }
  );
  expect(simulateResp.status()).toBe(307);
  const callbackUrl = simulateResp.headers()["location"]!;
  const conflictResp = await page.request.get(callbackUrl, {
    maxRedirects: 0,
  });
  expect(conflictResp.status()).toBe(409);
});
