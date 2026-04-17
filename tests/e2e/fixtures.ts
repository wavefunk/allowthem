import * as fs from "fs";
import * as path from "path";
import { test as base, Page } from "@playwright/test";

export async function registerUser(
  page: Page,
  email: string,
  password: string
): Promise<void> {
  await page.goto("/register");
  await page.locator('input[name="email"]').fill(email);
  await page.locator('input[name="password"]').fill(password);
  await page.locator('input[name="password_confirm"]').fill(password);
  await page.locator('button[type="submit"]').click();
  await page.waitForURL((url) => !url.pathname.startsWith("/register"));
}

export async function loginUser(
  page: Page,
  email: string,
  password: string
): Promise<void> {
  await page.goto("/login");
  // The login form uses `identifier` to accept both email and username
  await page.locator('input[name="identifier"]').fill(email);
  await page.locator('input[name="password"]').fill(password);
  await page.locator('button[type="submit"]').click();
  await page.waitForURL((url) => !url.pathname.startsWith("/login"));
}

export async function registerExpectingError(
  page: Page,
  email: string,
  password: string,
  passwordConfirm: string = password
): Promise<void> {
  await page.goto("/register");
  await page.locator('input[name="email"]').fill(email);
  await page.locator('input[name="password"]').fill(password);
  await page.locator('input[name="password_confirm"]').fill(passwordConfirm);
  await page.locator('button[type="submit"]').click();
  // No waitForURL — error case stays on /register
}

export async function loginExpectingError(
  page: Page,
  identifier: string,
  password: string
): Promise<void> {
  await page.goto("/login");
  await page.locator('input[name="identifier"]').fill(identifier);
  await page.locator('input[name="password"]').fill(password);
  await page.locator('button[type="submit"]').click();
  // No waitForURL — error case stays on /login
}

export async function requestPasswordReset(
  page: Page,
  email: string
): Promise<void> {
  await page.goto("/forgot-password");
  await page.locator('input[name="email"]').fill(email);
  await page.locator('button[type="submit"]').click();
  // No waitForURL — success state renders in-place
}

export async function extractResetToken(email: string): Promise<string> {
  const logPath = path.resolve(__dirname, "server.log");
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const content = fs.readFileSync(logPath, "utf8");
    const lines = content.split("\n").filter((l) => l.includes(email));
    for (const line of lines.reverse()) {
      // Anchor to body=" to avoid matching the html= field (both carry the same URL
      // on the same tracing span line). LogEmailSender logs: body=<URL> html=<URL>.
      const m = line.match(
        /body="[^"]*auth\/reset-password\?token=([A-Za-z0-9_-]{43})/
      );
      if (m) return m[1];
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`Reset token for ${email} not found in server.log within 5s`);
}

// ---------------------------------------------------------------------------
// OAuth helpers
// ---------------------------------------------------------------------------

export interface MockOAuthIdentity {
  email: string;
  verified?: boolean; // default: true
  uid?: string; // default: identity.email
  name?: string;
}

export async function oauthLogin(
  page: Page,
  provider: "google" | "github",
  identity: MockOAuthIdentity
): Promise<void> {
  // Intercept the redirect to /test-oauth/simulate and inject identity params.
  // page.route() on a local URL is safe — no cross-origin concerns.
  await page.route("**/test-oauth/simulate**", async (route) => {
    const url = new URL(route.request().url());
    url.searchParams.set("email", identity.email);
    url.searchParams.set("verified", String(identity.verified ?? true));
    url.searchParams.set("uid", identity.uid ?? identity.email);
    if (identity.name) url.searchParams.set("name", identity.name);
    await route.continue({ url: url.toString() });
  });

  await page.goto(`/oauth/${provider}/authorize`);
  // Chain: authorize → 307 simulate (intercepted, identity injected)
  //        simulate → 307 /oauth/{provider}/callback?code=...&state=...
  //        callback → session cookie + 307 /
  await page.waitForURL((url) => !url.pathname.startsWith("/oauth"));
  await page.unroute("**/test-oauth/simulate**");
}

export async function oauthLoginExpectingError(
  page: Page,
  provider: "google" | "github",
  identity: MockOAuthIdentity
): Promise<void> {
  await page.route("**/test-oauth/simulate**", async (route) => {
    const url = new URL(route.request().url());
    url.searchParams.set("email", identity.email);
    url.searchParams.set("verified", String(identity.verified ?? true));
    url.searchParams.set("uid", identity.uid ?? identity.email);
    if (identity.name) url.searchParams.set("name", identity.name);
    await route.continue({ url: url.toString() });
  });

  await page.goto(`/oauth/${provider}/authorize`);
  // On error the flow does not complete to a non-oauth URL.
  await page.unroute("**/test-oauth/simulate**");
}

export const test = base.extend<{ authenticatedPage: Page }>({
  authenticatedPage: async ({ page }, use) => {
    const email = `test-${Date.now()}@example.com`;
    const password = "Test1234!";
    // registerUser creates the user and sets an active session cookie
    await registerUser(page, email, password);
    await use(page);
  },
});

export { expect } from "@playwright/test";
