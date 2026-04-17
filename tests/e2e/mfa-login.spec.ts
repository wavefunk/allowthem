import { test, expect } from "@playwright/test";
import {
  registerUser,
  loginUser,
  enableMfa,
  loginWithMfaChallenge,
  generateTotpCode,
} from "./fixtures";

test("mfa login > valid TOTP code creates session and redirects to /", async ({
  page,
  context,
}) => {
  const email = `test-mfa-login-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  // Read secret before enableMfa navigates away from setup page
  await page.goto("/settings/mfa/setup");
  const secret = await page
    .locator('[data-testid="totp-secret"]')
    .textContent();
  if (!secret) throw new Error("secret not found");

  // Complete setup (post_mfa_confirm renders recovery page inline)
  await page.locator('input[name="code"]').fill(generateTotpCode(secret.trim()));
  await page.locator('button[type="submit"]').click();
  await page.locator('[data-testid="recovery-code"]').first().waitFor();

  // Log out, log back in
  await page.goto("/logout");
  await context.clearCookies();

  await loginWithMfaChallenge(
    page,
    email,
    "Test1234!",
    generateTotpCode(secret.trim())
  );
  await expect(page).toHaveURL("/");
  const cookies = await context.cookies();
  expect(cookies.find((c) => c.name === "allowthem_session")).toBeDefined();
});

test("mfa login > wrong TOTP code shows error and challenge remains", async ({
  page,
  context,
}) => {
  const email = `test-mfa-wrongcode-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  await enableMfa(page);
  await page.goto("/logout");
  await context.clearCookies();

  // Go to login, submit credentials
  await page.goto("/login");
  await page.locator('input[name="identifier"]').fill(email);
  await page.locator('input[name="password"]').fill("Test1234!");
  await page.locator('button[type="submit"]').click();
  await page.waitForURL(/\/mfa\/challenge/);

  // Submit wrong code
  await page.locator('input[name="code"]').fill("000000");
  await page.locator('button[type="submit"]').click();
  // Should stay on challenge page
  await expect(page).toHaveURL(/\/mfa\/challenge/);
  await expect(
    page.locator("text=Invalid TOTP or recovery code")
  ).toBeVisible();
});

test("mfa login > non-MFA user bypasses challenge and gets session", async ({
  page,
  context,
}) => {
  const email = `test-no-mfa-login-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  await page.goto("/logout");
  await context.clearCookies();
  await loginUser(page, email, "Test1234!");
  await expect(page).toHaveURL("/");
  const cookies = await context.cookies();
  expect(cookies.find((c) => c.name === "allowthem_session")).toBeDefined();
});

test("mfa login > disabled MFA bypasses challenge after disable", async ({
  page,
  context,
}) => {
  const email = `test-mfa-disabled-login-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  await enableMfa(page);
  // Disable MFA
  await page.goto("/settings");
  await page.locator('button:has-text("Disable 2FA")').click();
  // Log out + log in — should not see challenge
  await page.goto("/logout");
  await context.clearCookies();
  await loginUser(page, email, "Test1234!");
  await expect(page).toHaveURL("/");
});
