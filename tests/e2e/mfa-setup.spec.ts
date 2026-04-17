import { test, expect } from "@playwright/test";
import { registerUser, enableMfa, generateTotpCode } from "./fixtures";

test("mfa setup > settings page shows mfa section as not configured", async ({
  page,
}) => {
  const email = `test-mfa-status-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  await page.goto("/settings");
  await expect(page.locator("text=Not configured")).toBeVisible();
});

test("mfa setup > enable MFA shows recovery codes", async ({ page }) => {
  const email = `test-mfa-setup-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  const recoveryCodes = await enableMfa(page);
  // 10 recovery codes returned
  expect(recoveryCodes).toHaveLength(10);
  // Each code is non-empty
  for (const code of recoveryCodes) {
    expect(code.length).toBeGreaterThan(0);
  }
});

test("mfa setup > settings shows enabled after setup", async ({ page }) => {
  const email = `test-mfa-enabled-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  await enableMfa(page);
  await page.goto("/settings");
  await expect(page.locator("text=Enabled")).toBeVisible();
  await expect(
    page.locator("text=10 of 10 recovery codes remaining")
  ).toBeVisible();
});

test("mfa setup > wrong code during setup shows error", async ({ page }) => {
  const email = `test-mfa-badcode-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  // Navigate to setup page
  await page.goto("/settings/mfa/setup");
  await expect(page).toHaveURL(/\/settings\/mfa\/setup/);
  // Submit wrong code
  await page.locator('input[name="code"]').fill("000000");
  await page.locator('button[type="submit"]').click();
  // Stay on setup page with error
  await expect(page.locator("text=Invalid TOTP code")).toBeVisible();
});

test("mfa setup > disable MFA reverts settings to not configured", async ({
  page,
}) => {
  const email = `test-mfa-disable-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  await enableMfa(page);
  // Disable MFA
  await page.goto("/settings");
  await page.locator('button:has-text("Disable 2FA")').click();
  // Confirm redirected to settings with MFA not configured
  await expect(page).toHaveURL(/\/settings/);
  await expect(page.locator("text=Not configured")).toBeVisible();
});
