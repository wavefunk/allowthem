import { test, expect } from "@playwright/test";
import {
  registerUser,
  loginUser,
  loginExpectingError,
  requestPasswordReset,
  extractResetToken,
} from "./fixtures";

test.describe.configure({ mode: "serial" });

test("password-reset > happy path: request reset, set new password, new password works, old password rejected", async ({
  page,
  context,
}) => {
  const email = `test-pr-happy-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  await page.goto("/logout");

  // Request reset
  await requestPasswordReset(page, email);
  await expect(
    page.locator("text=If an account with that email exists")
  ).toBeVisible();

  // Extract token from server log and visit reset URL
  const token = await extractResetToken(email);
  await page.goto(`/auth/reset-password?token=${token}`);
  await expect(page.locator('input[name="new_password"]')).toBeVisible();
  await expect(page.locator('input[name="confirm_password"]')).toBeVisible();

  // Set new password
  await page.locator('input[name="new_password"]').fill("NewPass999!");
  await page.locator('input[name="confirm_password"]').fill("NewPass999!");
  await page.locator('button[type="submit"]').click();
  await expect(page.locator("text=Your password has been reset")).toBeVisible();

  // Login with new password succeeds
  await loginUser(page, email, "NewPass999!");
  await expect(page).toHaveURL("/");

  // Login with old password fails
  await context.clearCookies();
  await loginExpectingError(page, email, "Test1234!");
  await expect(page).toHaveURL(/\/login/);
  await expect(
    page.locator("text=Invalid email or password.")
  ).toBeVisible();
});

test("password-reset > unknown email: same success message (no enumeration)", async ({
  page,
}) => {
  await requestPasswordReset(page, `nobody-${Date.now()}@example.com`);
  await expect(
    page.locator("text=If an account with that email exists")
  ).toBeVisible();
});

test("password-reset > invalid email format: stays on forgot-password (browser validation)", async ({
  page,
}) => {
  await page.goto("/forgot-password");
  await page.locator('input[name="email"]').fill("notanemail");
  await page.locator('button[type="submit"]').click();
  // Browser type=email validation blocks submission — page stays on /forgot-password
  await expect(page).toHaveURL(/\/forgot-password/);
});

test("password-reset > invalid token: error state shown, form not rendered", async ({
  page,
}) => {
  await page.goto(
    "/auth/reset-password?token=invalidtoken12345678901234567890123456789012"
  );
  await expect(page.locator("text=invalid or has expired")).toBeVisible();
  await expect(page.locator('input[name="new_password"]')).not.toBeVisible();
});

test("password-reset > used token: error state shown", async ({ page }) => {
  const email = `test-pr-used-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  await page.goto("/logout");
  await requestPasswordReset(page, email);
  const token = await extractResetToken(email);

  // Use the token
  await page.goto(`/auth/reset-password?token=${token}`);
  await page.locator('input[name="new_password"]').fill("Used1234!");
  await page.locator('input[name="confirm_password"]').fill("Used1234!");
  await page.locator('button[type="submit"]').click();
  await expect(page.locator("text=Your password has been reset")).toBeVisible();

  // Try to use the same token again
  await page.goto(`/auth/reset-password?token=${token}`);
  await expect(page.locator("text=invalid or has expired")).toBeVisible();
});

test("password-reset > passwords do not match: inline error shown", async ({
  page,
}) => {
  const email = `test-pr-mismatch-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  await page.goto("/logout");
  await requestPasswordReset(page, email);
  const token = await extractResetToken(email);

  await page.goto(`/auth/reset-password?token=${token}`);
  await page.locator('input[name="new_password"]').fill("NewPass999!");
  await page.locator('input[name="confirm_password"]').fill("Different1!");
  await page.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/\/auth\/reset-password/);
  await expect(page.locator("text=Passwords do not match")).toBeVisible();
  // Token hidden field should still be present so user can retry
  await expect(page.locator('input[name="token"]')).not.toBeEmpty();
});

test("password-reset > password too short: inline error shown", async ({
  page,
}) => {
  const email = `test-pr-short-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  await page.goto("/logout");
  await requestPasswordReset(page, email);
  const token = await extractResetToken(email);

  await page.goto(`/auth/reset-password?token=${token}`);
  await page.locator('input[name="new_password"]').fill("short");
  await page.locator('input[name="confirm_password"]').fill("short");
  await page.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/\/auth\/reset-password/);
  await expect(
    page.locator("text=Password must be at least 8 characters")
  ).toBeVisible();
});
