import { test, expect } from "@playwright/test";
import { registerUser, enableMfa } from "./fixtures";

test("mfa recovery > valid recovery code creates session and decrements count", async ({
  page,
  context,
}) => {
  const email = `test-mfa-rec-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  const recoveryCodes = await enableMfa(page);
  const recoveryCode = recoveryCodes[0];

  await page.goto("/logout");
  await context.clearCookies();

  // Go to login, enter credentials
  await page.goto("/login");
  await page.locator('input[name="identifier"]').fill(email);
  await page.locator('input[name="password"]').fill("Test1234!");
  await page.locator('button[type="submit"]').click();
  await page.waitForURL(/\/mfa\/challenge/);

  // Switch to recovery code input
  await page.locator('label[for="use_recovery"]').click();
  await page.locator('input[name="recovery_code"]').fill(recoveryCode);
  await page.locator('button[type="submit"]').click();
  // Should succeed and redirect to /
  await expect(page).toHaveURL("/");
  const cookies = await context.cookies();
  expect(cookies.find((c) => c.name === "allowthem_session")).toBeDefined();

  // Recovery count should be 9
  await page.goto("/settings");
  await expect(
    page.locator("text=9 of 10 recovery codes remaining")
  ).toBeVisible();
});

test("mfa recovery > invalid recovery code shows error", async ({
  page,
  context,
}) => {
  const email = `test-mfa-badrec-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  await enableMfa(page);

  await page.goto("/logout");
  await context.clearCookies();

  await page.goto("/login");
  await page.locator('input[name="identifier"]').fill(email);
  await page.locator('input[name="password"]').fill("Test1234!");
  await page.locator('button[type="submit"]').click();
  await page.waitForURL(/\/mfa\/challenge/);

  await page.locator('label[for="use_recovery"]').click();
  await page.locator('input[name="recovery_code"]').fill("AAAAAAAA");
  await page.locator('button[type="submit"]').click();
  // Should stay on challenge with error
  await expect(page).toHaveURL(/\/mfa\/challenge/);
  await expect(page.locator("text=Invalid recovery code")).toBeVisible();
});

test("mfa recovery > already-used recovery code is rejected", async ({
  page,
  context,
}) => {
  const email = `test-mfa-usedrec-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  const recoveryCodes = await enableMfa(page);
  const recoveryCode = recoveryCodes[0];

  // Use the code once (via recovery login)
  await page.goto("/logout");
  await context.clearCookies();
  await page.goto("/login");
  await page.locator('input[name="identifier"]').fill(email);
  await page.locator('input[name="password"]').fill("Test1234!");
  await page.locator('button[type="submit"]').click();
  await page.waitForURL(/\/mfa\/challenge/);
  await page.locator('label[for="use_recovery"]').click();
  await page.locator('input[name="recovery_code"]').fill(recoveryCode);
  await page.locator('button[type="submit"]').click();
  await expect(page).toHaveURL("/");

  // Try the same code again
  await page.goto("/logout");
  await context.clearCookies();
  await page.goto("/login");
  await page.locator('input[name="identifier"]').fill(email);
  await page.locator('input[name="password"]').fill("Test1234!");
  await page.locator('button[type="submit"]').click();
  await page.waitForURL(/\/mfa\/challenge/);
  await page.locator('label[for="use_recovery"]').click();
  await page.locator('input[name="recovery_code"]').fill(recoveryCode);
  await page.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/\/mfa\/challenge/);
  await expect(page.locator("text=Invalid recovery code")).toBeVisible();
});
