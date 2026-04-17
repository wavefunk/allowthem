import { test, expect } from "@playwright/test";
import { test as fixtureTest, expect as fixtureExpect } from "./fixtures";

test("health endpoint returns 200", async ({ page }) => {
  await page.goto("/health");
  await expect(page.locator("body")).toContainText("ok");
});

test("login page renders the identifier and password fields", async ({
  page,
}) => {
  await page.goto("/login");
  await expect(page.locator('input[name="identifier"]')).toBeVisible();
  await expect(page.locator('input[name="password"]')).toBeVisible();
  await expect(page.locator('button[type="submit"]')).toBeVisible();
});

test("register page renders the registration form", async ({ page }) => {
  await page.goto("/register");
  await expect(page.locator('input[name="email"]')).toBeVisible();
  await expect(page.locator('input[name="password"]')).toBeVisible();
  await expect(page.locator('input[name="password_confirm"]')).toBeVisible();
  await expect(page.locator('button[type="submit"]')).toBeVisible();
});

fixtureTest(
  "register and login flow succeeds",
  async ({ authenticatedPage }) => {
    await authenticatedPage.goto("/settings");
    await fixtureExpect(authenticatedPage).not.toHaveURL(/\/login/);
    await fixtureExpect(
      authenticatedPage.locator('input[name="email"]')
    ).toBeVisible();
  }
);
