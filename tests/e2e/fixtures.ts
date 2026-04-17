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
