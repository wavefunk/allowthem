import { test, expect } from "@playwright/test";
import { registerUser, loginExpectingError } from "./fixtures";

test("login > rate limit: after exceeding limit shows rate-limit message", async ({
  page,
}) => {
  test.setTimeout(30_000);
  const email = `test-rl-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  await page.context().clearCookies();

  // Get a CSRF token by loading the login page
  await page.goto("/login");
  const csrfToken = await page
    .locator('input[name="csrf_token"]')
    .inputValue();

  // Exhaust the rate limit (ALLOWTHEM_MAX_LOGIN_ATTEMPTS=50 in global-setup.ts)
  for (let i = 0; i < 51; i++) {
    await page.request.post("/login", {
      form: {
        identifier: email,
        password: "wrong",
        csrf_token: csrfToken,
      },
    });
  }

  // Now attempt via browser — should see rate-limit error
  await loginExpectingError(page, email, "wrong");
  await expect(
    page.locator("text=Too many login attempts. Please try again later.")
  ).toBeVisible();
});
