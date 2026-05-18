import { test, expect } from "@playwright/test";
import { loginExpectingError } from "./fixtures";

test("login > rate limit: after exceeding limit shows rate-limit message", async ({
  page,
}) => {
  test.setTimeout(90_000);
  const email = `missing-rl-${Date.now()}@example.com`;

  // Get a CSRF token by loading the login page
  await page.goto("/login");
  const csrfToken = await page
    .locator('input[name="csrf_token"]')
    .inputValue();

  // Exhaust the rate limit (ALLOWTHEM_MAX_LOGIN_ATTEMPTS=50 in global-setup.ts)
  let sawRateLimit = false;
  for (let i = 0; i < 51; i++) {
    const resp = await page.request.post("/login", {
      form: {
        identifier: email,
        password: "wrong",
        csrf_token: csrfToken,
      },
    });
    if (resp.status() === 429) {
      sawRateLimit = true;
      break;
    }
  }
  expect(sawRateLimit).toBe(true);

  // Now attempt via browser — should see rate-limit error
  await loginExpectingError(page, email, "wrong");
  await expect(
    page.locator("text=Too many login attempts. Please try again later.")
  ).toBeVisible();
});
