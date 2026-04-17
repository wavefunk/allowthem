import { test, expect } from "@playwright/test";
import { registerUser, loginUser, loginExpectingError } from "./fixtures";

// Serial mode: rate-limit test must run last (it exhausts the IP counter).
test.describe.configure({ mode: "serial" });

test("login > happy path: valid credentials redirect to / and set session cookie", async ({
  page,
  context,
}) => {
  const email = `test-login-happy-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  await context.clearCookies();
  await loginUser(page, email, "Test1234!");
  await expect(page).toHaveURL("/");
  const cookies = await context.cookies();
  const sessionCookie = cookies.find((c) => c.name === "allowthem_session");
  expect(sessionCookie).toBeDefined();
});

test("login > error: wrong password shows invalid-credentials message", async ({
  page,
}) => {
  const email = `test-login-badpw-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  await page.context().clearCookies();
  await loginExpectingError(page, email, "wrongpassword");
  await expect(page).toHaveURL(/\/login/);
  await expect(page.locator("text=Invalid email or password.")).toBeVisible();
});

test("login > error: unknown user shows invalid-credentials message", async ({
  page,
}) => {
  await loginExpectingError(
    page,
    `nobody-${Date.now()}@example.com`,
    "Test1234!"
  );
  await expect(page).toHaveURL(/\/login/);
  await expect(page.locator("text=Invalid email or password.")).toBeVisible();
});

test("login > error: blank identifier shows invalid-credentials message", async ({
  page,
}) => {
  // The server returns LOGIN_ERROR for blank identifier (login.rs trims then checks empty).
  // The `identifier` field has `required` but no minlength — a single space satisfies
  // the browser required check, but the server trims it to empty and returns the error.
  await page.goto("/login");
  await page.locator('input[name="identifier"]').fill(" "); // whitespace trims to empty server-side
  await page.locator('input[name="password"]').fill("Test1234!");
  await page.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/\/login/);
  await expect(page.locator("text=Invalid email or password.")).toBeVisible();
});

test("login > already authenticated: redirect to /", async ({ page }) => {
  const email = `test-login-auth-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  // Already has session — GET /login redirects to /
  await page.goto("/login");
  await expect(page).toHaveURL("/");
});

// Rate-limit test MUST be last in this file (serial mode ensures ordering).
// It exhausts the IP counter for 127.0.0.1 for the remainder of the server's life.
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
