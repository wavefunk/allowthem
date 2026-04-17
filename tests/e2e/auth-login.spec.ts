import { test, expect } from "@playwright/test";
import { registerUser, loginUser, loginExpectingError } from "./fixtures";

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

