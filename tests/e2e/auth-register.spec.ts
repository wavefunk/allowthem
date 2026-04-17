import { test, expect } from "@playwright/test";
import { registerUser, registerExpectingError } from "./fixtures";

test("register > happy path: valid credentials redirect to / and set session cookie", async ({
  page,
  context,
}) => {
  const email = `test-reg-happy-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  await expect(page).toHaveURL("/");
  const cookies = await context.cookies();
  const sessionCookie = cookies.find((c) => c.name === "allowthem_session");
  expect(sessionCookie).toBeDefined();
});

test("register > error: duplicate email shows inline message", async ({
  page,
  context,
}) => {
  const email = `test-reg-dup-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  await context.clearCookies();
  await registerExpectingError(page, email, "Test1234!");
  await expect(page).toHaveURL(/\/register/);
  await expect(
    page.locator("text=An account with this email already exists")
  ).toBeVisible();
});

test("register > error: password too short — browser minlength blocks submission", async ({
  page,
}) => {
  const email = `test-reg-short-${Date.now()}@example.com`;
  await page.goto("/register");
  await page.locator('input[name="email"]').fill(email);
  await page.locator('input[name="password"]').fill("abc");
  await page.locator('input[name="password_confirm"]').fill("abc");
  await page.locator('button[type="submit"]').click();
  // Browser minlength="8" blocks submission — URL stays at /register
  await expect(page).toHaveURL(/\/register/);
  const passwordField = page.locator('input[name="password"]');
  const isInvalid = await passwordField.evaluate(
    (el) => !(el as HTMLInputElement).validity.valid
  );
  expect(isInvalid).toBe(true);
});

test("register > error: passwords do not match shows inline message", async ({
  page,
}) => {
  const email = `test-reg-mismatch-${Date.now()}@example.com`;
  await registerExpectingError(page, email, "Test1234!", "Different1!");
  await expect(page).toHaveURL(/\/register/);
  await expect(page.locator("text=Passwords do not match")).toBeVisible();
});

test("register > error: duplicate username shows inline message", async ({
  page,
  context,
}) => {
  // Register a first account with a unique username.
  const suffix = Date.now();
  const firstEmail = `test-reg-user1-${suffix}@example.com`;
  const secondEmail = `test-reg-user2-${suffix}@example.com`;
  const username = `taken-${suffix}`;

  await page.goto("/register");
  await page.locator('input[name="email"]').fill(firstEmail);
  await page.locator('input[name="username"]').fill(username);
  await page.locator('input[name="password"]').fill("Test1234!");
  await page.locator('input[name="password_confirm"]').fill("Test1234!");
  await page.locator('button[type="submit"]').click();
  await page.waitForURL((url) => !url.pathname.startsWith("/register"));

  // Clear the session cookie so GET /register renders the form instead of redirecting.
  await context.clearCookies();

  // Second registration: distinct email, same username — should fail with inline error.
  await page.goto("/register");
  await page.locator('input[name="email"]').fill(secondEmail);
  await page.locator('input[name="username"]').fill(username);
  await page.locator('input[name="password"]').fill("Test1234!");
  await page.locator('input[name="password_confirm"]').fill("Test1234!");
  await page.locator('button[type="submit"]').click();

  await expect(page).toHaveURL(/\/register/);
  await expect(
    page.locator("text=This username is already taken")
  ).toBeVisible();
});

test("register > error: invalid email format — browser type=email blocks submission", async ({
  page,
}) => {
  await page.goto("/register");
  await page.locator('input[name="email"]').fill("notanemail");
  await page.locator('input[name="password"]').fill("Test1234!");
  await page.locator('input[name="password_confirm"]').fill("Test1234!");
  await page.locator('button[type="submit"]').click();
  // Browser type="email" blocks submission — URL stays at /register
  await expect(page).toHaveURL(/\/register/);
  const emailField = page.locator('input[name="email"]');
  const isInvalid = await emailField.evaluate(
    (el) => !(el as HTMLInputElement).validity.valid
  );
  expect(isInvalid).toBe(true);
});

test("register > blank fields: form does not submit (browser validation)", async ({
  page,
}) => {
  await page.goto("/register");
  await page.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/\/register/);
  // Email field is invalid per HTML5 constraint validation
  const emailField = page.locator('input[name="email"]');
  const isInvalid = await emailField.evaluate(
    (el) => !(el as HTMLInputElement).validity.valid
  );
  expect(isInvalid).toBe(true);
});

test("register > already authenticated: redirect to /", async ({ page }) => {
  const email = `test-reg-auth-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");
  // Already has session cookie — GET /register redirects to /
  await page.goto("/register");
  await expect(page).toHaveURL("/");
});
