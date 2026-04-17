import { test, expect } from "@playwright/test";
import { registerUser } from "./fixtures";

test("logout > happy path: session destroyed and redirect to /login", async ({
  page,
  context,
}) => {
  const email = `test-logout-${Date.now()}@example.com`;
  await registerUser(page, email, "Test1234!");

  // Confirm we're authenticated — settings page loads without redirect
  await page.goto("/settings");
  await expect(page).not.toHaveURL(/\/login/);

  // Logout
  await page.goto("/logout");
  await expect(page).toHaveURL("/login");

  // Confirm session is gone — settings now redirects to /login
  await page.goto("/settings");
  await expect(page).toHaveURL(/\/login/);

  // Confirm session cookie is cleared (Max-Age=0 causes browsers to delete it,
  // so the cookie should no longer be present in the context)
  const cookies = await context.cookies();
  const sessionCookie = cookies.find(
    (c) => c.name === "allowthem_session" && c.value !== ""
  );
  expect(sessionCookie).toBeUndefined();
});

test("logout > unauthenticated: graceful redirect to /login without error", async ({
  page,
}) => {
  // No session cookie — plain page fixture starts unauthenticated
  await page.goto("/logout");
  await expect(page).toHaveURL("/login");
  // Page should render the login form, not an error page
  await expect(page.locator('input[name="identifier"]')).toBeVisible();
});
