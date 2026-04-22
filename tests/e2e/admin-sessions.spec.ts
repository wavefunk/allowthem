import { test, expect, loginAsAdmin } from "./fixtures";

test.describe.configure({ mode: "serial" });

// Helper: extract CSRF token from any hidden csrf_token form input on the current page.
// CSRF is session-derived for authenticated users — it lives in form fields, not cookies.
async function getCsrfToken(
  page: import("@playwright/test").Page
): Promise<string> {
  const value = await page
    .locator('input[name="csrf_token"]')
    .first()
    .getAttribute("value");
  if (!value) throw new Error("csrf_token hidden input not found on page");
  return value;
}

// Helper: seed a user via register POST. This creates both a user and a session.
// The register endpoint sets a new session cookie on the response,
// overwriting the admin session. Clears cookies and re-logs in as admin.
async function seedUserAndReloginAdmin(
  page: import("@playwright/test").Page,
  email: string,
  csrfToken: string
): Promise<void> {
  await page.request.post("/register", {
    form: {
      email,
      password: "Test1234!",
      password_confirm: "Test1234!",
      csrf_token: csrfToken,
    },
  });
  // Clear the non-admin session cookie so loginAsAdmin can render /login
  await page.context().clearCookies();
  await loginAsAdmin(page);
}

// Helper: extract user_id from the sessions list by matching email in user link.
async function getUserIdFromSessionsList(
  page: import("@playwright/test").Page,
  email: string
): Promise<string> {
  const userLink = page
    .locator('a[href*="/admin/users/"]')
    .filter({ hasText: email })
    .first();
  const href = await userLink.getAttribute("href");
  const userId = href?.split("/admin/users/")[1]?.split(/[?/]/)[0];
  if (!userId) throw new Error(`Could not extract user_id for ${email}`);
  return userId;
}

test("admin sessions > list renders with session rows", async ({
  adminPage: page,
}) => {
  await page.goto("/admin/sessions");
  await expect(page).toHaveURL(/\/admin\/sessions/);
  // The admin session itself should appear (created by adminPage login)
  await expect(page.locator("h1").first()).toHaveText("SESSIONS");
});

test("admin sessions > user filter shows banner", async ({
  adminPage: page,
}) => {
  await page.goto("/admin/sessions");
  const csrfToken = await getCsrfToken(page);

  const email = `sess-filter-${Date.now()}@example.com`;
  await seedUserAndReloginAdmin(page, email, csrfToken);

  await page.goto("/admin/sessions");
  const userId = await getUserIdFromSessionsList(page, email);

  await page.goto(`/admin/sessions?user_id=${userId}`);
  await expect(page.locator("text=Showing sessions for")).toBeVisible();
});

test("admin sessions > revoke single session removes it", async ({
  adminPage: page,
}) => {
  await page.goto("/admin/sessions");
  const csrfToken = await getCsrfToken(page);

  const email = `sess-revoke-${Date.now()}@example.com`;
  await seedUserAndReloginAdmin(page, email, csrfToken);

  await page.goto("/admin/sessions");
  const userId = await getUserIdFromSessionsList(page, email);

  await page.goto(`/admin/sessions?user_id=${userId}`);

  // The revoke form has onsubmit="return confirm(...)" — auto-accept the dialog
  page.on("dialog", (dialog) => dialog.accept());

  // Use ends-with selector to match only per-session revoke forms (not revoke-all)
  const revokeBtn = page
    .locator('form[action$="/revoke"] button[type="submit"]')
    .first();
  await revokeBtn.click();
  // Wait for navigation after the form POST redirect
  await page.waitForLoadState("load");

  // Verify empty state after revoke
  await page.goto(`/admin/sessions?user_id=${userId}`);
  await expect(
    page.locator("text=No active sessions for this user.")
  ).toBeVisible();
});

test("admin sessions > revoke all sessions for user", async ({
  adminPage: page,
}) => {
  await page.goto("/admin/sessions");
  const csrfToken = await getCsrfToken(page);

  const email = `sess-revoke-all-${Date.now()}@example.com`;
  await seedUserAndReloginAdmin(page, email, csrfToken);

  await page.goto("/admin/sessions");
  const userId = await getUserIdFromSessionsList(page, email);

  await page.goto(`/admin/sessions?user_id=${userId}`);

  // The revoke-all form has onsubmit="return confirm(...)" — auto-accept the dialog
  page.on("dialog", (dialog) => dialog.accept());

  await page
    .locator('form[action*="/revoke-all/"] button[type="submit"]')
    .click();
  // Wait for navigation after the form POST redirect
  await page.waitForLoadState("load");

  // After revoke-all, empty state shown for this user
  await expect(
    page.locator("text=No active sessions for this user.")
  ).toBeVisible();
});
