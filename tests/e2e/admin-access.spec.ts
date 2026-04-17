import { test, expect } from "./fixtures";

// These tests do not mutate server state, no serial mode required.

// --- Non-admin 403 ---

test("admin access > non-admin user gets 403 at /admin/sessions", async ({
  authenticatedPage: page,
}) => {
  const resp = await page.goto("/admin/sessions");
  expect(resp?.status()).toBe(403);
});

test("admin access > non-admin user gets 403 at /admin/audit", async ({
  authenticatedPage: page,
}) => {
  const resp = await page.goto("/admin/audit");
  expect(resp?.status()).toBe(403);
});

// --- Unauthenticated redirect ---

test("admin access > unauthenticated /admin/sessions redirects to login with next param", async ({
  page,
}) => {
  await page.goto("/admin/sessions");
  await expect(page).toHaveURL(/\/login/);
  expect(page.url()).toContain("next=");
});

test("admin access > unauthenticated /admin/audit redirects to login with next param", async ({
  page,
}) => {
  await page.goto("/admin/audit");
  await expect(page).toHaveURL(/\/login/);
  expect(page.url()).toContain("next=");
});
