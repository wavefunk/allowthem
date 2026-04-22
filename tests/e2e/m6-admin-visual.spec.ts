import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./fixtures";

// Asserts admin shell inheritance (body.wf-app + .wf-shell + .wf-sidebar
// + .wf-main with either has-header or has-tablewrap) and bans every
// at-* residue class across a representative set of admin routes.
// Mirror of m3-auth-visual.spec.ts but for the admin surface post-M6.3.
// ROUTES is a surface-coverage sample — list/create/audit/sessions +
// /settings — not every admin page (detail/edit + MFA settings covered
// by the list-page assertion implicitly; if a detail-page specific
// regression appears later, extend ROUTES). /admin/users was excluded
// because the route is not wired yet (admin_template_render_tests.rs
// guards against sidebar links to it); re-add once the route lands.
const FORBIDDEN = [
  "at-app-shell",
  "at-sidebar",
  "at-main",
  "at-btn-primary",
  "at-input-focus",
  "at-link",
];

const ROUTES = [
  "/admin/applications",
  "/admin/applications/new",
  "/admin/audit",
  "/admin/sessions",
  "/settings",
];

test.describe("M6 admin visual QA", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  for (const route of ROUTES) {
    test(`${route} uses wf-app shell, no at-* residue`, async ({ page }) => {
      await page.goto(route);
      await expect(page.locator("body.wf-app")).toHaveCount(1);
      await expect(page.locator("div.wf-shell")).toHaveCount(1);
      await expect(page.locator("aside.wf-sidebar")).toHaveCount(1);
      const main = page.locator("div.wf-main");
      await expect(main).toHaveCount(1);
      const mainClass = await main.getAttribute("class");
      expect(mainClass).toMatch(/\b(has-header|has-tablewrap)\b/);
      const body = await page.content();
      for (const needle of FORBIDDEN) {
        expect(body, `${route}: found forbidden ${needle}`).not.toContain(
          needle
        );
      }
    });
  }
});
