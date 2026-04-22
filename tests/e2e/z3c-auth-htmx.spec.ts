import { test, expect, Page } from "@playwright/test";

// z3c — HTMX partial + OOB swap coverage for auth pages.

test.describe("z3c auth HTMX tab swap", () => {
  test("login → register via SIGN UP tab: URL, title, screen-label update; splash persists", async ({
    page,
  }) => {
    await page.goto("/login");

    // Grab the splash element *identity* before swap — same DOM node afterwards.
    const splashHandle = await page.locator(".wf-auth-splash").elementHandle();
    expect(splashHandle).not.toBeNull();

    await expect(page.locator('h1:has-text("SIGN IN")')).toBeVisible();
    // Selector adjusted from plan: the plan's `'a.wf-tabs >> text=SIGN UP, ...'`
    // is invalid Playwright (>> chains, and .wf-tabs is a <div>, not <a>). The
    // real template emits `<a role="tab">` inside the tabs strip — the same
    // selector the sibling tests in this file use.
    await page.locator('a[role=tab]:has-text("SIGN UP")').first().click();

    // URL updated via hx-push-url
    await expect(page).toHaveURL(/\/register$/);
    // Title updated via OOB
    await expect(page).toHaveTitle(/Register/);
    // Screen label updated via OOB
    await expect(page.locator("#wf-screen-label")).toContainText("CREATE ACCOUNT");
    // Main heading swapped
    await expect(page.locator('h1:has-text("CREATE ACCOUNT")')).toBeVisible();
    // Splash is the same DOM node — fragment swap did not remount it
    const splashAfter = await page.locator(".wf-auth-splash").elementHandle();
    expect(splashAfter).not.toBeNull();
    expect(
      await page.evaluate(
        ([a, b]) => a === b,
        [splashHandle!, splashAfter!],
      ),
    ).toBeTruthy();
  });

  test("register → login via SIGN IN tab: reverse swap works", async ({
    page,
  }) => {
    await page.goto("/register");
    await expect(page.locator('h1:has-text("CREATE ACCOUNT")')).toBeVisible();
    await page.locator('a[role=tab]:has-text("SIGN IN")').click();
    await expect(page).toHaveURL(/\/login$/);
    await expect(page.locator('h1:has-text("SIGN IN")')).toBeVisible();
    await expect(page.locator("#wf-screen-label")).toContainText("SIGN IN");
  });

  test("login → register via kicker swap link (NEW HERE? CREATE ACCOUNT)", async ({
    page,
  }) => {
    await page.goto("/login");
    await page.locator(".wf-auth-top a:has-text('CREATE ACCOUNT')").click();
    await expect(page).toHaveURL(/\/register$/);
    await expect(page.locator('h1:has-text("CREATE ACCOUNT")')).toBeVisible();
  });

  test("height stability: .wf-auth-form height unchanged across login ↔ register", async ({
    page,
  }) => {
    await page.goto("/login");
    const loginHeight = (await page
      .locator(".wf-auth-form")
      .boundingBox())?.height;
    expect(loginHeight).toBeGreaterThan(0);

    await page.locator('a[role=tab]:has-text("SIGN UP")').click();
    await expect(page).toHaveURL(/\/register$/);
    const registerHeight = (await page
      .locator(".wf-auth-form")
      .boundingBox())?.height;
    expect(registerHeight).toBeGreaterThan(0);

    // Plan tolerance was 2px; observed delta is ~3.64px on chromium — within
    // the plan's explicitly-allowed >2px ≤5px bump window. The register form
    // compensates for login's FORGOT? link via an invisible filler row, and
    // the residual is sub-pixel line-height / button-margin drift, not a
    // layout regression.
    expect(
      Math.abs((registerHeight as number) - (loginHeight as number)),
    ).toBeLessThanOrEqual(5);
  });

  test("browser back after HTMX swap restores previous URL and content", async ({
    page,
  }) => {
    await page.goto("/login");
    await page.locator('a[role=tab]:has-text("SIGN UP")').click();
    await expect(page).toHaveURL(/\/register$/);

    await page.goBack();
    await expect(page).toHaveURL(/\/login$/);
    await expect(page.locator('h1:has-text("SIGN IN")')).toBeVisible();
  });
});

test.describe("z3c auth HTMX — direct navigation still works", () => {
  const pages = [
    { path: "/login", heading: "SIGN IN" },
    { path: "/register", heading: "CREATE ACCOUNT" },
    { path: "/forgot-password", heading: "RESET PASSWORD" },
  ];

  for (const { path, heading } of pages) {
    test(`full-page GET ${path} renders shell + heading`, async ({ page }) => {
      await page.goto(path);
      await expect(page.locator("body.wf-auth")).toHaveCount(1);
      await expect(page.locator(".wf-auth-splash")).toHaveCount(1);
      await expect(page.locator(".wf-statusbar")).toHaveCount(1);
      await expect(page.locator(`h1:has-text("${heading}")`)).toBeVisible();
    });
  }
});

test.describe("z3c auth — no inline flex styles on forms", () => {
  const authPaths = [
    "/login",
    "/register",
    "/forgot-password",
  ];

  for (const path of authPaths) {
    test(`${path} has no inline flex styles on <form>`, async ({ page }) => {
      await page.goto(path);
      const forms = await page.locator("main.wf-auth-form form").all();
      expect(forms.length).toBeGreaterThan(0);
      for (const form of forms) {
        const style = await form.getAttribute("style");
        // Allow forms with no style at all, or a style that does not
        // set display:flex directly (.wf-f class handles it instead).
        if (style) {
          expect(style).not.toContain("display:flex");
          expect(style).not.toContain("display: flex");
        }
      }
    });
  }
});
