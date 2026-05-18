import { test, expect, Page } from "@playwright/test";

// z3c — HTMX partial + OOB swap coverage for auth pages.

test.describe("z3c auth HTMX tab swap", () => {
  test("login → register via SIGN UP tab: URL, title, screen-label update; splash persists", async ({
    page,
  }) => {
    await page.goto("/login");

    // Grab the visual pane identity before swap — same DOM node afterwards.
    const visualHandle = await page.locator(".wf-split-shell-visual").elementHandle();
    expect(visualHandle).not.toBeNull();

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
    // Visual pane is the same DOM node — fragment swap did not remount it
    const visualAfter = await page.locator(".wf-split-shell-visual").elementHandle();
    expect(visualAfter).not.toBeNull();
    expect(
      await page.evaluate(
        ([a, b]) => a === b,
        [visualHandle!, visualAfter!],
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

  test("SplitShell content column remains stable across login ↔ register", async ({
    page,
  }) => {
    await page.goto("/login");
    const loginBox = await page
      .locator(".wf-auth-form")
      .boundingBox();
    expect(loginBox?.height).toBeGreaterThan(0);

    await page.locator('a[role=tab]:has-text("SIGN UP")').click();
    await expect(page).toHaveURL(/\/register$/);
    const registerBox = await page
      .locator(".wf-auth-form")
      .boundingBox();
    expect(registerBox?.height).toBeGreaterThan(0);

    expect(Math.abs((registerBox?.x ?? 0) - (loginBox?.x ?? 0))).toBeLessThanOrEqual(1);
    expect(Math.abs((registerBox?.width ?? 0) - (loginBox?.width ?? 0))).toBeLessThanOrEqual(1);
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
      await expect(page.locator(".wf-split-shell")).toHaveCount(1);
      await expect(page.locator(".wf-split-shell-visual")).toHaveCount(1);
      await expect(page.locator(".wf-modeline")).toHaveCount(1);
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
