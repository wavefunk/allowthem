import { test, expect, Page } from "@playwright/test";
import {
  registerUser,
  requestPasswordReset,
  enableMfa,
  extractResetToken,
} from "./fixtures";

// M3 frontend revamp — visual QA for the 8 migrated auth templates.
//
// Asserts shell inheritance (wf-auth + wf-auth-splash + wf-statusbar), bans
// a curated set of Tailwind / at-* / legacy-shell substrings, and exercises
// the dark/light mode toggle. Covers the same ground as the Rust-side
// auth_template_guard_tests.rs but against a running browser.
//
// M6.2 flipped the polarity: at-auth-shell / at-form-pane / at-form-wrap are
// now forbidden; wf-auth + wf-auth-splash are required.

const FORBIDDEN = [
  "bg-gray-50",
  "bg-red-50",
  "bg-green-50",
  "bg-yellow-50",
  "bg-blue-600",
  "text-gray-900",
  "text-gray-700",
  "text-gray-600",
  "text-gray-500",
  "text-blue-600",
  "min-h-screen",
  "max-w-md",
  "focus:ring-blue-500",
  "at-btn-primary",
  "at-input-focus",
  "at-link",
  "at-auth-shell",
  "at-form-pane",
  "at-form-wrap",
];

async function expectShellStructure(page: Page) {
  await expect(page.locator("body.wf-auth")).toHaveCount(1);
  await expect(page.locator(".wf-auth-splash")).toHaveCount(1);
  await expect(page.locator(".wf-statusbar")).toHaveCount(1);
}

async function expectNoForbiddenSubstrings(page: Page) {
  const html = await page.content();
  for (const needle of FORBIDDEN) {
    expect(html, `page contains forbidden substring "${needle}"`).not.toContain(
      needle,
    );
  }
}

test.describe("M3 auth templates — shell + no Tailwind residue", () => {
  test("/login renders _auth_shell with no Tailwind residue", async ({
    page,
  }) => {
    await page.goto("/login");
    await expectShellStructure(page);
    await expectNoForbiddenSubstrings(page);
  });

  test("/register renders _auth_shell with no Tailwind residue", async ({
    page,
  }) => {
    await page.goto("/register");
    await expectShellStructure(page);
    await expectNoForbiddenSubstrings(page);
  });

  test("/forgot-password renders _auth_shell with no Tailwind residue", async ({
    page,
  }) => {
    await page.goto("/forgot-password");
    await expectShellStructure(page);
    await expectNoForbiddenSubstrings(page);
  });

  test("/auth/reset-password with no token renders the friendly error via shell", async ({
    page,
  }) => {
    await page.goto("/auth/reset-password");
    await expectShellStructure(page);
    await expectNoForbiddenSubstrings(page);
  });

  test("/auth/reset-password with invalid token renders via shell", async ({
    page,
  }) => {
    await page.goto("/auth/reset-password?token=invalid-token-xyz");
    await expectShellStructure(page);
    await expectNoForbiddenSubstrings(page);
  });

  test("/auth/reset-password with a live token renders the form via shell", async ({
    page,
  }) => {
    const email = `m3-reset-${Date.now()}@example.com`;
    const password = "ResetE2E1234!";
    await registerUser(page, email, password);
    await page.goto("/logout").catch(() => {});
    await requestPasswordReset(page, email);
    // Wait for the generic success confirmation before polling the log —
    // the handler writes the reset-email body synchronously before responding,
    // so once we see the success banner the log line is guaranteed to exist.
    await expect(
      page.locator("text=If an account with that email exists"),
    ).toBeVisible();
    const token = await extractResetToken(email);
    await page.goto(`/auth/reset-password?token=${token}`);
    await expectShellStructure(page);
    await expectNoForbiddenSubstrings(page);
    await expect(page.locator('input[name="new_password"]')).toBeVisible();
  });

  test("/settings/mfa/setup renders via shell (authenticated)", async ({
    page,
  }) => {
    const email = `m3-mfa-setup-${Date.now()}@example.com`;
    await registerUser(page, email, "MfaE2E1234!");
    await page.goto("/settings/mfa/setup");
    await expectShellStructure(page);
    await expectNoForbiddenSubstrings(page);
    await expect(page.locator('[data-testid="totp-uri"]')).toBeVisible();
    await expect(page.locator('[data-testid="totp-secret"]')).toBeVisible();
  });

  test("/settings/mfa/recovery (after enabling MFA) renders via shell", async ({
    page,
  }) => {
    const email = `m3-mfa-rec-${Date.now()}@example.com`;
    await registerUser(page, email, "MfaE2E1234!");
    const codes = await enableMfa(page);
    expect(codes.length).toBeGreaterThan(0);
    // enableMfa lands on the recovery view directly
    await expectShellStructure(page);
    await expectNoForbiddenSubstrings(page);
  });

  // Direct-GET coverage of /mfa/challenge is deliberately omitted: the
  // handler redirects to /login when the token is not live, and exercising
  // a live challenge requires the full MFA login flow (covered by mfa-*.spec.ts).
  // Shell structure for mfa_challenge.html is guarded by the Rust
  // auth_template_guard_tests.rs suite.
});

test.describe("M3 auth templates — dark/light mode toggle", () => {
  test("toggle flips the document mode and persists across navigations", async ({
    page,
  }) => {
    await page.goto("/login");

    // mode-toggle.js treats an unset data-mode as "dark"; the first click
    // therefore always yields "light". Drive the invariant from what click
    // produces rather than from the unset initial attribute.
    const toggle = page.locator("[data-mode-toggle]");
    await toggle.click();
    const afterMode = await page.evaluate(() =>
      document.documentElement.getAttribute("data-mode"),
    );
    expect(["dark", "light"]).toContain(afterMode);

    await toggle.click();
    const flippedMode = await page.evaluate(() =>
      document.documentElement.getAttribute("data-mode"),
    );
    expect(flippedMode).not.toBe(afterMode);
    expect(["dark", "light"]).toContain(flippedMode);

    // Navigate to a different auth page and confirm mode survives
    await page.goto("/register");
    const persistedMode = await page.evaluate(() =>
      document.documentElement.getAttribute("data-mode"),
    );
    expect(persistedMode).toBe(flippedMode);
  });
});

test.describe("M3 auth templates — no console errors on first paint", () => {
  const pages = [
    "/login",
    "/register",
    "/forgot-password",
    "/auth/reset-password",
  ];

  for (const path of pages) {
    test(`${path} logs no console errors`, async ({ page }) => {
      const errors: string[] = [];
      // Chromium auto-requests /favicon.ico which the server doesn't serve;
      // that 404 is unrelated to template correctness, so ignore it here.
      const isIgnorableRequestFailure = (url: string): boolean =>
        url.endsWith("/favicon.ico");

      page.on("pageerror", (err) => errors.push(err.message));
      page.on("requestfailed", (req) => {
        if (isIgnorableRequestFailure(req.url())) return;
        errors.push(`requestfailed ${req.url()}: ${req.failure()?.errorText}`);
      });
      page.on("response", (resp) => {
        if (resp.status() >= 400 && !isIgnorableRequestFailure(resp.url())) {
          // Only surface subresource failures — the main document navigation
          // is checked separately by the shell-structure tests.
          if (resp.url() !== page.url()) {
            errors.push(`HTTP ${resp.status()} from ${resp.url()}`);
          }
        }
      });
      page.on("console", (msg) => {
        if (msg.type() !== "error") return;
        const text = msg.text();
        // "Failed to load resource" console messages duplicate the response
        // events above without carrying the URL; rely on the response handler
        // to report real subresource failures and drop the console noise.
        if (text.startsWith("Failed to load resource")) return;
        errors.push(text);
      });
      await page.goto(path);
      await page.waitForLoadState("networkidle");
      expect(errors, `console errors on ${path}: ${errors.join(" | ")}`).toEqual(
        [],
      );
    });
  }
});
