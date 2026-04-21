import * as fs from "fs";
import * as path from "path";

import { test, expect } from "@playwright/test";

const seededClientIdFile = path.resolve(__dirname, ".seeded-client-id");

test.describe("M5 accent override", () => {
  test("renders seeded --accent on login page", async ({ page }) => {
    const seededClientId = fs.readFileSync(seededClientIdFile, "utf8").trim();
    expect(seededClientId).not.toBe("");
    await page.goto(`/login?client_id=${encodeURIComponent(seededClientId)}`);
    await expect(page.locator("body")).toHaveClass(/at-auth-shell/);
    const accent = await page.evaluate(() =>
      getComputedStyle(document.documentElement)
        .getPropertyValue("--accent")
        .trim(),
    );
    expect(accent).toBe("#cba6f7");
    const ink = await page.evaluate(() =>
      getComputedStyle(document.documentElement)
        .getPropertyValue("--accent-ink")
        .trim(),
    );
    expect(ink).toBe("#000000");
  });
});
