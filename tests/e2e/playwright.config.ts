// Run `npx playwright install chromium` once after `npm install` to download browser binaries.
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "**/*.spec.ts",
  timeout: 30_000,
  retries: 0,
  use: {
    baseURL: "http://127.0.0.1:3100",
  },
  globalSetup: "./global-setup.ts",
  globalTeardown: "./global-teardown.ts",
  projects: [
    {
      name: "chromium",
      use: { browserName: "chromium" },
    },
  ],
});
