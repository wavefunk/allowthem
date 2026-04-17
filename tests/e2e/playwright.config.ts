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
      name: "main",
      use: { browserName: "chromium" },
      testIgnore: "**/auth-rate-limit.spec.ts",
    },
    {
      name: "rate-limit",
      use: { browserName: "chromium" },
      testMatch: "**/auth-rate-limit.spec.ts",
      dependencies: ["main"],
    },
  ],
});
