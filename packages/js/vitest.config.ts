import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: false,
    include: ["test/**/*.test.ts", "server/test/**/*.test.ts"],
    // Browser tests run under jsdom (window, history, sessionStorage); server
    // tests run under node (no DOM globals leaking into the verifier path).
    environmentMatchGlobs: [
      ["server/test/**", "node"],
      ["test/**", "jsdom"],
    ],
  },
});
