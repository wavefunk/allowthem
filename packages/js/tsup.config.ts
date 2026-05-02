import { defineConfig } from "tsup";

/**
 * Two parallel configs: one for the browser entry (`@allowthem/js`),
 * one for the server entry (`@allowthem/js/server`). tsup runs the
 * array entries in parallel via `Promise.all`, so both `clean: false`
 * — pre-build cleanup is hoisted to the `prebuild` script in
 * `package.json` so the parallel writers don't race each other to wipe
 * `dist/`.
 */
export default defineConfig([
  // Browser entry — @allowthem/js
  {
    entry: { index: "src/index.ts" },
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: true,
    clean: false,
    target: "es2020",
    platform: "neutral",
    splitting: false,
    minify: false,
    outDir: "dist",
    outExtension: ({ format }) => ({ js: format === "esm" ? ".mjs" : ".cjs" }),
  },
  // Server entry — @allowthem/js/server
  {
    entry: { "server/index": "server/index.ts" },
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: true,
    clean: false,
    target: "node18",
    platform: "node",
    external: ["jose", "express"],
    splitting: false,
    minify: false,
    outDir: "dist",
    outExtension: ({ format }) => ({ js: format === "esm" ? ".mjs" : ".cjs" }),
  },
]);
