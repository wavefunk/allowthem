/**
 * Re-export `AuthError` for the server entry. Defining a single class keeps
 * `instanceof` checks working across the browser and server entries even
 * after the package's dual-entry build (h6d.4) routes consumers through
 * different bundles.
 *
 * The `.js` extension is required for the `moduleResolution: "Bundler"`
 * resolver in `tsconfig.json` plus the eventual ESM emit.
 */
export { AuthError, ERROR_CODES } from "../src/errors.js";
export type { AuthErrorCode } from "../src/errors.js";
