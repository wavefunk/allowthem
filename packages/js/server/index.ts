/**
 * Public surface for `@allowthem/js/server`.
 *
 * h6d.4 finalises `package.json` `exports` so consumers can import via
 * `"@allowthem/js/server"` instead of relative paths.
 */
export {
  createAllowthemVerifier,
  hasPermission,
  requireRole,
  DEFAULTS,
} from "./verifier.js";
export type {
  AllowthemUser,
  AllowthemVerifier,
  VerifierConfig,
} from "./verifier.js";
export { createMiddleware } from "./middleware.js";
export type { MiddlewareOptions } from "./middleware.js";
export { AuthError, ERROR_CODES } from "./errors.js";
export type { AuthErrorCode } from "./errors.js";
