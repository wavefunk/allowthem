/**
 * Express-style middleware factory for the server SDK.
 *
 * Returns a `RequestHandler` that:
 * 1. Reads `Authorization` header. Missing → 401 with `WWW-Authenticate: Bearer`.
 * 2. Calls `verifier.verify(header)`.
 * 3. If `opts.requireRole` is set, asserts the role.
 * 4. On success, attaches the user to `req.user` (or `req[opts.attachAs]`)
 *    and calls `next()`.
 * 5. On {@link AuthError}, renders an RFC 6750-shaped 401/403 with a
 *    sanitised description.
 * 6. On any other error (e.g., `jwks_fetch_failed` bubbling up), calls
 *    `next(err)` so the host's error handler can decide. The middleware
 *    does not mask infrastructure issues silently.
 *
 * The Express types are loaded as devDeps (`@types/express`); runtime has no
 * dependency on the express package — h6d.4's bundler tree-shakes the
 * type-only imports.
 */
import type { NextFunction, Request, RequestHandler, Response } from "express";
import { AuthError } from "./errors.js";
import {
  type AllowthemUser,
  type AllowthemVerifier,
  requireRole as requireRoleFn,
} from "./verifier.js";

export interface MiddlewareOptions {
  /**
   * Required role; rejects with 403 if absent. Convenience for the common
   * "admin-only endpoint" pattern.
   */
  requireRole?: string;

  /**
   * Property name on the request to attach the verified user. Default:
   * `"user"`.
   */
  attachAs?: string;
}

declare module "express" {
  // eslint-disable-next-line @typescript-eslint/no-empty-interface
  interface Request {
    user?: AllowthemUser;
  }
}

/**
 * Create an Express request handler that verifies the bearer token and
 * attaches the verified user.
 */
export function createMiddleware(
  verifier: AllowthemVerifier,
  opts: MiddlewareOptions = {},
): RequestHandler {
  const attachKey = opts.attachAs ?? "user";
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const auth = req.headers.authorization;
    if (auth === undefined || auth === "") {
      res.status(401).set("WWW-Authenticate", "Bearer").end();
      return;
    }
    try {
      const user = await verifier.verify(auth);
      if (opts.requireRole !== undefined) {
        requireRoleFn(user, opts.requireRole);
      }
      (req as unknown as Record<string, unknown>)[attachKey] = user;
      next();
    } catch (err) {
      if (!(err instanceof AuthError)) {
        // Infrastructure issues (jwks_fetch_failed, etc.) bubble to the host
        // error handler — don't mask as a generic 503.
        next(err);
        return;
      }
      const status = err.code === "forbidden" ? 403 : 401;
      const safeDesc = (err.description ?? "").replace(/"/g, "");
      const realm = `Bearer error="${err.code}", error_description="${safeDesc}"`;
      res.status(status).set("WWW-Authenticate", realm).end();
    }
  };
}
