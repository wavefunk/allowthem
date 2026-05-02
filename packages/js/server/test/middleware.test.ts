import type {
  NextFunction,
  Request,
  RequestHandler,
  Response as ExpressResponse,
} from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthError } from "../errors.js";
import { createMiddleware } from "../middleware.js";
import { type AllowthemUser, type AllowthemVerifier, createAllowthemVerifier } from "../verifier.js";
import {
  makeJwksResponse,
  makeTestKeypair,
  signTestToken,
  type TestKeypair,
} from "./_helpers.js";

const DOMAIN = "acme.allowthem.io";
const ISSUER = `https://${DOMAIN}`;
const AUDIENCE = "ath_xxx";

let kp: TestKeypair;

beforeEach(async () => {
  kp = await makeTestKeypair("kid-1");
});
afterEach(() => {
  vi.useRealTimers();
});

interface FakeReqRes {
  req: Request;
  res: ExpressResponse;
  next: NextFunction;
  get: () => {
    statusCode: number;
    setHeaders: Record<string, string>;
    ended: boolean;
    nextCalled: boolean;
    nextErr: unknown;
  };
}

function makeReqRes(headers: Record<string, string> = {}): FakeReqRes {
  let statusCode = 200;
  const setHeaders: Record<string, string> = {};
  let ended = false;
  let nextErr: unknown;
  let nextCalled = false;
  const res = {
    status(code: number) {
      statusCode = code;
      return this;
    },
    set(key: string, val: string) {
      setHeaders[key] = val;
      return this;
    },
    end() {
      ended = true;
      return this;
    },
  } as unknown as ExpressResponse;
  const req = { headers } as unknown as Request;
  const next = ((err?: unknown): void => {
    nextCalled = true;
    nextErr = err;
  }) as NextFunction;
  return { req, res, next, get: () => ({ statusCode, setHeaders, ended, nextCalled, nextErr }) };
}

function jwksFetch(bodyFn: () => unknown, status = 200): typeof fetch {
  const fn = async (): Promise<Response> => {
    const body = bodyFn();
    return new Response(typeof body === "string" ? body : JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  };
  return fn as unknown as typeof fetch;
}

function makeRealVerifier(fetchFn: typeof fetch): AllowthemVerifier {
  return createAllowthemVerifier({
    domain: DOMAIN,
    audience: AUDIENCE,
    fetch: fetchFn,
  });
}

async function callHandler(handler: RequestHandler, ctx: FakeReqRes): Promise<void> {
  await Promise.resolve(handler(ctx.req, ctx.res, ctx.next));
  // Allow the async middleware body to settle.
  await new Promise<void>((res) => { setTimeout(res, 0); });
}

describe("createMiddleware", () => {
  it("missing Authorization header → 401 with WWW-Authenticate: Bearer", async () => {
    const verifier = makeRealVerifier(jwksFetch(() => makeJwksResponse([kp])));
    const handler = createMiddleware(verifier);
    const ctx = makeReqRes();

    await callHandler(handler, ctx);
    const out = ctx.get();
    expect(out.statusCode).toBe(401);
    expect(out.setHeaders["WWW-Authenticate"]).toBe("Bearer");
    expect(out.ended).toBe(true);
    expect(out.nextCalled).toBe(false);
  });

  it("empty Authorization value → 401 with WWW-Authenticate: Bearer", async () => {
    const verifier = makeRealVerifier(jwksFetch(() => makeJwksResponse([kp])));
    const handler = createMiddleware(verifier);
    const ctx = makeReqRes({ authorization: "" });

    await callHandler(handler, ctx);
    expect(ctx.get().statusCode).toBe(401);
  });

  it("valid token + no requireRole → req.user populated, next() called without error", async () => {
    const verifier = makeRealVerifier(jwksFetch(() => makeJwksResponse([kp])));
    const handler = createMiddleware(verifier);
    const token = await signTestToken({
      kp,
      iss: ISSUER,
      aud: AUDIENCE,
      sub: "user-1",
      email: "u@example.com",
      roles: ["viewer"],
    });
    const ctx = makeReqRes({ authorization: `Bearer ${token}` });

    await callHandler(handler, ctx);
    const out = ctx.get();
    expect(out.nextCalled).toBe(true);
    expect(out.nextErr).toBeUndefined();
    const user = (ctx.req as unknown as { user?: AllowthemUser }).user;
    expect(user?.sub).toBe("user-1");
    expect(out.ended).toBe(false);
  });

  it("valid token + requireRole satisfied → next() called", async () => {
    const verifier = makeRealVerifier(jwksFetch(() => makeJwksResponse([kp])));
    const handler = createMiddleware(verifier, { requireRole: "admin" });
    const token = await signTestToken({
      kp,
      iss: ISSUER,
      aud: AUDIENCE,
      roles: ["admin", "user"],
    });
    const ctx = makeReqRes({ authorization: `Bearer ${token}` });

    await callHandler(handler, ctx);
    const out = ctx.get();
    expect(out.nextCalled).toBe(true);
    expect(out.nextErr).toBeUndefined();
  });

  it("valid token + requireRole missing → 403 with forbidden realm", async () => {
    const verifier = makeRealVerifier(jwksFetch(() => makeJwksResponse([kp])));
    const handler = createMiddleware(verifier, { requireRole: "admin" });
    const token = await signTestToken({
      kp,
      iss: ISSUER,
      aud: AUDIENCE,
      roles: ["viewer"],
    });
    const ctx = makeReqRes({ authorization: `Bearer ${token}` });

    await callHandler(handler, ctx);
    const out = ctx.get();
    expect(out.statusCode).toBe(403);
    expect(out.setHeaders["WWW-Authenticate"]).toMatch(/^Bearer error="forbidden"/);
    expect(out.setHeaders["WWW-Authenticate"]).toMatch(/error_description="missing role: admin"/);
    expect(out.nextCalled).toBe(false);
  });

  it("invalid token → 401 with invalid_token realm", async () => {
    const verifier = makeRealVerifier(jwksFetch(() => makeJwksResponse([kp])));
    const handler = createMiddleware(verifier);
    const ctx = makeReqRes({ authorization: "Bearer not.a.jwt" });

    await callHandler(handler, ctx);
    const out = ctx.get();
    expect(out.statusCode).toBe(401);
    expect(out.setHeaders["WWW-Authenticate"]).toMatch(/^Bearer error="invalid_token"/);
  });

  it("attachAs option attaches user under a different request key", async () => {
    const verifier = makeRealVerifier(jwksFetch(() => makeJwksResponse([kp])));
    const handler = createMiddleware(verifier, { attachAs: "currentUser" });
    const token = await signTestToken({ kp, iss: ISSUER, aud: AUDIENCE });
    const ctx = makeReqRes({ authorization: `Bearer ${token}` });

    await callHandler(handler, ctx);
    const user = (ctx.req as unknown as { currentUser?: AllowthemUser }).currentUser;
    expect(user?.sub).toBeDefined();
    expect((ctx.req as unknown as { user?: AllowthemUser }).user).toBeUndefined();
  });

  it("non-AuthError verify failure (jwks_fetch_failed) → next(err), no response written", async () => {
    // Inject a verifier whose verify() throws a plain Error to simulate
    // jwks_fetch_failed bubbling — middleware shouldn't hide infra issues.
    const fakeVerifier: AllowthemVerifier = {
      verify: async () => { throw new Error("network exploded"); },
      requireRole: () => {},
      hasPermission: () => false,
      middleware: () => { throw new Error("unused"); },
    };
    const handler = createMiddleware(fakeVerifier);
    const ctx = makeReqRes({ authorization: "Bearer x" });

    await callHandler(handler, ctx);
    const out = ctx.get();
    expect(out.nextCalled).toBe(true);
    expect(out.nextErr).toBeInstanceOf(Error);
    expect((out.nextErr as Error).message).toBe("network exploded");
    expect(out.ended).toBe(false); // no res.end() — host error handler decides
  });

  it("AuthError description containing quotes is sanitised in WWW-Authenticate", async () => {
    const fakeVerifier: AllowthemVerifier = {
      verify: async () => {
        throw new AuthError("invalid_token", 'has "quoted" content');
      },
      requireRole: () => {},
      hasPermission: () => false,
      middleware: () => { throw new Error("unused"); },
    };
    const handler = createMiddleware(fakeVerifier);
    const ctx = makeReqRes({ authorization: "Bearer x" });

    await callHandler(handler, ctx);
    const realm = ctx.get().setHeaders["WWW-Authenticate"]!;
    // No bare quotes inside the description value.
    expect(realm).toBe('Bearer error="invalid_token", error_description="has quoted content"');
  });

  it("verifier.middleware wires the same factory", async () => {
    const verifier = makeRealVerifier(jwksFetch(() => makeJwksResponse([kp])));
    const handler = verifier.middleware({ requireRole: "admin" });
    const token = await signTestToken({
      kp,
      iss: ISSUER,
      aud: AUDIENCE,
      roles: ["admin"],
    });
    const ctx = makeReqRes({ authorization: `Bearer ${token}` });

    await callHandler(handler, ctx);
    expect(ctx.get().nextCalled).toBe(true);
    expect(ctx.get().nextErr).toBeUndefined();
  });
});
