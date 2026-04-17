import { createHash, randomBytes } from "crypto";
import { Page } from "@playwright/test";

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

export interface PkceChallenge {
  codeVerifier: string;
  codeChallenge: string;
}

export function generatePkce(): PkceChallenge {
  const codeVerifier = randomBytes(32).toString("base64url").slice(0, 43);
  const codeChallenge = createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  return { codeVerifier, codeChallenge };
}

// ---------------------------------------------------------------------------
// Authorization URL builder
// ---------------------------------------------------------------------------

export interface AuthParams {
  baseUrl: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  codeChallenge: string;
  nonce?: string;
}

export function buildAuthorizeUrl(params: AuthParams): string {
  const url = new URL(`${params.baseUrl}/oauth/authorize`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", params.clientId);
  url.searchParams.set("redirect_uri", params.redirectUri);
  url.searchParams.set("scope", params.scope);
  url.searchParams.set("state", params.state);
  url.searchParams.set("code_challenge", params.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  if (params.nonce) url.searchParams.set("nonce", params.nonce);
  return url.toString();
}

// ---------------------------------------------------------------------------
// Redirect capture via page.route() intercept
// ---------------------------------------------------------------------------

/**
 * Arm a route intercept that captures all query params when the browser is
 * redirected to redirectUri. Call this BEFORE navigating to the authorize URL,
 * then perform the consent click, then call the returned function to collect.
 *
 * The intercept fulfills with HTTP 200 so the browser settles on the
 * non-existent test-callback path without a network error.
 */
export async function armRedirectCapture(
  page: Page,
  redirectUri: string
): Promise<() => Promise<URLSearchParams>> {
  // Instead of intercepting the redirect, wait for navigation to the
  // callback URL and parse query params from page.url() directly.
  return async () => {
    await page.waitForURL((url) => url.href.startsWith(redirectUri), {
      timeout: 10_000,
    });
    const url = new URL(page.url());
    return url.searchParams;
  };
}

/**
 * Specialisation of armRedirectCapture for the approve path: asserts that a
 * `code` query param is present and returns `{ code, state }`.
 */
export async function armCodeCapture(
  page: Page,
  redirectUri: string
): Promise<() => Promise<{ code: string; state: string }>> {
  const collectParams = await armRedirectCapture(page, redirectUri);
  return async () => {
    const params = await collectParams();
    const code = params.get("code");
    const state = params.get("state") ?? "";
    if (!code) throw new Error("Authorization code not present in redirect");
    return { code, state };
  };
}

// ---------------------------------------------------------------------------
// JWT payload decoder (no signature verification)
// ---------------------------------------------------------------------------

export function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT structure");
  const payload = Buffer.from(parts[1], "base64url").toString("utf8");
  return JSON.parse(payload);
}

// ---------------------------------------------------------------------------
// Token exchange and UserInfo wrappers
// ---------------------------------------------------------------------------

export interface TokenResponse {
  access_token: string;
  id_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export async function exchangeCode(
  page: Page,
  code: string,
  codeVerifier: string,
  redirectUri: string,
  clientId: string,
  clientSecret: string
): Promise<TokenResponse> {
  const res = await page.request.post("/oauth/token", {
    form: {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
      client_id: clientId,
      client_secret: clientSecret,
    },
  });
  if (!res.ok()) {
    const body = await res.text();
    throw new Error(`Token exchange failed ${res.status()}: ${body}`);
  }
  return res.json() as Promise<TokenResponse>;
}

export async function refreshTokens(
  page: Page,
  refreshToken: string,
  clientId: string,
  clientSecret: string
): Promise<TokenResponse> {
  const res = await page.request.post("/oauth/token", {
    form: {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: clientId,
      client_secret: clientSecret,
    },
  });
  if (!res.ok()) {
    const body = await res.text();
    throw new Error(`Refresh failed ${res.status()}: ${body}`);
  }
  return res.json() as Promise<TokenResponse>;
}

export async function fetchUserInfo(
  page: Page,
  accessToken: string
): Promise<Record<string, unknown>> {
  const res = await page.request.get("/oauth/userinfo", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok()) throw new Error(`UserInfo failed: ${res.status()}`);
  return res.json();
}
