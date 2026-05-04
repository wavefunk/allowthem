export { createAllowthemClient } from "./client.js";
export { AuthError, ERROR_CODES } from "./errors.js";
export type {
  AllowthemClient,
  ClientConfig,
  LoginOptions,
  LogoutOptions,
  TokenResponse,
  UserClaims,
} from "./types.js";
export type {
  EventName,
  EventPayloads,
  EventHandler,
} from "./events.js";
export type { TokenSet, TokenStore } from "./tokens.js";
