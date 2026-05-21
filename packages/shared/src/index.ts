// @poc/shared public surface. See specs/shared-library.md for contracts.
//
// `unsafeBrand` is intentionally NOT re-exported: brand minting belongs to
// the module that owns the brand (e.g. `CanonicalURI` is minted inside
// `canonicalize`). Re-exporting it from the barrel would defeat the
// compile-time guarantees that the brand machinery provides.

export {
  BaseOAuthError,
  InsufficientScopeError,
  InvalidAudienceError,
  InvalidCanonicalURIError,
  InvalidCIMDError,
  InvalidContentTypeError,
  InvalidIssuerError,
  InvalidTokenError,
  MaxBytesExceededError,
  type OAuthErrorCode,
  PKCEMismatchError,
  SSRFBlockedError,
  TokenExpiredError,
} from "./errors.js";
export { canonicalize, equalsCanonical } from "./oauth/canonical-uri.js";
export type {
  AccessTokenJWT,
  AuthorizationCode,
  Branded,
  CanonicalURI,
  ClientId,
  PKCEChallenge,
  PKCEVerifier,
  RefreshTokenOpaque,
  ScopeString,
  StateParam,
} from "./types/brands.js";
