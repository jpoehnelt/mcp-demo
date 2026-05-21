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
export { isDeniedAddress, type SafeFetchOptions, safeFetch } from "./http/ssrf.js";
export {
  buildInsufficientScopeHeader,
  buildUnauthorizedHeader,
  parseWWWAuthenticate,
} from "./http/www-authenticate.js";
export { canonicalize, equalsCanonical } from "./oauth/canonical-uri.js";
export { generatePKCE, verifyPKCE } from "./oauth/pkce.js";
export { generateState, verifyState } from "./oauth/state.js";
export type { ASMetadata } from "./types/as-metadata.js";
export { ASMetadataSchema, parseASMetadata } from "./types/as-metadata.js";
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
export type { CIMDDocument } from "./types/cimd.js";
export { CIMDDocumentSchema, parseCIMDDocument } from "./types/cimd.js";
export type { ProtectedResourceMetadata } from "./types/prm.js";
export { PRMSchema, parsePRM } from "./types/prm.js";
export type { TokenClaims } from "./types/token-claims.js";
export { parseTokenClaims, TokenClaimsSchema } from "./types/token-claims.js";
