// Typed error hierarchy. Each error carries the OAuth error code the HTTP
// layer maps to a response status / `error` field in `WWW-Authenticate`.
// Source of truth: specs/shared-library.md §4.

export type OAuthErrorCode =
  | "invalid_token"
  | "insufficient_scope"
  | "invalid_client"
  | "invalid_request"
  | "invalid_grant";

/**
 * Common base so call sites can `catch (e: unknown) { if (e instanceof
 * BaseOAuthError) ... }` and read `code` without runtime type sniffing.
 * Not part of the table in spec §4 — purely an implementation convenience.
 */
export abstract class BaseOAuthError extends Error {
  public abstract readonly code: OAuthErrorCode;

  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

// --- invalid_token family ---------------------------------------------------

export class InvalidTokenError extends BaseOAuthError {
  public readonly code: OAuthErrorCode = "invalid_token";
}

export class InvalidAudienceError extends InvalidTokenError {}

export class InvalidIssuerError extends InvalidTokenError {}

export class TokenExpiredError extends InvalidTokenError {}

// --- insufficient_scope -----------------------------------------------------

export class InsufficientScopeError extends BaseOAuthError {
  public readonly code: OAuthErrorCode = "insufficient_scope";
}

// --- invalid_client ---------------------------------------------------------

export class InvalidCIMDError extends BaseOAuthError {
  public readonly code: OAuthErrorCode = "invalid_client";
}

// --- invalid_request --------------------------------------------------------

export class SSRFBlockedError extends BaseOAuthError {
  public readonly code: OAuthErrorCode = "invalid_request";
}

export class MaxBytesExceededError extends BaseOAuthError {
  public readonly code: OAuthErrorCode = "invalid_request";
}

export class InvalidContentTypeError extends BaseOAuthError {
  public readonly code: OAuthErrorCode = "invalid_request";
}

export class InvalidCanonicalURIError extends BaseOAuthError {
  public readonly code: OAuthErrorCode = "invalid_request";
}

// --- invalid_grant ----------------------------------------------------------

export class PKCEMismatchError extends BaseOAuthError {
  public readonly code: OAuthErrorCode = "invalid_grant";
}
