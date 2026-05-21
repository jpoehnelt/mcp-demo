import { describe, expect, it } from "vitest";
import {
  BaseOAuthError,
  InsufficientScopeError,
  InvalidAudienceError,
  InvalidCanonicalURIError,
  InvalidCIMDError,
  InvalidContentTypeError,
  InvalidIssuerError,
  InvalidTokenError,
  MaxBytesExceededError,
  PKCEMismatchError,
  SSRFBlockedError,
  TokenExpiredError,
} from "./errors.js";

describe("errors", () => {
  it("each error carries its OAuth error code (spec §4 table)", () => {
    expect(new InvalidTokenError("x").code).toBe("invalid_token");
    expect(new InvalidAudienceError("x").code).toBe("invalid_token");
    expect(new InvalidIssuerError("x").code).toBe("invalid_token");
    expect(new TokenExpiredError("x").code).toBe("invalid_token");
    expect(new InsufficientScopeError("x").code).toBe("insufficient_scope");
    expect(new InvalidCIMDError("x").code).toBe("invalid_client");
    expect(new SSRFBlockedError("x").code).toBe("invalid_request");
    expect(new MaxBytesExceededError("x").code).toBe("invalid_request");
    expect(new InvalidContentTypeError("x").code).toBe("invalid_request");
    expect(new InvalidCanonicalURIError("x").code).toBe("invalid_request");
    expect(new PKCEMismatchError("x").code).toBe("invalid_grant");
  });

  it("invalid_token subclasses are instanceof InvalidTokenError", () => {
    const aud = new InvalidAudienceError("aud");
    const iss = new InvalidIssuerError("iss");
    const exp = new TokenExpiredError("exp");
    expect(aud).toBeInstanceOf(InvalidTokenError);
    expect(iss).toBeInstanceOf(InvalidTokenError);
    expect(exp).toBeInstanceOf(InvalidTokenError);
  });

  it("all OAuth errors are instances of Error and BaseOAuthError", () => {
    const errs: BaseOAuthError[] = [
      new InvalidTokenError("a"),
      new InvalidAudienceError("a"),
      new InvalidIssuerError("a"),
      new TokenExpiredError("a"),
      new InsufficientScopeError("a"),
      new InvalidCIMDError("a"),
      new SSRFBlockedError("a"),
      new MaxBytesExceededError("a"),
      new InvalidContentTypeError("a"),
      new InvalidCanonicalURIError("a"),
      new PKCEMismatchError("a"),
    ];
    for (const e of errs) {
      expect(e).toBeInstanceOf(Error);
      expect(e).toBeInstanceOf(BaseOAuthError);
    }
  });

  it("preserves message and class name on each subclass", () => {
    const e = new InvalidAudienceError("audience mismatch");
    expect(e.message).toBe("audience mismatch");
    expect(e.name).toBe("InvalidAudienceError");
  });

  it("supports error chaining via the standard `cause` option", () => {
    const root = new TypeError("inner");
    const e = new SSRFBlockedError("blocked", { cause: root });
    expect(e.cause).toBe(root);
  });
});
