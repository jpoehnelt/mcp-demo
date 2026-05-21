import { describe, expect, it } from "vitest";
import { canonicalize } from "../oauth/canonical-uri.js";
import type {
  AccessTokenJWT,
  AuthorizationCode,
  CanonicalURI,
  ClientId,
  PKCEChallenge,
  PKCEVerifier,
  RefreshTokenOpaque,
  ScopeString,
  StateParam,
} from "./brands.js";
import { unsafeBrand } from "./brands.js";

// These functions exist solely to anchor `@ts-expect-error` assertions:
// each branded type MUST reject a bare string. If the brand is loosened the
// expect-error itself becomes an error and typecheck fails. [INV-4.11]
//
// The body returns the parameter to give Biome a non-empty block; the
// runtime value is irrelevant — only the parameter's type matters.
function expectsCanonical(v: CanonicalURI): CanonicalURI {
  return v;
}
function expectsAccessToken(v: AccessTokenJWT): AccessTokenJWT {
  return v;
}
function expectsRefreshToken(v: RefreshTokenOpaque): RefreshTokenOpaque {
  return v;
}
function expectsAuthorizationCode(v: AuthorizationCode): AuthorizationCode {
  return v;
}
function expectsPKCEVerifier(v: PKCEVerifier): PKCEVerifier {
  return v;
}
function expectsPKCEChallenge(v: PKCEChallenge): PKCEChallenge {
  return v;
}
function expectsStateParam(v: StateParam): StateParam {
  return v;
}
function expectsClientId(v: ClientId): ClientId {
  return v;
}
function expectsScopeString(v: ScopeString): ScopeString {
  return v;
}

describe("brands", () => {
  it("rejects bare strings at compile time and accepts branded values at runtime [INV-4.11]", () => {
    // @ts-expect-error — bare string MUST NOT satisfy CanonicalURI
    expectsCanonical("https://example.com");
    // @ts-expect-error — bare string MUST NOT satisfy AccessTokenJWT
    expectsAccessToken("eyJhbGciOiJSUzI1NiJ9.x.y");
    // @ts-expect-error — bare string MUST NOT satisfy RefreshTokenOpaque
    expectsRefreshToken("opaque");
    // @ts-expect-error — bare string MUST NOT satisfy AuthorizationCode
    expectsAuthorizationCode("abc");
    // @ts-expect-error — bare string MUST NOT satisfy PKCEVerifier
    expectsPKCEVerifier("verifier");
    // @ts-expect-error — bare string MUST NOT satisfy PKCEChallenge
    expectsPKCEChallenge("challenge");
    // @ts-expect-error — bare string MUST NOT satisfy StateParam
    expectsStateParam("state");
    // @ts-expect-error — bare string MUST NOT satisfy ClientId (a doubly-branded CanonicalURI)
    expectsClientId("https://example.com/cimd");
    // @ts-expect-error — bare string MUST NOT satisfy ScopeString
    expectsScopeString("read write");

    // Positive: minting through `canonicalize` produces a real `CanonicalURI`.
    expectsCanonical(canonicalize("https://example.com/foo"));

    // Positive: `unsafeBrand` is the internal escape hatch each module uses
    // after running its own invariant checks. Exercising it here keeps the
    // brand machinery testable without leaking it from the public surface.
    expectsAccessToken(unsafeBrand<string, "AccessTokenJWT">("eyJ.x.y"));
    expectsRefreshToken(unsafeBrand<string, "RefreshTokenOpaque">("opaque"));
    expectsAuthorizationCode(unsafeBrand<string, "AuthorizationCode">("abc"));
    expectsPKCEVerifier(unsafeBrand<string, "PKCEVerifier">("v".repeat(43)));
    expectsPKCEChallenge(unsafeBrand<string, "PKCEChallenge">("challenge"));
    expectsStateParam(unsafeBrand<string, "StateParam">("state"));
    expectsScopeString(unsafeBrand<string, "ScopeString">("read write"));

    // `ClientId` brands a `CanonicalURI`, not a bare string — minting it
    // therefore requires layering brands.
    const canon = canonicalize("https://example.com/cimd");
    expectsClientId(unsafeBrand<CanonicalURI, "ClientId">(canon));

    // Brands are erased at runtime; the underlying value is just a string.
    expect(typeof canonicalize("https://example.com/foo")).toBe("string");
  });

  it("preserves the underlying value identity (brand is phantom-only)", () => {
    const raw = "https://example.com/foo";
    const canon = canonicalize(raw);
    expect(canon).toBe("https://example.com/foo");
  });
});
