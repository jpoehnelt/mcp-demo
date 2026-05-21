// Branded types for security-sensitive primitives.
// See specs/shared-library.md and architecture invariant §4.11.
//
// Brands are nominal phantom types: a `Branded<string, "Foo">` is structurally
// a `string` at runtime but is incompatible with a bare `string` at compile
// time. Mint a brand only inside the module that owns it (e.g. `CanonicalURI`
// is minted inside `canonicalize`). `unsafeBrand` is the single internal
// escape hatch and MUST NOT be re-exported from the package barrel.

declare const __brand: unique symbol;

export type Branded<T, B extends string> = T & { readonly [__brand]: B };

export type CanonicalURI = Branded<string, "CanonicalURI">;
export type AccessTokenJWT = Branded<string, "AccessTokenJWT">;
export type RefreshTokenOpaque = Branded<string, "RefreshTokenOpaque">;
export type AuthorizationCode = Branded<string, "AuthorizationCode">;
export type PKCEVerifier = Branded<string, "PKCEVerifier">;
export type PKCEChallenge = Branded<string, "PKCEChallenge">;
export type StateParam = Branded<string, "StateParam">;
export type ClientId = Branded<CanonicalURI, "ClientId">;
export type ScopeString = Branded<string, "ScopeString">;

/**
 * Internal-only brand minting helper. Owning module re-uses this to attach a
 * brand to a value after performing the brand's invariant checks. Not part of
 * the package's public surface — keep imports scoped to sibling modules
 * inside `@poc/shared`.
 */
export function unsafeBrand<T, B extends string>(value: T): Branded<T, B> {
  return value as Branded<T, B>;
}
