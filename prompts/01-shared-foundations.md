# Step 1 — Shared Foundations

## Spec anchors

- [architecture.md §4.11](../specs/architecture.md) — Canonical URI handling
- [shared-library.md §2.1](../specs/shared-library.md) — Canonical URI module
- [shared-library.md §4](../specs/shared-library.md) — Error classes table

## Goal

Land the bedrock of `@poc/shared`: branded types for security-sensitive primitives, the typed error class hierarchy, and `canonicalize()` / `equalsCanonical()`. Everything in later slices imports from here.

## Deliverables

- `packages/shared/src/types/brands.ts` — branded type machinery
- `packages/shared/src/errors.ts` — typed error class hierarchy
- `packages/shared/src/oauth/canonical-uri.ts` — `canonicalize`, `equalsCanonical`
- Corresponding `*.test.ts` co-located next to each implementation file
- Update `packages/shared/src/index.ts` to re-export the public surface
- Update `packages/shared/package.json` `exports` map if needed

## Public API

```ts
// brands.ts
export type Branded<T, B extends string> = T & { readonly __brand: B };
export type CanonicalURI       = Branded<string, "CanonicalURI">;
export type AccessTokenJWT     = Branded<string, "AccessTokenJWT">;
export type RefreshTokenOpaque = Branded<string, "RefreshTokenOpaque">;
export type AuthorizationCode  = Branded<string, "AuthorizationCode">;
export type PKCEVerifier       = Branded<string, "PKCEVerifier">;
export type PKCEChallenge      = Branded<string, "PKCEChallenge">;
export type StateParam         = Branded<string, "StateParam">;
export type ClientId           = Branded<CanonicalURI, "ClientId">;
export type ScopeString        = Branded<string, "ScopeString">;
export function unsafeBrand<T, B extends string>(value: T): Branded<T, B>;

// canonical-uri.ts
export function canonicalize(url: string): CanonicalURI;       // throws InvalidCanonicalURIError
export function equalsCanonical(a: string, b: string): boolean; // constant-time compare after canonicalize

// errors.ts (per shared-library §4 table)
export class InvalidTokenError       extends Error { code: "invalid_token" }
export class InvalidAudienceError    extends InvalidTokenError {}
export class InvalidIssuerError      extends InvalidTokenError {}
export class TokenExpiredError       extends InvalidTokenError {}
export class InsufficientScopeError  extends Error { code: "insufficient_scope" }
export class InvalidCIMDError        extends Error { code: "invalid_client" }
export class SSRFBlockedError        extends Error { code: "invalid_request" }
export class MaxBytesExceededError   extends Error { code: "invalid_request" }
export class InvalidContentTypeError extends Error { code: "invalid_request" }
export class PKCEMismatchError       extends Error { code: "invalid_grant" }
export class InvalidCanonicalURIError extends Error { code: "invalid_request" }
```

`unsafeBrand` is for internal use inside the module that owns the brand. Do not re-export from `index.ts`. Mint `CanonicalURI` only inside `canonicalize`; mint `PKCEVerifier`/`PKCEChallenge` only inside the PKCE module (slice 3); etc.

## Acceptance criteria

- `canonicalize` handles every example in the MCP spec [Canonical Server URI](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#canonical-server-uri) section. Rules per [architecture.md §4.11](../specs/architecture.md):
  - lowercase scheme + host
  - remove default port (`:80` for http, `:443` for https)
  - remove fragment
  - remove trailing slash (path of `/` collapses to empty)
  - normalize percent-encoding per RFC 3986 §6.2.2
  - reject non-absolute URLs
- `equalsCanonical` uses `crypto.timingSafeEqual` after both inputs canonicalize.
- Each error class carries its OAuth `code` as a readable property (used by later HTTP layer to map to status).
- Brand restrictiveness proven by `@ts-expect-error` assertions:

  ```ts
  function expectsCanonical(_: CanonicalURI) {}
  // @ts-expect-error — bare string MUST NOT satisfy CanonicalURI
  expectsCanonical("https://example.com");
  expectsCanonical(canonicalize("https://example.com")); // OK
  ```

  If the brand is loosened, `@ts-expect-error` itself becomes an error and `pnpm typecheck` fails.

## Out of scope

- Zod schemas (slice 2)
- PKCE / state (slice 3)
- HTTP / SSRF (slice 4)
- JWT / discovery / CIMD validator (slice 5)
- Anything app-level

## Test patterns

- Positive: every canonical-URI example normalizes to expected output
- Negative: relative URL, empty string, fragment, mixed-case host — assertions on the thrown error class
- Constant-time compare: at minimum verify `equalsCanonical("a", "b") === false` (don't write timing tests — they're flaky)
- Brand assertions: one `@ts-expect-error` per branded type proves a bare string is rejected

## Verification

```bash
# Files must exist
test -f packages/shared/src/types/brands.ts
test -f packages/shared/src/types/brands.test.ts
test -f packages/shared/src/errors.ts
test -f packages/shared/src/errors.test.ts
test -f packages/shared/src/oauth/canonical-uri.ts
test -f packages/shared/src/oauth/canonical-uri.test.ts

# Gates
pnpm typecheck
pnpm lint
pnpm test

# Independent AI review — address findings before commit
cr review --agent --type uncommitted -c CLAUDE.md -c specs/shared-library.md
```

All gate commands must exit 0. CodeRabbit findings: address or explicitly acknowledge.
