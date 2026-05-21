# Step 5 — Shared Identity Layer

## Spec anchors

- [shared-library.md §2.4](../specs/shared-library.md) — JWT verifier
- [shared-library.md §2.5](../specs/shared-library.md) — Metadata discovery
- [shared-library.md §2.6](../specs/shared-library.md) — CIMD validator
- [architecture.md §4.1](../specs/architecture.md), [§4.2](../specs/architecture.md), [§4.3](../specs/architecture.md), [§4.9](../specs/architecture.md), [§4.11](../specs/architecture.md)

## Goal

The identity layer that consumes everything from slices 1–4. JWT signature + claim verification (jose + JWKS), authorization server metadata discovery (RFC 8414 cascade with path insertion), and CIMD document validation (URL ↔ `client_id` byte-equality, path requirement, redirect URI shape).

## Deliverables

- `packages/shared/src/oauth/jwt-verifier.ts` + `jwt-verifier.test.ts`
- `packages/shared/src/oauth/discovery.ts` + `discovery.test.ts`
- `packages/shared/src/oauth/cimd-validator.ts` + `cimd-validator.test.ts`
- Update `packages/shared/src/index.ts` to re-export

## Public API

```ts
// jwt-verifier.ts
export function createJWTVerifier(opts: {
  issuer: CanonicalURI;
  audience: CanonicalURI;
  jwksCacheTTLms?: number;
}): { verify(token: string): Promise<TokenClaims> };

// discovery.ts
export function resolvePRMUrl(mcpServerUrl: CanonicalURI): string;
export function fetchPRM(url: string): Promise<ProtectedResourceMetadata>;
export function discoverASMetadata(issuerUrl: CanonicalURI): Promise<ASMetadata>;

// cimd-validator.ts
export function validateFetchedCIMD(
  url: string,
  json: unknown,
  opts: { allowInsecure: boolean },
): CIMDDocument;
```

## Acceptance criteria

### JWT verifier (§2.4)

- Uses `jose.createRemoteJWKSet` internally; constructed once and reused.
- Accepts only `RS256`, `ES256`, `EdDSA`. Reject `HS*` — **invariant §4.3**.
- Reject `alg: "none"`.
- Verify in order: signature → `iss` (canonical compare) → `aud` (string-or-array containment after canonicalization) → `exp` → `nbf` (if present) → `iat`. ±30 s clock skew tolerance.
- Cache TTL from JWKS response `Cache-Control: max-age`, fallback 3600 s, cap 24 h.
- Throws typed errors per slice 1: `InvalidTokenError` (signature, alg), `InvalidIssuerError`, `InvalidAudienceError`, `TokenExpiredError`.
- Returns `TokenClaims` (parsed via slice 2's `parseTokenClaims`).

### Discovery (§2.5)

- `resolvePRMUrl`: implements [RFC 9728 §3](https://datatracker.ietf.org/doc/html/rfc9728#section-3) path-aware resolution. E.g., `https://example.com/public/mcp` → `https://example.com/.well-known/oauth-protected-resource/public/mcp`. No path → `https://example.com/.well-known/oauth-protected-resource`.
- `fetchPRM`: uses `safeFetch` from slice 4 with `expectContentType: "application/json"`, then `parsePRM` (slice 2).
- `discoverASMetadata` cascade (per [MCP spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#authorization-server-metadata-discovery)):
  1. `{issuer}/.well-known/oauth-authorization-server` with **path insertion** per [RFC 8414 §3.1](https://datatracker.ietf.org/doc/html/rfc8414#section-3.1). Example: `https://idp.example.com/tenant1` → `https://idp.example.com/.well-known/oauth-authorization-server/tenant1`.
  2. `{issuer}/.well-known/openid-configuration` with path insertion.
  3. `{issuer}/.well-known/openid-configuration` with path appending (OIDC compatibility fallback). Example: `https://idp.example.com/tenant1` → `https://idp.example.com/tenant1/.well-known/openid-configuration`.
- MUST hard-fail with a typed error if `code_challenge_methods_supported` doesn't include `"S256"`.

### CIMD validator (§2.6)

1. Parse JSON via `parseCIMDDocument(json, opts)` (slice 2).
2. `canonicalize(url)` and `canonicalize(parsed.client_id)`; assert byte-equal via `equalsCanonical` — **invariant §4.9**. Mismatch (semantic or literal) → `InvalidCIMDError`.
3. Verify the canonical URL has a non-empty path component. Bare-domain or `/`-only path → `InvalidCIMDError`.
4. For each `redirect_uri`: require `https://` OR `http://127.0.0.1[:port]`. Reject `http://localhost` (resolves dynamically). Already enforced by the schema, but reassert here for clarity.
5. Return the validated document with `client_id` set to its canonical form.

## Test patterns

### JWT verifier

- Mint a real JWT in-test using `jose.SignJWT` with a generated RS256 key; expose the JWKS via a mock fetch (`safeFetch` is overridable, or use jose's `jwtVerify` with the local key set for tests).
- `[INV-4.1]`: token with `aud: "https://other.example.com"` rejected when audience is `https://mcp.example.com`.
- `[INV-4.2]`: token with `iss` mismatched rejected.
- `[INV-4.3]`: token with `alg: "HS256"` rejected.
- `[INV-4.3]`: token with `alg: "none"` rejected.
- Token with `exp` in past (beyond 30 s skew) → `TokenExpiredError`.
- Token with `nbf` in future (beyond 30 s skew) → rejected.

### Discovery

- `resolvePRMUrl` table-driven test for empty path, `/`, `/foo`, `/foo/bar`.
- `discoverASMetadata` happy path: stub `safeFetch` to return valid metadata on step 1.
- Cascade: step 1 returns 404 → falls back to step 2; step 2 returns 404 → falls back to step 3.
- Hard-fail when metadata lacks `S256` in `code_challenge_methods_supported`.

### CIMD validator

- `[INV-4.9]`: fetched URL `https://example.com/cimd` + parsed `client_id: "https://example.com/cimd"` → OK.
- `[INV-4.9]`: fetched URL `https://example.com/cimd` + parsed `client_id: "https://EXAMPLE.com/cimd"` → OK (canonicalize lowercases host).
- `[INV-4.9]`: fetched URL `https://example.com/cimd` + parsed `client_id: "https://example.com/other"` → reject.
- Bare-domain `client_id` → reject.
- `redirect_uri: "http://localhost:7777/cb"` → reject (schema already rejects, just reassert).

## Out of scope

- Storage / caching across processes (the verifier's JWKS cache is in-process via jose).
- App-level integration (slices 6+).

## Verification

```bash
test -f packages/shared/src/oauth/jwt-verifier.ts
test -f packages/shared/src/oauth/jwt-verifier.test.ts
test -f packages/shared/src/oauth/discovery.ts
test -f packages/shared/src/oauth/discovery.test.ts
test -f packages/shared/src/oauth/cimd-validator.ts
test -f packages/shared/src/oauth/cimd-validator.test.ts

pnpm typecheck
pnpm lint
pnpm test

pnpm exec vitest run -t '[INV-4.1]' --reporter=verbose
pnpm exec vitest run -t '[INV-4.3]' --reporter=verbose
pnpm exec vitest run -t '[INV-4.9]' --reporter=verbose

# Independent AI review — address findings before commit
cr review --agent --type uncommitted -c CLAUDE.md -c specs/shared-library.md
```

All gate commands must exit 0. CodeRabbit findings: address or explicitly acknowledge.
