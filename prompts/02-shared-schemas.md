# Step 2 — Shared Zod Schemas

## Spec anchors

- [shared-library.md §1.1](../specs/shared-library.md) — CIMD Document Schema
- [shared-library.md §1.2](../specs/shared-library.md) — Protected Resource Metadata Schema
- [shared-library.md §1.3](../specs/shared-library.md) — Authorization Server Metadata Schema
- [shared-library.md §1.4](../specs/shared-library.md) — JWT Claims Schema

## Goal

Land the four zod schemas every external boundary in the system parses against. Strict where the spec is strict (CIMD top-level keys). Each schema gets a parse helper and corresponding type export.

## Deliverables

- `packages/shared/src/types/cimd.ts` + `cimd.test.ts`
- `packages/shared/src/types/prm.ts` + `prm.test.ts`
- `packages/shared/src/types/as-metadata.ts` + `as-metadata.test.ts`
- `packages/shared/src/types/token-claims.ts` + `token-claims.test.ts`
- Update `packages/shared/src/index.ts` to re-export

## Public API

```ts
// cimd.ts — schema is strict (zod v4 .strict()), unknown top-level keys rejected
export type CIMDDocument = z.infer<typeof CIMDDocumentSchema>;
export function parseCIMDDocument(
  json: unknown,
  opts: { allowInsecure: boolean },
): CIMDDocument;

// prm.ts
export type ProtectedResourceMetadata = z.infer<typeof PRMSchema>;
export function parsePRM(json: unknown): ProtectedResourceMetadata;

// as-metadata.ts
export type ASMetadata = z.infer<typeof ASMetadataSchema>;
export function parseASMetadata(json: unknown): ASMetadata;

// token-claims.ts
export type TokenClaims = z.infer<typeof TokenClaimsSchema>;
export function parseTokenClaims(json: unknown): TokenClaims;
```

## Acceptance criteria

### CIMD (§1.1)

- `.strict()` — unknown top-level keys rejected.
- `client_id`: URL with non-empty path. `https://` always allowed; `http://127.0.0.1[:port]` allowed only when `opts.allowInsecure === true`. Bare-domain (path empty or `/`) rejected.
- `client_name`: required.
- `redirect_uris`: non-empty array; each entry `https://` or `http://127.0.0.1[:port]`. `http://localhost` rejected.
- `grant_types`: optional, default `["authorization_code"]`. Only `"authorization_code"` and `"refresh_token"` accepted.
- `response_types`: optional, default `["code"]`. Only `["code"]` accepted.
- `token_endpoint_auth_method`: optional, default `"none"`. Only `"none"` accepted.
- `scope`: optional, space-delimited string.

### PRM (§1.2)

- `resource`: required, canonical URI string.
- `authorization_servers`: required, non-empty string array.
- `scopes_supported`: optional string array.
- `bearer_methods_supported`: optional, default `["header"]`.
- `resource_documentation`: optional.

### AS metadata (§1.3)

- Required: `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `response_types_supported`, `code_challenge_methods_supported`.
- Optional: `grant_types_supported`, `scopes_supported`, `token_endpoint_auth_methods_supported`, `client_id_metadata_document_supported`, `registration_endpoint`.
- Hard-fail downstream (slice 5) if `code_challenge_methods_supported` doesn't include `"S256"`; the schema itself accepts the field as `string[]`.

### Token claims (§1.4)

- Required: `iss`, `sub`, `aud` (string OR string[]), `exp`, `iat`, `jti`, `scope`, `client_id`.
- Optional: `nbf` (number). MAY-level claim; jose validates it during verification (slice 5).

## Test patterns

For each schema, write tests in three buckets:

1. **Valid happy-path** — minimal valid input passes.
2. **Required-field omissions** — each MUST field gets a negative test.
3. **Strict rejections** — for CIMD only, unknown top-level key triggers `ZodError`.

Use small inline fixtures, not separate fixture files. The agent should NOT create a `test-fixtures/` directory yet.

## Out of scope

- CIMD URL-equality validation (`client_id` == fetch URL) — that's slice 5.
- AS metadata discovery cascade — slice 5.
- JWT signature verification — slice 5.

## Verification

```bash
test -f packages/shared/src/types/cimd.ts
test -f packages/shared/src/types/prm.ts
test -f packages/shared/src/types/as-metadata.ts
test -f packages/shared/src/types/token-claims.ts
test -f packages/shared/src/types/cimd.test.ts
test -f packages/shared/src/types/prm.test.ts
test -f packages/shared/src/types/as-metadata.test.ts
test -f packages/shared/src/types/token-claims.test.ts

pnpm typecheck
pnpm lint
pnpm test

# Independent AI review — address findings before commit
cr review --agent --type uncommitted -c CLAUDE.md -c specs/shared-library.md
```

All gate commands must exit 0. CodeRabbit findings: address or explicitly acknowledge.
