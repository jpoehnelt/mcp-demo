# Step 9 — IdP Token Endpoint (Authorization Code Grant)

## Spec anchors

- [authorization-server.md §5.1](../specs/authorization-server.md) — Authorization Code Grant
- [authorization-server.md §5.2](../specs/authorization-server.md) — Response
- [authorization-server.md §5.4](../specs/authorization-server.md) — Error responses
- [architecture.md §4.4](../specs/architecture.md), [§4.5](../specs/architecture.md), [§4.15](../specs/architecture.md) — Relevant invariants

## Goal

Implement `POST /token` for the `authorization_code` grant: code lookup, single-use enforcement, PKCE verification, JWT minting, refresh-token issuance. The refresh-token *redemption* flow (`grant_type=refresh_token`) is **out of scope** for this PoC — issuance only.

## Deliverables

- `apps/mock-customer-idp/src/routes/token.ts` — endpoint handler
- `apps/mock-customer-idp/src/jwt.ts` — JWT minting helper using jose + the active signing keyset
- `apps/mock-customer-idp/src/refresh.ts` — refresh-token issuance (32 random bytes + SHA-256 hash persistence). No redeem logic yet.
- New tests in `integration.test.ts`

## Public API (internal)

```ts
// routes/token.ts
export function registerTokenRoutes(app: Hono, deps: {
  env: IdPEnv;
  db: Database;
  log: Logger;
  keys: SigningKeyset;
}): void;

// jwt.ts
export function mintAccessToken(args: {
  env: IdPEnv;
  keys: SigningKeyset;
  sub: string;
  clientId: ClientId;
  resource: CanonicalURI;
  scope: ScopeString;
}): Promise<{ token: AccessTokenJWT; expiresIn: number }>;

// refresh.ts
export function issueRefreshToken(args: {
  db: Database;
  env: IdPEnv;
  clientId: ClientId;
  resource: CanonicalURI;
  scope: ScopeString;
  sub: string;
}): { plaintext: RefreshTokenOpaque; familyId: string };
```

## Acceptance criteria

### `POST /token`

`Content-Type: application/x-www-form-urlencoded` (NOT JSON). Reject other content types with `invalid_request`.

Body params:

- `grant_type` (required, only `"authorization_code"` accepted; other grants → `unsupported_grant_type`)
- `code` (required)
- `client_id` (required)
- `redirect_uri` (required)
- `code_verifier` (required)
- `resource` (required — invariant §4.5)

Flow (steps 1–9, per §5.1) — all inside `BEGIN IMMEDIATE` transaction:

1. Look up `code` in `auth_codes`. Missing / expired (`exp < now`) / `used = 1` → `invalid_grant`.
2. Mark `used = 1` (same transaction — prevents replay under concurrent requests).
3. Validate canonicalized request `redirect_uri` byte-equals stored value.
4. Validate canonicalized request `client_id` byte-equals stored value.
5. Validate canonicalized request `resource` byte-equals stored value. Reject if absent/different → `invalid_target` per §5.4.
6. Validate `code_verifier`: `base64url(SHA-256(ASCII(verifier)))` byte-equals stored `code_challenge` — invariant §4.4. Constant-time compare. Mismatch → `invalid_grant`.
7. `mintAccessToken(...)` — JWT claims per §5.1 step 7:
   - `iss` = canonical `AS_ISSUER_URL`
   - `aud` = canonical `resource` (string, single-valued per invariant §4.5)
   - `sub` from auth_code row
   - `client_id` from auth_code row
   - `scope` from auth_code row
   - `exp` = now + `AS_TOKEN_TTL_SEC`
   - `iat` = now
   - `nbf` = now
   - `jti` = `crypto.randomUUID()`
8. Sign with the active key (slice 6's `SigningKeyset`). JWT header MUST include `kid`. MUST NOT use `alg: "none"`.
9. `issueRefreshToken(...)` — 32 random bytes returned to client as base64url; stored as SHA-256 hex hash in `refresh_tokens` bound to `client_id`, `resource`, `scope`, `sub`, fresh `family_id` (UUID v4), `parent_hash = null`, `exp = now + AS_REFRESH_TOKEN_TTL_SEC`.

### Response (§5.2)

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "<granted scopes>",
  "refresh_token": "<opaque base64url>"
}
```

### Error responses (§5.4)

`application/json`, HTTP 400 (HTTP 401 for `invalid_client`). Each branch is reachable via a test:

| `error` | When |
|---|---|
| `invalid_request` | Missing/malformed param; multiple `resource` values; wrong Content-Type |
| `invalid_grant` | Bad code; expired/replayed code; bad PKCE; mismatched `client_id`/`redirect_uri` |
| `invalid_client` | Request `client_id` canonical mismatch vs stored |
| `unsupported_grant_type` | `grant_type` ≠ `authorization_code` |
| `invalid_scope` | (not reached on the auth-code grant — codes are bound to scope) |
| `invalid_target` | `resource` missing or mismatched |

## Test patterns

```ts
describe("POST /token (authorization_code grant)", () => {
  it("happy path → JWT + refresh token", async () => {
    // 1. drive /authorize to get a code
    // 2. POST /token with valid params
    // 3. assert JWT verifies with the active JWKS, has expected claims
  });

  it("[INV-4.4] rejects bad PKCE verifier", async () => {
    /* ... */
  });

  it("[INV-4.5] rejects multiple resource params", async () => {
    /* ... */
  });

  it("[INV-4.5] rejects missing resource", async () => {
    /* ... */
  });

  it("replayed code → invalid_grant", async () => {
    // POST twice with the same code
  });

  it("expired code → invalid_grant", async () => {
    // set auth_codes.exp to a past value
  });

  it("mismatched redirect_uri → invalid_grant", async () => {
    /* ... */
  });

  it("mismatched client_id → invalid_grant", async () => {
    /* ... */
  });

  it("alg: none token MUST NOT be issued", async () => {
    // assert the JWT header.alg is the active AS_SIGNING_ALG, not "none"
  });

  it("issues refresh token bound to (client_id, resource, scope, sub)", async () => {
    // SELECT FROM refresh_tokens WHERE family_id = ... → assert row shape
  });
});
```

For JWT verification in tests: use shared slice 5's `createJWTVerifier` pointed at the in-process IdP — assert the IdP's tokens roundtrip through the verifier.

## Out of scope

- `grant_type=refresh_token` redemption + rotation + family revocation (per [authorization-server.md §5.3](../specs/authorization-server.md) — deferred).
- Token introspection / revocation endpoints (architecture §6 non-goal).
- Key rotation.

## Verification

```bash
test -f apps/mock-customer-idp/src/routes/token.ts
test -f apps/mock-customer-idp/src/jwt.ts
test -f apps/mock-customer-idp/src/refresh.ts

pnpm typecheck
pnpm lint
pnpm test

pnpm exec vitest run -t '[INV-4.4]' --reporter=verbose
pnpm exec vitest run -t '[INV-4.5]' --reporter=verbose

# Independent AI review — address findings before commit
cr review --agent --type uncommitted -c CLAUDE.md -c specs/authorization-server.md
```

All gate commands must exit 0. CodeRabbit findings: address or explicitly acknowledge.

Smoke (optional, with IdP running):

```bash
# After driving /authorize and getting a code, manually:
curl -s -X POST http://localhost:4444/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=...&client_id=...&redirect_uri=...&code_verifier=...&resource=..." \
  | jq .access_token
```
