# Step 7 — IdP Metadata + JWKS

## Spec anchors

- [authorization-server.md §1](../specs/authorization-server.md) — Endpoints list
- [authorization-server.md §3](../specs/authorization-server.md) — AS metadata, OIDC mirror, JWKS
- [authorization-server.md §6](../specs/authorization-server.md) — Key management (alg derived at runtime, §3.2/§3.3 reference §6 as canonical)

## Goal

Publish the three metadata endpoints clients use for discovery: RFC 8414 authorization server metadata, OIDC Discovery mirror, and the JWKS endpoint. All three reflect the active `AS_SIGNING_ALG` dynamically (no hardcoded RS256).

## Deliverables

- `apps/mock-customer-idp/src/routes/metadata.ts` — three route handlers + registration helper
- Tests in `apps/mock-customer-idp/src/integration.test.ts` (extend the existing file from slice 6)

## Public API (internal)

```ts
// metadata.ts
export function registerMetadataRoutes(app: Hono, deps: {
  env: IdPEnv;
  keys: SigningKeyset;
}): void;
```

Registers `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`, and `/jwks.json` on the passed Hono app. Called from `createIdPApp` in `app.ts`.

## Acceptance criteria

### `GET /.well-known/oauth-authorization-server` (§3.1)

Returns exactly:

```json
{
  "issuer": "<canonical AS_ISSUER_URL>",
  "authorization_endpoint": "<AS_ISSUER_URL>/authorize",
  "token_endpoint": "<AS_ISSUER_URL>/token",
  "jwks_uri": "<AS_ISSUER_URL>/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"],
  "client_id_metadata_document_supported": true,
  "scopes_supported": ["weather:read", "weather:premium"]
}
```

`Content-Type: application/json`, `Cache-Control: max-age=3600`.

Note: `scopes_supported` is exactly `["weather:read", "weather:premium"]` — no `openid` or `offline_access` (per [authorization-server.md §3.1](../specs/authorization-server.md), OIDC + offline_access are out of scope for this PoC).

### `GET /.well-known/openid-configuration` (§3.2)

Mirrors §3.1 plus:

- `subject_types_supported: ["public"]`
- `id_token_signing_alg_values_supported`: array containing the active `AS_SIGNING_ALG` value — **NOT hardcoded**. If `AS_SIGNING_ALG=ES256`, this field is `["ES256"]`.
- `userinfo_endpoint: "<AS_ISSUER_URL>/userinfo"` — stub. Returns 200 with `{}` on GET (out of scope to actually populate; clients shouldn't rely on it since OIDC is non-goal).

`Content-Type: application/json`, `Cache-Control: max-age=3600`.

### `GET /jwks.json` (§3.3 + §6)

Returns:

```json
{
  "keys": [
    {
      "kid": "<from signing_keys.kid>",
      "use": "sig",
      "alg": "<active AS_SIGNING_ALG>",
      ...rest of the public JWK fields
    }
  ]
}
```

The `alg` value is derived from `keys.alg`, not hardcoded. Multiple keys may be returned in future (key rotation), but for now there's exactly one.

`Content-Type: application/json`, `Cache-Control: max-age=3600`.

### `GET /userinfo`

Stub: returns 200 with `{}`. Existing only because §3.2's metadata advertises the endpoint.

## Test patterns

Extend `integration.test.ts` with new `describe` blocks:

```ts
describe("AS metadata", () => {
  it("returns canonical issuer + endpoint URLs", async () => {
    const res = await app.request("/.well-known/oauth-authorization-server");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.issuer).toBe("http://localhost:4444");
    expect(body.scopes_supported).toEqual(["weather:read", "weather:premium"]);
    expect(body.code_challenge_methods_supported).toEqual(["S256"]);
  });

  it("Cache-Control: max-age=3600", async () => {
    const res = await app.request("/.well-known/oauth-authorization-server");
    expect(res.headers.get("Cache-Control")).toBe("max-age=3600");
  });
});

describe("OIDC mirror", () => {
  it("id_token_signing_alg_values_supported reflects AS_SIGNING_ALG", async () => {
    // boot a second app with AS_SIGNING_ALG=ES256
    const app = createIdPApp({ env: { ...baseEnv, AS_SIGNING_ALG: "ES256" }, ... });
    const body = await (await app.request(".../openid-configuration")).json();
    expect(body.id_token_signing_alg_values_supported).toEqual(["ES256"]);
  });
});

describe("JWKS", () => {
  it("returns a single key with matching kid + alg", async () => {
    const body = await (await app.request("/jwks.json")).json();
    expect(body.keys).toHaveLength(1);
    expect(body.keys[0].kid).toBe(keys.kid);
    expect(body.keys[0].alg).toBe(env.AS_SIGNING_ALG);
    expect(body.keys[0].use).toBe("sig");
  });
});
```

## Out of scope

- Key rotation (the keyset always has one active key in this PoC).
- `/authorize` and `/token` endpoints (slices 8 and 9).

## Verification

```bash
test -f apps/mock-customer-idp/src/routes/metadata.ts

pnpm typecheck
pnpm lint
pnpm test

# Independent AI review — address findings before commit
cr review --agent --type uncommitted -c CLAUDE.md -c specs/authorization-server.md
```

All gate commands must exit 0. CodeRabbit findings: address or explicitly acknowledge.

Smoke (optional, with the IdP running):

```bash
cp apps/mock-customer-idp/.env.example apps/mock-customer-idp/.env  # if not done
pnpm dev:idp &
sleep 1
curl -s http://localhost:4444/.well-known/oauth-authorization-server | jq .scopes_supported
# → ["weather:read", "weather:premium"]
curl -s http://localhost:4444/jwks.json | jq '.keys[0].alg'
# → "RS256" (or your active AS_SIGNING_ALG)
kill %1
```
