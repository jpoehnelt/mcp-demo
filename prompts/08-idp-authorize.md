# Step 8 — IdP Authorize Endpoint

## Spec anchors

- [authorization-server.md §4](../specs/authorization-server.md) — Authorization Endpoint (all subsections)
- [architecture.md §4.4](../specs/architecture.md), [§4.5](../specs/architecture.md), [§4.9](../specs/architecture.md), [§4.10](../specs/architecture.md), [§4.14](../specs/architecture.md) — Relevant invariants
- [shared-library.md §2.6](../specs/shared-library.md) — `validateFetchedCIMD` used here

## Goal

Implement `GET /authorize` (request validation + CIMD fetch + consent UI render) and `POST /authorize/consent` (approve/deny → redirect with code or error). This is the most logic-dense slice in the IdP — read §4 carefully.

## Deliverables

- `apps/mock-customer-idp/src/routes/authorize.ts` — both handlers
- `apps/mock-customer-idp/src/cimd-cache.ts` — DB-backed fetch + cache
- `apps/mock-customer-idp/src/consent.ts` — HTML rendering helpers
- `apps/mock-customer-idp/src/session.ts` — minimal signed-cookie session for the consent flow
- New tests added to `integration.test.ts` covering authorize happy path, CIMD failures, SSRF rejection, missing PKCE, multiple `resource` values, user denial

## Public API (internal)

```ts
// routes/authorize.ts
export function registerAuthorizeRoutes(app: Hono, deps: {
  env: IdPEnv;
  db: Database;
  log: Logger;
}): void;

// cimd-cache.ts
export function fetchAndValidateCIMD(
  url: string,
  deps: { env: IdPEnv; db: Database; log: Logger },
): Promise<CIMDDocument>;
```

## Acceptance criteria

### `GET /authorize` request parsing (§4.1)

All parameters parsed with zod:

| Param | Validation |
|---|---|
| `response_type` | `"code"` only |
| `client_id` | absolute `https://` URL OR `http://127.0.0.1[:port]/path` when `AS_DEV_ALLOW_INSECURE_CIMD=true`. Path required. Non-URL values rejected. |
| `redirect_uri` | absolute URL (validated against CIMD `redirect_uris` after fetch) |
| `scope` | space-delimited; subset of `scopes_supported` |
| `state` | non-empty string |
| `code_challenge` | non-empty string |
| `code_challenge_method` | `"S256"` only |
| `resource` | absolute URI. **Exactly one occurrence** — invariant §4.5. Multiple → `invalid_request`. |

Param errors map to OAuth 2.1 §4.1.2.1 redirects when `redirect_uri` is known-valid; otherwise return 400 with a plain error message.

### CIMD resolution (§4.2)

Implemented in `fetchAndValidateCIMD`:

1. Canonicalize the URL via slice 1's `canonicalize`.
2. Look up `cimd_cache` keyed on the canonical URL. If row exists with `expires_at > now()`, return the cached document.
3. On miss, call shared `safeFetch` (slice 4) with:
   - `allowInsecure: env.AS_DEV_ALLOW_INSECURE_CIMD`
   - `maxBytes: 100_000`
   - `timeoutMs: 5_000`
   - `expectContentType: "application/json"`
4. Pass the parsed JSON to shared `validateFetchedCIMD` (slice 5) — this enforces invariant §4.9 (URL match), path requirement, redirect URI shape.
5. Persist to `cimd_cache` with `fetched_at = now()`, `expires_at` derived from response `Cache-Control: max-age` (default 5 min, cap 1 day).

SSRF errors propagate as `SSRFBlockedError`; map to `invalid_client` in the response.

### `GET /authorize` flow

1. Parse request → on failure redirect with error or 400.
2. `fetchAndValidateCIMD(request.client_id)` → on failure `invalid_client` redirect (when redirect_uri-valid) or 400.
3. Validate `request.redirect_uri` byte-equals (after canonicalize) one of `cimd.redirect_uris` — invariant §4.10. Otherwise 400 (don't redirect to an unverified URI).
4. Validate `request.scope` subset of `scopes_supported` — otherwise redirect with `error=invalid_scope`.
5. If `AS_AUTO_APPROVE=true`: skip the consent UI; act as if user pressed Approve. Use `sub = AS_DEMO_USER_SUB`.
6. Else: render consent HTML (a minimal `<form action="/authorize/consent" method="POST">` with hidden fields carrying the request params + a signed session cookie). Display `client_name`, `client_uri`, `logo_uri`, requested scopes, redirect URI hostname. MUST warn if `redirect_uri` is loopback (per MCP localhost-risks reference).

### `POST /authorize/consent`

- Read the signed session cookie; verify HMAC. Reject if tampered.
- On Approve: generate `code = base64url(crypto.randomBytes(32))`, persist row in `auth_codes` (table from §7) with all the §4.6 fields, then 302 to `redirect_uri?code=<code>&state=<state>`.
- On Deny: 302 to `redirect_uri?error=access_denied&state=<state>` per OAuth 2.1 §4.1.2.1.

### Auth code record (§4.6)

Stored fields exactly per the table — note the `exp` is `now + 60_000` ms (60s TTL).

### Session cookie (`session.ts`)

- HMAC-signed (HS256 with a server-process-local random secret). Format: `<base64url(json-payload)>.<base64url(hmac)>`.
- Scoped to `/authorize` path. `HttpOnly`. `SameSite=Lax`. Not `Secure` in dev (HTTP localhost) but document the production requirement.
- Carries: the parsed request params + a CSRF token tied to the form. 5-minute TTL.

## Test patterns

```ts
describe("GET /authorize", () => {
  it("happy path with AS_AUTO_APPROVE", async () => {
    // boot CIMD server in-process at http://127.0.0.1:<port>/client.json
    // call /authorize with valid params
    const res = await app.request(`/authorize?${buildQuery(validParams)}`);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toMatch(/\?code=[\w-]+&state=/);
  });

  it("[INV-4.5] rejects multiple resource params", async () => {
    const res = await app.request("/authorize?resource=a&resource=b&...");
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toMatch(/error=invalid_request/);
  });

  it("[INV-4.10] rejects redirect_uri not in CIMD", async () => {
    /* ... */
  });

  it("[INV-4.9] rejects CIMD whose client_id doesn't match fetch URL", async () => {
    /* serve a CIMD doc with mismatched client_id */
  });

  it("rejects CIMD URL resolving to private IP (SSRF)", async () => {
    /* stub dns.lookup */
  });

  it("rejects code_challenge_method=plain", async () => {
    /* ... */
  });

  it("renders consent UI when AS_AUTO_APPROVE=false", async () => {
    /* assert HTML contains client_name */
  });
});

describe("POST /authorize/consent", () => {
  it("deny → redirect with error=access_denied", async () => {
    /* ... */
  });

  it("approve → persists auth_code row + redirects with code", async () => {
    /* ... */
  });

  it("forged session cookie → reject", async () => {
    /* ... */
  });
});
```

To boot a local CIMD server for tests: a small Hono app serving a canned CIMD document on a random port, used as the `client_id`. Pattern reusable across slices.

## Out of scope

- Refresh-token grant (slice 9 issues refresh tokens but only the `authorization_code` grant is supported in this PoC).
- Token endpoint (slice 9).
- Multi-tenant issuers.

## Verification

```bash
test -f apps/mock-customer-idp/src/routes/authorize.ts
test -f apps/mock-customer-idp/src/cimd-cache.ts
test -f apps/mock-customer-idp/src/consent.ts
test -f apps/mock-customer-idp/src/session.ts

pnpm typecheck
pnpm lint
pnpm test

pnpm exec vitest run -t '[INV-4.5]' --reporter=verbose
pnpm exec vitest run -t '[INV-4.9]' --reporter=verbose
pnpm exec vitest run -t '[INV-4.10]' --reporter=verbose

# Independent AI review — address findings before commit
cr review --agent --type uncommitted -c CLAUDE.md -c specs/authorization-server.md
```

All gate commands must exit 0. CodeRabbit findings: address or explicitly acknowledge.
