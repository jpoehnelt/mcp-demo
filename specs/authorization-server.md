# Authorization Server Specification

The Authorization Server (`mock-customer-idp`) simulates what a BYOC customer would bring (Okta, Entra, Keycloak). It MUST be standards-correct on the wire.

## 1. Endpoints

| Method | Path | Standard | Purpose |
|--------|------|----------|---------|
| GET | `/.well-known/oauth-authorization-server` | [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) | Authorization server metadata |
| GET | `/.well-known/openid-configuration` | [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) | OIDC-compatible mirror |
| GET | `/jwks.json` | [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) | Public signing keys |
| GET | `/authorize` | [OAuth 2.1 §4.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15#section-4.1.1) | Authorization endpoint |
| POST | `/authorize/consent` | — | Consent form handler |
| POST | `/token` | [OAuth 2.1 §4.1.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15#section-4.1.3) | Token endpoint |
| GET | `/healthz` | — | Health check |

## 2. Configuration

All env vars MUST be parsed with zod at startup. Invalid config MUST prevent startup.

| Env Var | Default | Purpose |
|---------|---------|---------|
| `AS_ISSUER_URL` | — (required) | Issuer identifier; MUST canonicalize per architecture §4.11. For this PoC, MUST have an empty path component (e.g., `http://localhost:4444`, not `http://localhost:4444/tenant1`). The well-known endpoints in §1 are mounted at root; path-having issuers would require RFC 8414 §3.1 path-insertion routing, which is out of scope. The MCP server's discovery cascade (shared-library §2.5) DOES handle path-having issuers, so this constraint applies only to the mock IdP. |
| `AS_PORT` | `4444` | Listen port |
| `AS_DB_PATH` | `./as.db` | SQLite database path |
| `AS_DEV_ALLOW_INSECURE_CIMD` | `false` | Allow `http://127.0.0.1` CIMD URLs (dev only — see §4.3) |
| `AS_AUTO_APPROVE` | `false` | Skip login + consent UI for headless demo (uses `AS_DEMO_USER_SUB`) |
| `AS_DEMO_USER_SUB` | `demo-user` | Hard-coded `sub` for the single demo user (see §4.4) |
| `AS_SIGNING_ALG` | `RS256` | JWT signing algorithm: `RS256` \| `ES256` \| `EdDSA` (see §6) |
| `AS_TOKEN_TTL_SEC` | `300` | Access token lifetime (5 min) |
| `AS_REFRESH_TOKEN_TTL_SEC` | `86400` | Refresh token lifetime (24 h) |

## 3. Authorization Server Metadata

### 3.1 `/.well-known/oauth-authorization-server`

```json
{
  "issuer": "<AS_ISSUER_URL>",
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

`openid` and `offline_access` are intentionally NOT advertised: OIDC is out of scope (architecture §6), and refresh tokens are issued unconditionally by §5.1 step 9 (this PoC does not gate refresh on `offline_access`). Re-introduce these scopes only if you also implement ID-token issuance / `offline_access` gating respectively.

### 3.2 `/.well-known/openid-configuration`

Mirrors §3.1 plus:
- `subject_types_supported: ["public"]`
- `id_token_signing_alg_values_supported`: array containing the active `AS_SIGNING_ALG` value
- `userinfo_endpoint`: stub returning 200 with empty profile

Note: this PoC does not actually issue ID tokens (OIDC is out of scope — architecture §6); the field is published only so OIDC-aware discovery clients don't choke on its absence.

### 3.3 `/jwks.json`

Returns the current public signing key in JWK format with `kid`, `use: "sig"`, and `alg` set to the active `AS_SIGNING_ALG` value (`RS256` | `ES256` | `EdDSA`). The `alg` field is derived at runtime, not hardcoded — §6 (Key Management) is the canonical source.

Response MUST include `Cache-Control: max-age=3600`.

## 4. Authorization Endpoint

### 4.1 Request Parameters

All parameters MUST be validated with zod.

| Parameter | Required | Validation |
|-----------|----------|------------|
| `response_type` | MUST | Only `code` supported (no implicit, no hybrid) |
| `client_id` | MUST | MUST be an absolute `https://` URL (or `http://127.0.0.1[:port]` when `AS_DEV_ALLOW_INSECURE_CIMD=true`) with a non-empty path — treated as a CIMD URL. Non-URL `client_id` values MUST be rejected (DCR is out of scope per architecture §6). The path requirement is enforced again during CIMD document validation (§4.2 step 4 via shared-library §2.6); this row states the surface-level shape check at request parse time. |
| `redirect_uri` | MUST | MUST be present in the resolved CIMD's `redirect_uris` (byte-equal after canonicalization) — architecture invariant §4.10 |
| `scope` | MUST | Space-delimited; MUST be a subset of `scopes_supported` |
| `state` | MUST | Opaque CSRF token (≥128 bits entropy); echoed verbatim on redirect — architecture invariant §4.14 |
| `code_challenge` | MUST | Required — architecture invariant §4.4 |
| `code_challenge_method` | MUST | Only `S256` accepted (`plain` rejected) |
| `resource` | MUST | Exactly one occurrence required — architecture invariant §4.5; stored with the issued code |

### 4.2 CIMD Resolution

When `client_id` arrives at `/authorize`:

1. **Canonicalize** the URL per architecture §4.11 (lowercase scheme/host, no default port, no trailing slash, no fragment, normalize percent-encoding). All subsequent comparisons use the canonical form.
2. Check `cimd_cache` keyed on the canonical URL for a fresh entry (respect prior fetch's `Cache-Control: max-age`; fallback 5 minutes; cap at 1 day).
3. On cache miss, fetch the CIMD document using SSRF-safe fetch (see §4.3):
   - `allowInsecure`: value of `AS_DEV_ALLOW_INSECURE_CIMD`
   - `maxBytes`: 100,000
   - `timeoutMs`: 5,000
   - `expectContentType`: `application/json`
   - `maxRedirects`: 0 (a CIMD URL must serve its own document, not redirect)
4. Validate the fetched document:
   - Parse JSON against the CIMD zod schema (rejects unknown top-level fields under the v4 strict default).
   - Canonicalize `parsed.client_id` and assert it equals the canonical fetch URL — **architecture invariant §4.9**.
   - For each `redirect_uri`: require `https://` OR `http://127.0.0.1[:port]`; reject `http://localhost` (resolves dynamically; use the literal loopback IP).
   - Reject if `redirect_uris` is empty.
5. Cache the validated document with `(fetched_at, expires_at)` derived from the response's `Cache-Control: max-age`.

### 4.3 SSRF Protection

Before fetching any CIMD URL, the authorization server MUST:

1. Resolve the hostname to IP addresses (both A and AAAA records).
2. Reject the request if **any** resolved address falls in a denylisted range, then **pin the connection to a specific approved address** (defeats DNS rebinding between resolve-time and connect-time).
3. Apply timeouts, byte caps, and `maxRedirects: 0` per §4.2.

Denylisted address ranges (when `AS_DEV_ALLOW_INSECURE_CIMD=false`):

| Family | Ranges |
| ------ | ------ |
| IPv4 private (RFC 1918) | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| IPv4 loopback | `127.0.0.0/8` |
| IPv4 link-local | `169.254.0.0/16` |
| IPv4 CGNAT (RFC 6598) | `100.64.0.0/10` |
| IPv4 multicast | `224.0.0.0/4` |
| IPv4 broadcast / unspecified | `255.255.255.255/32`, `0.0.0.0/8` |
| IPv6 loopback | `::1/128` |
| IPv6 link-local | `fe80::/10` |
| IPv6 ULA (RFC 4193) | `fc00::/7` |
| IPv6 multicast | `ff00::/8` |
| IPv4-mapped IPv6 | `::ffff:0:0/96` (re-check the embedded IPv4 against the above) |

When `AS_DEV_ALLOW_INSECURE_CIMD=true`, IPv4 loopback (`127.0.0.0/8`) becomes allowed; all other ranges still denied. The dev flag exists so the demo CLI can host its CIMD on `http://127.0.0.1:<ephemeral>`; it does NOT open up arbitrary private-IP fetching.

Reference: [CIMD draft-01 §6 (SSRF)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-01#name-server-side-request-forgery).

### 4.4 User Authentication

The mock IdP is **not** a production user store. It ships with a single hard-coded user (`sub=demo-user`, configurable via `AS_DEMO_USER_SUB`) and supports two auth modes:

| Mode | Trigger | Behavior |
| ---- | ------- | -------- |
| Headless | `AS_AUTO_APPROVE=true` | No login UI; `sub` is taken from `AS_DEMO_USER_SUB`; consent is implicitly granted |
| Interactive | default | Render a minimal HTML form (username + password); on POST, validate against the hard-coded credential pair; set a signed session cookie scoped to `/authorize` |

The interactive form exists only so the auth-code flow looks realistic in screenshots; it has no password hashing, no rate limiting, no account lockout, and MUST NOT be deployed as-is. See `architecture.md §6` (Non-Goals) for rationale.

### 4.5 Consent UI

- Display: `client_name`, `client_uri`, `logo_uri`, requested scopes, redirect URI hostname.
- MUST display a warning when any `redirect_uri` is loopback ([MCP spec — Localhost Redirect URI Risks](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#localhost-redirect-uri-risks)).
- If `AS_AUTO_APPROVE=true`, skip rendering and proceed as if the user pressed "Approve".
- On approve: generate 32-byte base64url authorization code, persist to `auth_codes`, redirect to `redirect_uri?code=...&state=...` (302). The `state` value is echoed verbatim.
- On deny: redirect to `redirect_uri?error=access_denied&state=...` per [OAuth 2.1 §4.1.2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15#section-4.1.2.1).

### 4.6 Authorization Code Record

Stored fields (single-use, short-lived):

| Field | Source |
|-------|--------|
| `code` | 32 bytes from `crypto.randomBytes`, base64url |
| `client_id` | Canonical CIMD URL |
| `redirect_uri` | Canonical form, validated against CIMD `redirect_uris` |
| `code_challenge` | From authorize request |
| `code_challenge_method` | Always `S256` |
| `scope` | Granted scopes (space-delimited subset of requested) |
| `resource` | Canonical form of authorize-request `resource` |
| `sub` | Authenticated user (see §4.4) |
| `created_at` | `now` (epoch ms, for debugging) |
| `exp` | `now + 60s` (OAuth 2.1 recommends ≤10 min; tighter is safer) |
| `used` | Boolean, default false; set true atomically on first redemption |

## 5. Token Endpoint

Content-Type: `application/x-www-form-urlencoded` (NOT JSON).

### 5.1 Authorization Code Grant (`grant_type=authorization_code`)

Steps 1–2 run inside a single `BEGIN IMMEDIATE` transaction; the entire grant fails atomically on any check below.

1. Look up `code` in SQLite. If missing, expired (`exp < now`), or `used = 1` → `invalid_grant`.
2. Mark code `used = 1` (within the same transaction) — prevents replay even under concurrent requests.
3. Validate the canonical form of request `redirect_uri` byte-equals the stored value.
4. Validate request `client_id` (canonicalized) byte-equals the stored value.
5. Validate the canonical form of request `resource` byte-equals the stored value. MUST reject if absent or different — **architecture invariant §4.5**.
6. Validate `code_verifier`: `base64url(SHA-256(ASCII(verifier)))` byte-equals the stored `code_challenge` — **architecture invariant §4.4**. Compare in constant time.
7. Build JWT access token:

| Claim | Value |
|-------|-------|
| `iss` | Canonical `AS_ISSUER_URL` |
| `aud` | Canonical form of `resource` (string; single-valued per architecture §4.5) |
| `sub` | From code record |
| `client_id` | From code record |
| `scope` | Granted scopes (space-delimited) |
| `exp` | `now + AS_TOKEN_TTL_SEC` |
| `iat` | `now` |
| `nbf` | `now` |
| `jti` | Random UUID (v4) |

8. Sign with the algorithm from `AS_SIGNING_ALG` (default `RS256`; `ES256` and `EdDSA` supported). JWT header MUST include `kid`; MUST NOT use `alg: none`.
9. Issue refresh token: 32 random bytes, returned to the client as base64url, stored in SQLite as SHA-256 hash. Bound to `client_id`, `resource`, `scope`, `sub`, and a new `family_id` (UUID).

### 5.2 Response

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "<granted scopes>",
  "refresh_token": "<opaque>"
}
```

### 5.3 Refresh Token Grant (`grant_type=refresh_token`)

Runs inside a `BEGIN IMMEDIATE` transaction.

1. Look up the refresh token by `SHA-256(presented_token)`.
2. **Reuse detection.** If the row exists but is already `revoked = 1` → revoke every refresh token sharing the same `family_id`, return `invalid_grant`. This catches the "old token replayed after rotation" attack on a public client.
3. If the row is missing or `exp < now` → `invalid_grant` (no family revocation; the attacker never had a real token).
4. Validate the request `client_id` (canonicalized per architecture §4.11) byte-equals the `client_id` stored on the row. OAuth 2.1 §4.3.1 requires public clients to identify themselves on refresh; mismatch → `invalid_grant`. Compare in constant time.
5. Validate `resource`: if present in the request, its canonical form MUST byte-equal the stored value; if absent, the stored value is used (architecture invariant §4.5). Multiple `resource` values → `invalid_request`. Any mismatch → `invalid_target`.
6. Validate `scope`: if present, MUST be a subset of the stored scope (no expansion); if absent, the stored scope is reused. Expansion → `invalid_scope`.
7. Mark the presented row `revoked = 1`.
8. Mint a new access token from the stored row's bindings (`client_id`, `resource`, `scope`, `sub`) using the same JWT shape as §5.1 step 7–8 with a fresh `iat`, `nbf`, `exp`, and `jti`.
9. Issue a new refresh token in the same `family_id`, with `parent_hash` set to the presented token's hash. Return both.

Refresh-token rotation is required for public clients — [OAuth 2.1 §6.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15#section-6.1). Reuse-on-revoked detection (step 2) covers the stolen-refresh-token case.

### 5.4 Error Responses

Token-endpoint errors follow [OAuth 2.1 §4.1.3.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15#section-4.1.3.1) — `application/json`, HTTP 400 (or 401 for `invalid_client`):

| `error` | When |
| ------- | ---- |
| `invalid_request` | Missing/malformed parameter; multiple `resource` values |
| `invalid_grant` | Bad code, expired code, replayed code, bad PKCE verifier, bad/revoked refresh token, refresh `client_id` does not match the token's binding |
| `invalid_client` | Request `client_id` (canonicalized) does not byte-equal the stored value on the auth code |
| `unauthorized_client` | Client not allowed to use this grant type |
| `unsupported_grant_type` | Grant other than `authorization_code` or `refresh_token` |
| `invalid_scope` | Requested scope outside `scopes_supported` or outside granted scope on refresh |
| `invalid_target` | `resource` parameter missing (on `authorization_code`), not a canonical URI (RFC 8707), or does not match the value bound to the refresh token (on `refresh_token`) |

Authorization-endpoint errors redirect to the validated `redirect_uri` with `error`, `error_description` (optional, no secrets), and the original `state` — per [OAuth 2.1 §4.1.2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15#section-4.1.2.1).

## 6. Key Management

- On first boot, generate a signing keypair per `AS_SIGNING_ALG` (default `RS256` → RSA 2048; `ES256` → P-256; `EdDSA` → Ed25519). Store in `signing_keys` with a freshly generated `kid` (UUID).
- JWKS endpoint returns the public key with `kid`, `use: "sig"`, and the matching `alg`.
- JWKS response MUST include `Cache-Control: max-age=3600`.
- Private key (`private_jwk`) MUST NOT appear in any log output — **architecture invariant §4.12**.
- Key rotation is out of scope for the PoC (see architecture §6 Non-Goals). The schema supports multiple rows so rotation can be added without migration.

## 7. Storage Schema

```sql
CREATE TABLE signing_keys (
  kid TEXT PRIMARY KEY,
  alg TEXT NOT NULL,                     -- 'RS256' | 'ES256' | 'EdDSA'
  private_jwk JSON NOT NULL,
  public_jwk JSON NOT NULL,
  created_at INTEGER NOT NULL,
  retired_at INTEGER                     -- NULL = active; non-NULL = serve in JWKS but do not sign
);

CREATE TABLE cimd_cache (
  url TEXT PRIMARY KEY,                  -- canonical URL (architecture §4.11)
  document JSON NOT NULL,
  fetched_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE auth_codes (
  code TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,   -- always 'S256'
  scope TEXT NOT NULL,
  resource TEXT NOT NULL,
  sub TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  exp INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_auth_codes_exp ON auth_codes(exp);  -- for janitor sweep

CREATE TABLE refresh_tokens (
  token_hash TEXT PRIMARY KEY,           -- SHA-256(presented_token), hex
  family_id TEXT NOT NULL,               -- shared across rotated descendants; revoked together on reuse
  parent_hash TEXT,                      -- previous token in the family (NULL for first)
  client_id TEXT NOT NULL,
  resource TEXT NOT NULL,
  scope TEXT NOT NULL,
  sub TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  exp INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id);
```

## 8. Logging

Structured logging via pino. The following fields MUST be redacted at every log level — **architecture invariant §4.12**:

- Secret values: `token`, `access_token`, `refresh_token`, `code`, `code_verifier`, `private_jwk`, `client_secret` (defensive — none should exist), `password`
- Headers: `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`
- Query strings and request bodies on `/token` and `/authorize/consent` (entire payloads, since they carry the secrets above)

Redaction config MUST be centralized in a single logging module and exercised by an invariant test that scans a synthetic request flow's log output for any of the secret values.
