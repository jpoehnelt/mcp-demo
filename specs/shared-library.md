# Shared Library Specification

The `@poc/shared` package contains all cross-cutting OAuth, JWT, PKCE, discovery, validation, and SSRF logic. The three application packages import from here. No OAuth-related logic is duplicated across apps.

## 1. Modules

### 1.1 CIMD Document Schema

Zod schema per [CIMD draft-01 §4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-01#section-4). Schema is strict (zod v4 `.strict()`): unknown top-level keys MUST be rejected.

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `client_id` | string | MUST | Canonical URL (architecture §4.11). MUST have a non-empty path component (a bare domain or path of `/` is rejected). Scheme is `https://` by default, or `http://127.0.0.1[:port]` when `allowInsecure` is true — the path requirement applies to both schemes |
| `client_name` | string | MUST | |
| `client_uri` | string | MAY | |
| `logo_uri` | string | MAY | |
| `redirect_uris` | string[] | MUST | Non-empty; each entry HTTPS or `http://127.0.0.1[:port]` |
| `grant_types` | string[] | MAY | Default: `["authorization_code"]`. Accepted values: `"authorization_code"`, `"refresh_token"`. Any other value MUST be rejected. |
| `response_types` | string[] | MAY | Default and only accepted value: `["code"]` |
| `token_endpoint_auth_method` | `"none"` | MAY | Default and only accepted value: `"none"`. `private_key_jwt` is out of scope (architecture §6). |
| `scope` | string | MAY | Space-delimited; subset of authorization server `scopes_supported` |

Export: `parseCIMDDocument(json: unknown, opts: { allowInsecure: boolean }): CIMDDocument`

### 1.2 Protected Resource Metadata Schema

Zod schema per [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728):

| Field | Type | Required |
|-------|------|----------|
| `resource` | string | MUST | Canonical URI |
| `authorization_servers` | string[] | MUST | Minimum 1 |
| `scopes_supported` | string[] | MAY | |
| `bearer_methods_supported` | string[] | MAY | Default: `["header"]` |
| `resource_documentation` | string | MAY | |

### 1.3 Authorization Server Metadata Schema

Zod schema for the union of [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) and [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) fields:

| Field | Required |
|-------|----------|
| `issuer` | MUST |
| `authorization_endpoint` | MUST |
| `token_endpoint` | MUST |
| `jwks_uri` | MUST |
| `response_types_supported` | MUST |
| `grant_types_supported` | SHOULD |
| `code_challenge_methods_supported` | MUST (for MCP) |
| `scopes_supported` | SHOULD |
| `token_endpoint_auth_methods_supported` | SHOULD |
| `client_id_metadata_document_supported` | MAY |
| `registration_endpoint` | MAY |

### 1.4 JWT Claims Schema

| Field | Type | Required |
|-------|------|----------|
| `iss` | string | MUST |
| `sub` | string | MUST |
| `aud` | string \| string[] | MUST |
| `exp` | number | MUST |
| `iat` | number | MUST |
| `nbf` | number | MAY (validated by jose if present per §2.4 and resource-server §4.1) |
| `jti` | string | MUST |
| `scope` | string | MUST |
| `client_id` | string | MUST |

## 2. OAuth Modules

### 2.1 Canonical URI

- `canonicalize(url: string): string` — implements architecture §4.11:
  - Lowercases scheme and host
  - Removes default port (`:80` for http, `:443` for https)
  - Removes fragment
  - Removes trailing slash (unless path is empty/`/`, in which case path becomes empty)
  - Normalizes percent-encoding per [RFC 3986 §6.2.2](https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2)
  - Validates absolute URI; throws `InvalidCanonicalURIError` otherwise
- `equalsCanonical(a: string, b: string): boolean` — Constant-time comparison after canonicalization.

MUST handle all examples from the MCP spec [Canonical Server URI](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#canonical-server-uri) section. The invariant test suite enumerates each example.

### 2.2 PKCE

- `generatePKCE(): { verifier: string; challenge: string; method: "S256" }`
  - Verifier: 43–128 chars from the unreserved set per [RFC 7636 §4.1](https://datatracker.ietf.org/doc/html/rfc7636#section-4.1) (`ALPHA / DIGIT / "-" / "." / "_" / "~"`)
  - Challenge: `base64url(SHA-256(ASCII(verifier)))` with NO padding
  - Uses `crypto.randomBytes(32)` (≥256 bits entropy) and `crypto.createHash('sha256')`

**Do NOT use `Buffer.from(x, 'base64')`** — use base64url (Node `'base64url'` encoding). Padding and charset differ.

### 2.3 CSRF State

- `generateState(): string` — 32 random bytes (`crypto.randomBytes(32)`) base64url-encoded. ≥256 bits entropy, well above the 128-bit floor of **architecture invariant §4.14**.
- `verifyState(received: string, expected: string): boolean` — constant-time comparison (`crypto.timingSafeEqual`).
- The client MUST store `expected` in memory (or signed cookie) keyed by the authorization request and MUST clear it immediately after callback verification.

### 2.4 JWT Verifier

```typescript
createJWTVerifier(opts: {
  issuer: string;
  audience: string;
  jwksCacheTTLms?: number;
}): { verify(token: string): Promise<TokenClaims> }
```

- Uses `jose.createRemoteJWKSet` internally.
- Reject MAC algorithms (`HS*`); accept only `RS256`, `ES256`, `EdDSA` (architecture invariant §4.3).
- Verifies: signature, `iss` (canonical compare), `aud` (string or array per RFC 7519 §4.1.3, containment check after canonicalization), `exp`, `nbf`, `iat`.
- ±30 s clock skew tolerance.
- Cache TTL from JWKS response `Cache-Control: max-age`, fallback 3600 s, cap 24 h.
- MUST throw typed errors: `InvalidTokenError`, `InvalidAudienceError`, `InvalidIssuerError`, `TokenExpiredError`, `UnsupportedAlgError`.

### 2.5 Metadata Discovery

- `resolvePRMUrl(mcpServerUrl: string): string` — Per [RFC 9728 §3](https://datatracker.ietf.org/doc/html/rfc9728#section-3). MUST handle path-aware resolution (e.g., `https://example.com/public/mcp` → `https://example.com/.well-known/oauth-protected-resource/public/mcp`).
- `fetchPRM(url: string): Promise<ProtectedResourceMetadata>` — Fetches and validates PRM.
- `discoverASMetadata(issuerUrl: string): Promise<ASMetadata>` — Implements the cascade from the MCP spec [Authorization Server Metadata Discovery](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#authorization-server-metadata-discovery):
  1. `{issuer}/.well-known/oauth-authorization-server` with path insertion ([RFC 8414 §3.1](https://datatracker.ietf.org/doc/html/rfc8414#section-3.1))
  2. `{issuer}/.well-known/openid-configuration` with path insertion
  3. `{issuer}/.well-known/openid-configuration` with path appending

- MUST hard-fail if `code_challenge_methods_supported` does not include `S256`.

### 2.6 CIMD Validator

```typescript
validateFetchedCIMD(
  url: string,
  json: unknown,
  opts: { allowInsecure: boolean }
): CIMDDocument
```

1. Parse JSON with `parseCIMDDocument(json, opts)`.
2. Compute `canonicalize(url)` and `canonicalize(parsed.client_id)`; assert byte-equal — **architecture invariant §4.9**. Rejects mismatches whether semantic (`https://Example.com` vs `https://example.com`) or literal.
3. Verify the canonical URL has a non-empty path component (`/cimd`, `/.well-known/cimd`, etc.); reject bare-domain URLs.
4. For each `redirect_uri`: require `https://` OR `http://127.0.0.1[:port]`. **Reject `http://localhost`** — localhost resolves dynamically and breaks the SSRF model.
5. Return the validated document with `client_id` set to its canonical form.

## 3. HTTP Modules

### 3.1 `WWW-Authenticate` Header Helpers

- `buildUnauthorizedHeader(opts)` → `Bearer realm="...", resource_metadata="...", scope="..."`
- `buildInsufficientScopeHeader(opts)` → `Bearer realm="...", error="insufficient_scope", scope="...", resource_metadata="...", error_description="..."`
- `parseWWWAuthenticate(header: string)` → `{ scheme: string; params: Record<string, string> }`

`realm` defaults to the resource's canonical URI. Quoted-string escaping per [RFC 7235 §2.1](https://datatracker.ietf.org/doc/html/rfc7235#section-2.1).

### 3.2 SSRF-Safe Fetch

- `isDeniedAddress(ip: string, opts: { allowLoopback: boolean }): boolean` — Returns true for any address in the denylist below. When `allowLoopback` is true, `127.0.0.0/8` is excluded (matches `AS_DEV_ALLOW_INSECURE_CIMD=true`); all other ranges remain denied.

  | Family | Ranges |
  | ------ | ------ |
  | IPv4 private (RFC 1918) | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
  | IPv4 loopback | `127.0.0.0/8` (toggleable) |
  | IPv4 link-local | `169.254.0.0/16` |
  | IPv4 CGNAT (RFC 6598) | `100.64.0.0/10` |
  | IPv4 multicast | `224.0.0.0/4` |
  | IPv4 broadcast / unspecified | `255.255.255.255/32`, `0.0.0.0/8` |
  | IPv6 loopback | `::1/128` |
  | IPv6 link-local | `fe80::/10` |
  | IPv6 ULA | `fc00::/7` |
  | IPv6 multicast | `ff00::/8` |
  | IPv4-mapped IPv6 | `::ffff:0:0/96` (recursively re-check) |

- `safeFetch(url, opts): Promise<{ status; body; headers }>`:
  1. Parse URL. Resolve hostname to **all** A and AAAA records via `dns.lookup`.
  2. If any resolved IP fails `isDeniedAddress` → `SSRFBlockedError` (do not attempt connection to other addresses; an attacker who can resolve to a denied IP wins regardless).
  3. Pin the connection to a specific approved address (defeats DNS rebinding).
  4. Fetch with `AbortController` for timeout and `maxRedirects: 0`.
  5. Stream response body with byte counter; throw `MaxBytesExceededError` if exceeded.
  6. Validate `Content-Type` matches `expectContentType` → `InvalidContentTypeError` if not.

## 4. Error Classes

Each error carries an OAuth error code for HTTP response translation:

| Error Class | OAuth Code |
|-------------|------------|
| `InvalidTokenError` | `invalid_token` |
| `InvalidAudienceError` | `invalid_token` |
| `InvalidIssuerError` | `invalid_token` |
| `TokenExpiredError` | `invalid_token` |
| `InsufficientScopeError` | `insufficient_scope` |
| `InvalidCIMDError` | `invalid_client` |
| `SSRFBlockedError` | `invalid_request` |
| `MaxBytesExceededError` | `invalid_request` |
| `InvalidContentTypeError` | `invalid_request` |
| `PKCEMismatchError` | `invalid_grant` |
