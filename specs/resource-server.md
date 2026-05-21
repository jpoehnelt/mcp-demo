# Resource Server Specification (MCP Server)

The MCP server acts as an [OAuth 2.1 resource server](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15#section-5). It enforces access control on MCP tools via audience-bound JWT access tokens.

**Architectural constraint:** The MCP server MUST NOT import from or depend on the authorization server implementation. It knows the authorization server only through `MCP_OIDC_ISSUER_URL`.

## 1. Endpoints

| Method | Path | Standard | Purpose |
|--------|------|----------|---------|
| GET | `/.well-known/oauth-protected-resource` | [RFC 9728 §3](https://datatracker.ietf.org/doc/html/rfc9728#section-3) | Protected Resource Metadata |
| POST | `/mcp` | [MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) | MCP transport (via SDK) |
| GET | `/healthz` | — | Health check |

> **Critical:** The PRM path is `/.well-known/oauth-protected-resource`, per RFC 9728. NOT `/.well-known/mcp-authorization`.

## 2. Configuration

| Env Var | Default | Purpose |
|---------|---------|---------|
| `MCP_OIDC_ISSUER_URL` | — (required) | Trusted issuer URL; used for JWKS fetch and `iss` validation. MUST canonicalize per architecture §4.11. |
| `MCP_AUDIENCE` | — (required) | Server's canonical URI. Used both to validate the token `aud` claim AND to populate the PRM `resource` field. MUST canonicalize. |
| `MCP_PRM_AUTH_SERVERS` | — (required) | Comma-separated authorization server issuer URLs published in the PRM `authorization_servers` array; each entry MUST canonicalize. |
| `MCP_PORT` | `3333` | Listen port (deployment-only, not identity). |

`MCP_OIDC_ISSUER_URL`, `MCP_AUDIENCE`, and `MCP_PRM_AUTH_SERVERS` are the **entire** identity-side configuration. Swapping these three to point at Okta/Entra/Keycloak MUST require no code changes — the BYOC contract (architecture §2.1).

## 3. Protected Resource Metadata

`GET /.well-known/oauth-protected-resource` MUST return (`Content-Type: application/json`, `Cache-Control: max-age=3600`):

```json
{
  "resource": "<canonical MCP_AUDIENCE>",
  "authorization_servers": ["<canonical MCP_PRM_AUTH_SERVERS entries, in order>"],
  "scopes_supported": ["weather:read"],
  "bearer_methods_supported": ["header"],
  "resource_documentation": "<optional URL>"
}
```

The full `authorization_servers` array MUST be emitted (not just the first); the comma-separated env var maps to a JSON array of canonical issuer URLs.

### 3.1 Scope Strategy

`scopes_supported` in the PRM advertises only the **minimum** required scope (`weather:read`). Premium scopes (`weather:premium`) surface through the 403 step-up challenge, per the MCP spec [Scope Selection Strategy](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#scope-selection-strategy).

### 3.2 Resource Field

The `resource` field MUST be the canonical URI of the server per architecture §4.11:

- Lowercase scheme and host
- No trailing slash
- No fragment
- No default port (omit `:443` for https, `:80` for http)
- Percent-encoding normalized per [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) §6

Per [RFC 8707 §2](https://www.rfc-editor.org/rfc/rfc8707.html#section-2) and the MCP spec [Canonical Server URI](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#canonical-server-uri).

Valid examples:
- `https://mcp.example.com`
- `https://mcp.example.com:8443`
- `https://mcp.example.com/server/mcp`

Invalid examples:
- `mcp.example.com` (missing scheme)
- `https://mcp.example.com#fragment` (contains fragment)
- `https://mcp.example.com/` (trailing slash, should be `https://mcp.example.com`)

## 4. Token Validation

### 4.1 Middleware Behavior

On every request to `/mcp`:

1. Extract `Authorization` header. If missing or not `Bearer <token>`:
   - Return `401` with:
     ```
     WWW-Authenticate: Bearer realm="<MCP_AUDIENCE>", resource_metadata="<prm_url>", scope="weather:read"
     ```
   - **Architecture invariant §4.7.**

2. If a token-shaped parameter appears in the URI query string or path, reject with `401` — tokens MUST be presented only in the `Authorization` header. [RFC 6750 §2.3](https://datatracker.ietf.org/doc/html/rfc6750#section-2.3); [OAuth 2.1 §5.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15#section-5.1.1). **Architecture invariant §4.13.**

3. Verify token using `jose.jwtVerify` with a remote JWKS set. The JWKS URL MUST come from the authorization server's RFC 8414 metadata document (NOT a hard-coded `/jwks.json` path). Metadata discovery MUST follow RFC 8414 §3.1 path-insertion rules — i.e., insert `/.well-known/oauth-authorization-server` *before* any path component on `MCP_OIDC_ISSUER_URL`, rather than appending. Use the shared library's `discoverASMetadata` (shared-library §2.5), which implements the cascade.
   - Reject MAC algorithms (`HS*`); accept only `RS256`, `ES256`, `EdDSA` — **architecture invariant §4.3.**
   - Verify signature — **architecture invariant §4.3.**
   - Verify canonical `iss` equals canonical `MCP_OIDC_ISSUER_URL` — **invariant §4.2.**
   - Verify `aud` (string or array per RFC 7519 §4.1.3) contains canonical `MCP_AUDIENCE` — **invariant §4.1.**
   - Verify `exp` is in the future
   - Verify `nbf` is in the past (if present)
   - Allow ±30 s clock skew

4. On any verification failure: return `401` with the `WWW-Authenticate` header from step 1. Log the failure reason (e.g., `aud_mismatch`, `expired`, `bad_signature`) — never log the token value. **Invariant §4.12.**

5. On success: attach parsed claims to request context for downstream scope checks (§5).

### 4.2 JWKS Caching

- JWKS MUST be cached per the authorization server's `Cache-Control: max-age` value.
- If no `Cache-Control` is present, fallback to 3600 seconds (1 hour).
- Cap at 24 hours regardless of what the authorization server sends (defends against a misconfigured server pinning keys indefinitely).
- JWKS MUST NOT be served from cache beyond the effective `max-age`.
- On `kid` cache miss, `jose.createRemoteJWKSet` may refetch (with cooldown) — this supports key rotation without restart.
- The JWKS fetcher MUST be constructed once at startup and reused.

### 4.3 Token Forwarding Prohibition

The MCP server MUST NOT forward access tokens to downstream services. This prevents the [confused deputy problem](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#confused-deputy-problem). If the MCP server needs to call external APIs, it MUST use its own credentials.

## 5. Scope Enforcement

```typescript
function requireScope(claims: TokenClaims, scope: string): void {
  const granted = (claims.scope ?? '').split(' ').filter(Boolean);
  if (!granted.includes(scope)) {
    throw new InsufficientScopeError(scope);
  }
}
```

When `InsufficientScopeError` is thrown, the error handler MUST return:

```
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer realm="<MCP_AUDIENCE>",
  error="insufficient_scope",
  scope="<required_scope>",
  resource_metadata="<prm_url>"
```

Per [RFC 6750 §3.1](https://datatracker.ietf.org/doc/html/rfc6750#section-3.1) and **architecture invariant §4.8**.

The `scope` value in the 403 response SHOULD include both the newly-required scope and any existing granted scopes needed for the operation, to prevent clients from losing previously granted permissions.

## 6. MCP Tools

Tools are registered via `@modelcontextprotocol/sdk` server APIs.

| Tool | Required Scope | Input | Output |
|------|---------------|-------|--------|
| `list_cities` | *(none — any valid token)* | — | Hardcoded list of 3 cities |
| `get_weather` | `weather:read` | `{ city: string }` | Mock current weather |
| `get_premium_forecast` | `weather:premium` | `{ city: string }` | Mock 14-day forecast |

Each tool handler whose row above names a scope MUST call `requireScope(claims, "<scope>")` before executing. Tools whose required scope is *(none)* MUST NOT call `requireScope` — authentication is already enforced by the §4.1 middleware, and calling `requireScope` with an empty/null value is forbidden (the helper's contract requires a concrete scope string).

`get_premium_forecast` intentionally requires a scope NOT advertised in the PRM's `scopes_supported`. This triggers the step-up authorization flow in the client.

## 7. Error Responses

| Condition | Status | WWW-Authenticate |
|-----------|--------|------------------|
| Missing `Authorization` header | 401 | `Bearer realm="<aud>", resource_metadata="...", scope="..."` |
| Invalid / expired / wrong-issuer / wrong-audience / MAC-alg token | 401 | `Bearer realm="<aud>", resource_metadata="...", scope="..."` |
| Token in URI (query or path) | 401 | `Bearer realm="<aud>", resource_metadata="...", scope="..."` |
| Valid token, insufficient scope | 403 | `Bearer realm="<aud>", error="insufficient_scope", scope="...", resource_metadata="..."` |

All 401 and 403 responses MUST include the `resource_metadata` parameter pointing to the PRM URL, per [RFC 9728 §5.1](https://datatracker.ietf.org/doc/html/rfc9728#section-5.1).
