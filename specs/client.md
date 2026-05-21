# Client Specification (MCP Client CLI)

The MCP client is a single-command CLI that performs full OAuth 2.1 discovery, CIMD self-registration, PKCE-protected authorization, and authenticated MCP tool calls. It implements [step-up authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#step-up-authorization-flow) on insufficient scope.

## 1. CLI Interface

```
mcp-client connect [options]
  --server <url>           MCP server URL (default: http://localhost:3333)
  --tool <name>            Tool to call (default: get_weather)
  --args <json>            Tool arguments (default: '{"city":"Denver"}')
  --scope <scopes>         Initial scope request (default: derived from 401 challenge)
  --cimd-port <n>          Port for local CIMD/callback server (default: 7777)
  --auto-open              Open browser automatically (default: true unless CI)
  --headless               Auto-approve consent via direct HTTP (for CI demo)
  --verbose                Print full handshake timeline
```

## 2. Local CIMD Server

The client boots an HTTP server on `127.0.0.1:<cimd-port>` with two routes:

| Route              | Purpose                                             |
| ------------------ | --------------------------------------------------- |
| `GET /client.json` | Serves the runtime-generated CIMD document          |
| `GET /callback`    | OAuth redirect handler; captures `code` and `state` |

### 2.1 CIMD Document

```json
{
  "client_id": "http://127.0.0.1:<port>/client.json",
  "client_name": "MCP Demo Client",
  "client_uri": "https://github.com/<owner>/mcp-demo",
  "redirect_uris": ["http://127.0.0.1:<port>/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

Requirements per [CIMD draft-01](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-01):

- `client_id` MUST canonically equal (architecture §4.11) the URL the document is served at
- `client_id` URL MUST contain a non-empty path component (e.g., `/client.json`); bare-domain URLs MUST be rejected
- MUST include at minimum: `client_id`, `client_name`, `redirect_uris`
- The document MUST be regenerated at startup (the ephemeral port changes between runs)
- The local server MUST bind to `127.0.0.1` literally (not `localhost`) so the authorization server's SSRF check has a deterministic IP to match

## 3. Authorization Flow

### 3.1 Discovery

```
┌──────────┐                    ┌────────────┐                    ┌──────┐
│  Client  │                    │ MCP Server │                    │ IdP  │
└─────┬────┘                    └──────┬─────┘                    └──┬───┘
      │  POST /mcp (no auth)           │                              │
      │───────────────────────────────▶│                              │
      │  401 + WWW-Authenticate        │                              │
      │◀───────────────────────────────│                              │
      │                                │                              │
      │  GET /.well-known/             │                              │
      │    oauth-protected-resource    │                              │
      │───────────────────────────────▶│                              │
      │  PRM (authorization_servers)   │                              │
      │◀───────────────────────────────│                              │
      │                                │                              │
      │  GET /.well-known/oauth-authorization-server                  │
      │──────────────────────────────────────────────────────────────▶│
      │  Authorization server metadata (or fallback to OIDC)          │
      │◀──────────────────────────────────────────────────────────────│
```

Detailed steps:

1. Boot local CIMD + callback server.
2. POST unauthenticated MCP `initialize` request to `<server>/mcp`. Expect `401`.
3. Parse `WWW-Authenticate` header. Extract `resource_metadata` URL and `scope`.
4. Fetch PRM from `resource_metadata` URL. Read the canonical `resource` field. If `authorization_servers` has multiple entries, select the first.
5. Run the authorization server metadata discovery cascade ([MCP spec §Authorization Server Metadata Discovery](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#authorization-server-metadata-discovery)):
   1. `{issuer}/.well-known/oauth-authorization-server` (with path insertion per RFC 8414 §3.1)
   2. `{issuer}/.well-known/openid-configuration` (with path insertion)
   3. `{issuer}/.well-known/openid-configuration` (path appending, OIDC compat)
6. Validate authorization server metadata:
   - `code_challenge_methods_supported` MUST include `S256`. Hard-fail otherwise. Per [MCP spec §Authorization Code Protection](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#authorization-code-protection).
   - Check `client_id_metadata_document_supported` — if `false` or absent, warn but proceed (the server may still accept CIMD URLs).

### 3.2 Authorization Request

Generate:

- PKCE pair: 43-128 char verifier, challenge = `base64url(SHA-256(ASCII(verifier)))` with no padding. [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636).
- `state`: random 32 bytes, base64url-encoded.

Build authorize URL with:

| Parameter               | Value                                                   |
| ----------------------- | ------------------------------------------------------- |
| `client_id`             | Local CIMD URL (`http://127.0.0.1:<port>/client.json`)  |
| `response_type`         | `code`                                                  |
| `redirect_uri`          | `http://127.0.0.1:<port>/callback`                      |
| `scope`                 | From 401 `WWW-Authenticate`, or `weather:read` fallback |
| `resource`              | Canonical URI from PRM `resource` field                 |
| `code_challenge`        | PKCE challenge                                          |
| `code_challenge_method` | `S256`                                                  |
| `state`                 | Random                                                  |

Open in browser (or headless mode for CI).

### 3.3 Callback and Token Exchange

1. Wait for callback at `/callback`.
   - First, check for an `error` query parameter — the authorization server redirects here on user denial or any authorize-time failure per [OAuth 2.1 §4.1.2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15#section-4.1.2.1). If present, validate `state` matches, then exit with a human-readable message derived from `error` and `error_description` (e.g., `access_denied` → "User denied consent"). Do NOT proceed to the token endpoint.
   - Otherwise, validate `state` matches the value sent (constant-time compare) and require `code` to be present. Reject the callback if `state` is missing or mismatches — **architecture invariant §4.14**.
2. POST to token endpoint with `Content-Type: application/x-www-form-urlencoded`:

| Parameter       | Value                                                                                                           |
| --------------- | --------------------------------------------------------------------------------------------------------------- |
| `grant_type`    | `authorization_code`                                                                                            |
| `code`          | From callback                                                                                                   |
| `client_id`     | CIMD URL                                                                                                        |
| `redirect_uri`  | Callback URL                                                                                                    |
| `code_verifier` | PKCE verifier                                                                                                   |
| `resource`      | Same as authorization request — **MUST be on both** per [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) |

3. Receive token response. Decode for display only when `--verbose`. The client MUST NOT base any authorization decision on decoded claims — verification is the resource server's responsibility (**architecture invariant §4.3**).

### 3.4 Tool Invocation

POST to `<server>/mcp` with `Authorization: Bearer <token>`.

- If `200`: pretty-print result, exit 0.
- If `403` with `error="insufficient_scope"`: initiate step-up (§3.5).
- Other errors: print diagnostics, exit nonzero.

### 3.5 Step-Up Authorization

Per [MCP spec §Step-Up Authorization Flow](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#step-up-authorization-flow):

1. Parse `scope` from 403 `WWW-Authenticate` header.
2. Loop back to §3.2 with `scope = union(previously_granted, newly_required)` — never narrow the set, or the next tool call may regress to a 403 for a different missing scope.
3. After the stepped-up token is issued (§3.3 completes), the client MUST automatically re-invoke the original `POST /mcp` tool call from §3.4 with the new bearer token. The user's intent (the original `--tool`/`--args` invocation) is what triggered the flow; step-up is a transparent re-authorization, not a new operation.
4. Cap at 2 retries; treat further 403s as permanent authorization failure (the user denied consent or the scope simply does not exist).

### 3.6 Scope Selection Strategy

Per [MCP spec §Scope Selection Strategy](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#scope-selection-strategy):

1. Use `scope` parameter from the initial 401 `WWW-Authenticate` header, if provided.
2. If `scope` is absent, use all scopes from PRM `scopes_supported`.
3. If `scopes_supported` is undefined, omit the `scope` parameter entirely.

## 4. Security Requirements

- PKCE verifier MUST be 43–128 characters from the unreserved set. [RFC 7636 §4.1](https://datatracker.ietf.org/doc/html/rfc7636#section-4.1).
- PKCE challenge MUST use S256 (not `plain`). [RFC 7636 §4.2](https://datatracker.ietf.org/doc/html/rfc7636#section-4.2).
- `state` MUST be ≥128 bits entropy (the PoC generates 256) and MUST be constant-time-compared on callback — **architecture invariant §4.14**.
- `resource` parameter MUST be sent on BOTH authorization AND token requests; exactly one value per request — **architecture invariant §4.5**.
- Tokens MUST be sent via `Authorization: Bearer` header, never as a query parameter or path component — **architecture invariant §4.13**.
- Tokens, codes, and `code_verifier` MUST NOT be logged at any level — **architecture invariant §4.12**.
- Tokens MUST NOT be decoded for security/authorization decisions on the client; only for human display (`--verbose`). The client treats access tokens as opaque even though they happen to be JWTs.
- On the callback request, the server MUST capture the code (or `error`), send a successful HTTP response to the browser, and then exit (or unbind the port). The listener MUST NOT remain open across the rest of the flow — this minimizes the window in which a stale listener on a well-known port could capture a subsequent unrelated authorization redirect or be hijacked by another local process.

## 5. CLI Output

```
✓ Local CIMD server at http://127.0.0.1:7777/client.json
✓ Discovered MCP server (audience: http://localhost:3333)
✓ Discovered authorization server at http://localhost:4444
✓ PKCE pair generated (S256)
→ Opening browser to authorize...
✓ Authorization code received
✓ Token issued (aud: http://localhost:3333, scope: weather:read, exp: 4m 59s)
✓ Tool call: get_weather({"city":"Denver"})

Result: 72°F and sunny
```
