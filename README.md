# MCP Demo

End-to-end demo of the [MCP Authorization profile](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization): OAuth 2.1 with PKCE, Client ID Metadata Documents (CIMD draft-01), and Resource Indicators (RFC 8707).

Three services in one workspace:

| Service             | Role                        | Port  |
| ------------------- | --------------------------- | ----- |
| `mock-customer-idp` | Authorization Server        | 4444  |
| `mcp-server`        | Resource Server (MCP tools) | 3333  |
| `mcp-client`        | Public OAuth client (CLI)   | 7777¹ |

¹ The client boots a short-lived local HTTP server on `127.0.0.1:7777` to host its CIMD doc and capture the OAuth callback. The port is closed as soon as the callback fires.

The specs in [`specs/`](specs/) are the source of truth; start with [`specs/architecture.md`](specs/architecture.md). The 12 implementation prompts that built this repo are in [`prompts/`](prompts/).

---

## Quick start

```bash
pnpm install
cp apps/mock-customer-idp/.env.example apps/mock-customer-idp/.env
cp apps/mcp-server/.env.example apps/mcp-server/.env

pnpm dev        # boots IdP (:4444) + MCP server (:3333) in parallel
```

In a second terminal:

```bash
pnpm dev:client -- --tool get_weather --args '{"city":"Denver"}'
```

A browser tab opens at the IdP's consent screen. Click **Approve**, then the client prints:

```
✓ Discovered MCP server (audience: http://localhost:3333)
✓ Discovered authorization server at http://localhost:4444
✓ Local CIMD server at http://127.0.0.1:7777/client.json
✓ PKCE pair generated (S256)
→ Opening browser to authorize...
✓ Authorization code received
✓ Token issued (aud: http://localhost:3333, scope: weather:read, exp: 4m 59s)
✓ Tool call: get_weather({"city":"Denver"})

Result: {
  "city": "Denver",
  "tempF": 72,
  "conditions": "sunny"
}
```

To skip the browser, set `AS_AUTO_APPROVE=true` in `apps/mock-customer-idp/.env` and pass `--headless` to the client.

---

## What each service exposes

### Authorization server (IdP) on `:4444`

| Endpoint                                      | Purpose                   |
| --------------------------------------------- | ------------------------- |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 AS metadata      |
| `GET /.well-known/openid-configuration`       | OIDC discovery mirror     |
| `GET /jwks.json`                              | JWKS (active signing key) |
| `GET /authorize`                              | Authorization endpoint    |
| `POST /authorize/consent`                     | Consent form handler      |
| `POST /token`                                 | Token endpoint            |
| `GET /healthz`                                | Health check              |

### MCP server (Resource Server) on `:3333`

| Endpoint                                    | Purpose                       |
| ------------------------------------------- | ----------------------------- |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 PRM                  |
| `POST /mcp`                                 | MCP Streamable HTTP transport |
| `GET /healthz`                              | Health check                  |

### Tools

| Tool                   | Required scope      | Notes                                              |
| ---------------------- | ------------------- | -------------------------------------------------- |
| `list_cities`          | _(any valid token)_ | Returns hardcoded city list                        |
| `get_weather`          | `weather:read`      | Mock current weather                               |
| `get_premium_forecast` | `weather:premium`   | 14-day forecast; triggers step-up auth (see below) |

---

## Sample endpoint output

Assuming `pnpm dev` is running:

### AS metadata (RFC 8414)

```bash
curl -s http://localhost:4444/.well-known/oauth-authorization-server | jq
```

```json
{
  "issuer": "http://localhost:4444",
  "authorization_endpoint": "http://localhost:4444/authorize",
  "token_endpoint": "http://localhost:4444/token",
  "jwks_uri": "http://localhost:4444/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"],
  "client_id_metadata_document_supported": true,
  "scopes_supported": ["weather:read", "weather:premium"]
}
```

Note: `token_endpoint_auth_methods_supported: ["none"]` means this authorization server only accepts **public clients** authenticated via PKCE + CIMD. `client_id_metadata_document_supported: true` means clients identify by URL-hosting their own metadata, no Dynamic Client Registration.

### OIDC discovery mirror

Mirrors authorization server metadata plus three OIDC-specific fields. Published only so OIDC-aware discovery clients don't 404 on this path. This PoC does not actually issue ID tokens (OIDC is non-goal per [`architecture.md §6`](specs/architecture.md)).

```bash
curl -s http://localhost:4444/.well-known/openid-configuration | jq
```

```json
{
  "issuer": "http://localhost:4444",
  "authorization_endpoint": "http://localhost:4444/authorize",
  "token_endpoint": "http://localhost:4444/token",
  "jwks_uri": "http://localhost:4444/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"],
  "client_id_metadata_document_supported": true,
  "scopes_supported": ["weather:read", "weather:premium"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "userinfo_endpoint": "http://localhost:4444/userinfo"
}
```

`id_token_signing_alg_values_supported` reflects the active `AS_SIGNING_ALG`; switch to `ES256` or `EdDSA` in `.env` and this field updates.

### JWKS

```bash
curl -s http://localhost:4444/jwks.json | jq
```

```json
{
  "keys": [
    {
      "kty": "RSA",
      "n": "9BpE9yCGLeZTlYRvDckwy_q0x0UYoX08erzZEy_f1BY6_74OSedCktggaI9CZ1HMN5YckLAzoR2Rzj_HuTTEiwGb9QqRumugPgru6wRxx_v1z-gT2XEl5fG2pkjk_2i0b5gmKe_DOKhg8toq4sxDuNUFCm7wObCEo5SQID5VG2AKqBKqOlkl9TYX7cfCuFv-J8A0TOWXrWK9djXesaZhBVi-L1P5law4tLDQkxPsFu3osLcJN8lpkERe9K70QGvQTDRNgWpyEVIJO7epMw6fdah1JV1xFVFOBPCrpkQxTIBBlfdMiLNjZo83tJRTBgowSgNQtafq0WcDb6KufTZPHw",
      "e": "AQAB",
      "kid": "d0543149-e64f-496e-9656-97f2e2cc486d",
      "alg": "RS256",
      "use": "sig"
    }
  ]
}
```

`kid` is generated on first boot and persisted in SQLite; subsequent boots load the same key. The private key never leaves SQLite or the process memory and is redacted from every log line ([`invariant §4.12`](specs/architecture.md)).

### Protected Resource Metadata (RFC 9728)

```bash
curl -s http://localhost:3333/.well-known/oauth-protected-resource | jq
```

```json
{
  "resource": "http://localhost:3333",
  "authorization_servers": ["http://localhost:4444"],
  "scopes_supported": ["weather:read"],
  "bearer_methods_supported": ["header"]
}
```

`scopes_supported` advertises only the **minimum** scope (`weather:read`). The premium scope (`weather:premium`) surfaces only via the 403 `insufficient_scope` step-up challenge (see below).

---

## The 401 challenge

The first thing the client does is probe `/mcp` unauthenticated to learn the `WWW-Authenticate` header:

```bash
curl -s -i -X POST http://localhost:3333/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
       "params":{"protocolVersion":"2024-11-05","capabilities":{},
                 "clientInfo":{"name":"curl","version":"1"}}}' | head
```

```http
HTTP/1.1 401 Unauthorized
content-type: application/json
www-authenticate: Bearer realm="http://localhost:3333", resource_metadata="http://localhost:3333/.well-known/oauth-protected-resource", scope="weather:read"
Content-Length: 25

{"error":"invalid_token"}
```

The `resource_metadata` parameter points clients at the protected resource metadata, that's where `authorization_servers` lives, which kicks off discovery.

---

## Driving the flow with `curl` (no client)

Useful for ad-hoc testing and the interview walkthrough. Get a bearer token from the client, then hit `/mcp` directly:

```bash
TOKEN=$(pnpm print-token | tail -1)

curl -s -X POST http://localhost:3333/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"get_weather","arguments":{"city":"Denver"}}}'
```

```json
{
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"city\":\"Denver\",\"tempF\":72,\"conditions\":\"sunny\"}"
      }
    ]
  },
  "jsonrpc": "2.0",
  "id": 1
}
```

Try `get_premium_forecast` with the same token (which only has `weather:read`):

```bash
curl -s -i -X POST http://localhost:3333/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
       "params":{"name":"get_premium_forecast","arguments":{"city":"Denver"}}}' | head
```

```http
HTTP/1.1 403 Forbidden
www-authenticate: Bearer realm="http://localhost:3333", error="insufficient_scope", scope="weather:premium", resource_metadata="http://localhost:3333/.well-known/oauth-protected-resource"
```

That's the step-up signal. The full `pnpm dev:client` flow handles this automatically; it unions the requested scopes and re-runs the authorize step.

---

## Step-up flow via the client

```bash
pnpm dev:client -- --tool get_premium_forecast --args '{"city":"Denver"}'
```

You'll see one consent prompt (for `weather:read`), then another after the 403 (for `weather:read weather:premium`), then the result:

```
✓ Token issued (aud: http://localhost:3333, scope: weather:read, exp: 4m 59s)
✓ Tool call: get_premium_forecast({"city":"Denver"})
✓ Step-up: re-authorizing with scope="weather:read weather:premium" (attempt 1/2)
...
✓ Token issued (aud: http://localhost:3333, scope: weather:read weather:premium, exp: 4m 59s)
✓ Tool call: get_premium_forecast({"city":"Denver"}) [replay]

Result: {
  "city": "Denver",
  "days": [
    { "day": 1, "tempF": 71, "conditions": "sunny" },
    ...
  ]
}
```

---

## Common commands

| Task                                        | Command                                    |
| ------------------------------------------- | ------------------------------------------ |
| Install                                     | `pnpm install`                             |
| Typecheck                                   | `pnpm typecheck`                           |
| Lint                                        | `pnpm lint`                                |
| Run all tests                               | `pnpm test`                                |
| Run subprocess smoke (opt-in)               | `RUN_SMOKE=1 pnpm test`                    |
| Both servers, parallel                      | `pnpm dev`                                 |
| Just the IdP                                | `pnpm dev:idp`                             |
| Just the MCP server                         | `pnpm dev:mcp`                             |
| Run the client (one-shot)                   | `pnpm dev:client -- --tool ... --args ...` |
| Print a bearer token (for `curl` / scripts) | `pnpm print-token \| tail -1`              |

---

## Project layout

```
apps/
├── mock-customer-idp/      OAuth 2.1 authorization server (SQLite-backed)
├── mcp-server/             MCP resource server with PRM + JWT middleware
└── mcp-client/             public-client CLI

packages/
└── shared/                 canonicalize, PKCE, state, SSRF-safe fetch,
                            JWT verifier, discovery cascade, CIMD validator,
                            WWW-Authenticate helpers, typed error classes

specs/                      authoritative protocol contracts (read these first)
prompts/                    12-slice implementation work orders
test/integration/           cross-app integration + subprocess smoke
```

---

## Tests

```
pnpm test                # 304 tests across all packages + cross-app integration
RUN_SMOKE=1 pnpm test    # also exercise subprocess smoke (spawns IdP + MCP via `pnpm dev:*`)
```

Invariant-tagged tests follow the convention `[INV-4.5]`, e.g.

```bash
pnpm exec vitest run -t 'INV-4\.9'   # CIMD URL validation tests
```

The 15 architectural invariants live in [`specs/architecture.md §4`](specs/architecture.md).

---

## Why no MCP Inspector script?

Inspector's auth path has known regressions ([#826](https://github.com/modelcontextprotocol/inspector/issues/826): Bearer token dropped after OAuth in v0.16.8+) and architectural limits ([#879](https://github.com/modelcontextprotocol/inspector/issues/879): custom headers not honored). It also defaults to Dynamic Client Registration (RFC 7591), which our IdP intentionally does not support; CIMD is the recommended mechanism in the MCP Authorization 2025-11-25 spec and the IdP enforces it.

For the demo:

- **`pnpm dev:client`** drives the full flow including step-up (the headline narrative)
- **`curl`** with a token from `pnpm print-token` exercises the raw JSON-RPC + bearer protocol

Inspector becomes useful again once CIMD support lands in its OAuth client.
