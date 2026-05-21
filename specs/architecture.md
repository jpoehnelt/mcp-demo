# System Architecture

## 1. Roles

This system comprises three services per the [MCP Authorization spec (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization):

| Role                 | Service             | Standards                                              |
| -------------------- | ------------------- | ------------------------------------------------------ |
| Authorization Server | `mock-customer-idp` | OAuth 2.1, RFC 8414, OIDC Discovery 1.0, CIMD draft-01 |
| Resource Server      | `mcp-server`        | RFC 9728, RFC 8707, RFC 6750                           |
| Client               | `mcp-client`        | OAuth 2.1, RFC 7636, RFC 8707, CIMD draft-01           |

## 2. Trust Boundaries

```
┌─────────────┐          ┌──────────────────┐
│ mcp-client  │──authz──▶│ mock-customer-idp│
│  (public    │◀─token───│ (Authorization   │
│   client)   │          │  Server)         │
└──────┬──────┘          └────────┬─────────┘
       │                          │
       │ Bearer token             │ JWKS (public keys)
       │                          │
       ▼                          ▼
┌──────────────────────────────────────────┐
│              mcp-server                  │
│          (Resource Server)               │
│                                          │
│  Identity config (see §2.1):             │
│    • MCP_OIDC_ISSUER_URL                 │
│    • MCP_AUDIENCE                        │
│    • MCP_PRM_AUTH_SERVERS                │
│                                          │
│  Zero imports from mock-customer-idp     │
│  (user-agent leg omitted from diagram)   │
└──────────────────────────────────────────┘
```

### 2.1 IdP-Agnostic MCP Server (BYOC Contract)

The MCP server MUST be completely decoupled from the authorization server implementation. Identity configuration (the BYOC contract):

| Env Var                | Purpose                                                                                                   |
| ---------------------- | --------------------------------------------------------------------------------------------------------- |
| `MCP_OIDC_ISSUER_URL`  | Trusted issuer; used to fetch JWKS and to compare against the token `iss` claim                           |
| `MCP_AUDIENCE`         | Server's canonical URI (per §4.11); validates token `aud` claim AND populates the PRM `resource` field    |
| `MCP_PRM_AUTH_SERVERS` | Comma-separated authorization server issuer URLs published in the PRM `authorization_servers` array; each MUST canonicalize |

Deployment-only (not identity):

| Env Var    | Purpose                     |
| ---------- | --------------------------- |
| `MCP_PORT` | Listen port (default: 3333) |

Switching to a real IdP (Okta/Entra/Keycloak) MUST require only changes to the three identity env vars above — no code changes, no rebuild.

### 2.2 Client as Public OAuth Client

The client is a public OAuth 2.1 client (no client secret) that self-hosts its CIMD document and uses PKCE (S256) for authorization code protection.

Public-client integrity at the token endpoint is established by the composition of three checks (no shared secret needed):

1. **CIMD `client_id` equals fetch URL** (invariant §4.9) — anchors the client identity to a URL the authorization server can re-fetch.
2. **`redirect_uri` exact match against the CIMD's `redirect_uris`** (invariant §4.10) — prevents code redirection to attacker-controlled URLs.
3. **PKCE S256 binding** (invariant §4.4) — the token request MUST present a `code_verifier` whose SHA-256 matches the `code_challenge` recorded at authorize time.

The client hosts its CIMD document on an ephemeral local HTTP server bound to `127.0.0.1` during the flow; the URL is what the client sends as `client_id`.

## 3. Standards Compliance

### 3.1 Required Standards

Links below point at the datatracker landing page so they track the latest revision automatically. Pinned draft revisions: OAuth 2.1 `draft-15`, CIMD `draft-01`.

| Standard                                                                                                       | Usage                                                                                                                     |
| -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| [MCP Authorization (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) | Profile that elevates several RFC `SHOULD`s to `MUST` (resource param, PRM path)                                          |
| [OAuth 2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)                                           | Core authorization framework                                                                                              |
| [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)                                                      | JSON Web Token (claim semantics for `aud`, `iss`, `exp`, `jti`)                                                           |
| [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)                                                      | JSON Web Key / JWKS (key publication format)                                                                              |
| [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414)                                                      | Authorization Server Metadata (primary discovery mechanism)                                                               |
| [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728)                                                      | Protected Resource Metadata                                                                                               |
| [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html)                                                        | Resource Indicators (`resource` parameter, audience binding)                                                              |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)                                                      | PKCE                                                                                                                      |
| [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750)                                                      | Bearer Token Usage (error responses, transport rules)                                                                     |
| [CIMD](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)                         | Client ID Metadata Documents                                                                                              |
| [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)                               | Optional IdP-side mirror at `/.well-known/openid-configuration` for OIDC-aware clients; the client MUST try RFC 8414 first |

### 3.2 Token Format

Access tokens are **JWTs** (RFC 7519) signed with an asymmetric algorithm. The authorization server publishes its signing key at `/jwks.json` and includes `kid` in every JWT header so the MCP server can pick the right key without a roundtrip per request.

| Item            | Requirement                                                    |
| --------------- | -------------------------------------------------------------- |
| Token type      | JWT (no opaque or reference tokens)                            |
| Signing alg     | `RS256` (default); `ES256` and `EdDSA` MAY be enabled          |
| MAC alg         | Forbidden (`HS*`); enforced by invariant §4.3                  |
| JWKS cache      | Honor authorization server `Cache-Control: max-age`; fallback 1 hour if absent |
| Required claims | `iss`, `aud`, `sub`, `exp`, `iat`, `jti`, `client_id`, `scope` |
| `aud`           | String OR array containing the canonical `MCP_AUDIENCE`        |

Refresh tokens are opaque (32 random bytes, stored as SHA-256 hash) and bound to `client_id`, `resource`, `scope`, and `sub`. They MUST be rotated on every use (OAuth 2.1 §6.1).

## 4. Invariants

These properties MUST hold at all times. Each MUST be covered by a named test in the invariant test suite; the test name MUST cite the invariant number so a regression points at the spec requirement.

1. **Audience binding.** MCP server MUST reject any token whose `aud` claim (string or array of strings per RFC 7519 §4.1.3) does not contain the canonical `MCP_AUDIENCE`. Comparison uses canonical form per §4.11. [RFC 8707 §2](https://www.rfc-editor.org/rfc/rfc8707.html#section-2); [MCP Authz §Audience](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).
2. **Issuer binding.** MCP server MUST reject any token whose `iss` ≠ canonical `MCP_OIDC_ISSUER_URL`. [OIDC Core §2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).
3. **Signature verification.** Tokens MUST be verified via JWKS fetched from the authorization server's discovery metadata. No `jwt.decode` without `jwt.verify`. MAC algorithms (`HS256`/`HS384`/`HS512`) MUST be rejected — only asymmetric `RS256`/`ES256`/`EdDSA` are accepted (prevents alg-confusion attacks).
4. **PKCE S256 required.** Authorization server metadata MUST advertise `code_challenge_methods_supported: ["S256"]` (no `plain`). Token endpoint MUST reject any authorization-code exchange whose `code_verifier` does not satisfy `base64url(SHA-256(verifier)) == code_challenge`.
5. **Resource parameter required.** The authorize endpoint and the `authorization_code` grant at the token endpoint MUST require exactly one `resource` parameter per request (MCP-profile stricter than RFC 8707, which permits multiple). Token `aud` is set to the canonical form of that `resource`. On the `refresh_token` grant the parameter is optional (RFC 8707 §2.1 SHOULD); when present it MUST canonically byte-equal the value bound to the refresh token, and when absent the stored value is used — no other behavior is permitted.
6. **PRM well-known path.** MCP server MUST serve PRM at `/.well-known/oauth-protected-resource`. Not `/.well-known/mcp-authorization`. [RFC 9728 §3](https://datatracker.ietf.org/doc/html/rfc9728#section-3).
7. **WWW-Authenticate on 401.** Missing or invalid tokens → `401` + `WWW-Authenticate: Bearer realm="<resource>", resource_metadata="<prm_url>", scope="<scopes>"`. [RFC 6750 §3](https://datatracker.ietf.org/doc/html/rfc6750#section-3).
8. **WWW-Authenticate on 403.** Insufficient scope → `403` + `WWW-Authenticate: Bearer realm="<resource>", error="insufficient_scope", scope="<required>", resource_metadata="<prm_url>"`. [RFC 6750 §3.1](https://datatracker.ietf.org/doc/html/rfc6750#section-3.1).
9. **CIMD URL validation.** The authorization server MUST reject a CIMD whose `client_id` field, after canonicalization per §4.11, ≠ the URL it was fetched from. It MUST reject CIMDs fetched from private, loopback, link-local, ULA, multicast, or broadcast addresses (see authz-server spec §4.3 for the explicit address-family list) unless `AS_DEV_ALLOW_INSECURE_CIMD=true`.
10. **Redirect URI exact match.** The authorization server MUST reject any `redirect_uri` not present in the resolved CIMD's `redirect_uris` array (byte-for-byte equality after canonicalization).
11. **Canonical URI handling.** Lowercase scheme and host, no trailing slash, no fragment, no default port, percent-encoding normalized per [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) §6. Applies on input (env vars `MCP_AUDIENCE`, `MCP_OIDC_ISSUER_URL`, `MCP_PRM_AUTH_SERVERS`; fetched CIMD URLs) AND on output (token `aud`, token `iss` compare, PRM `resource`, PRM `authorization_servers`).

    *Bare-domain consequence (intentional defense-in-depth):* a URL whose path is empty or `/` canonicalizes to an empty path. CIMD `client_id` URLs are required to have a non-empty path component (see shared-library spec §2.6), so a bare domain like `https://example.com/` can never serve as a valid CIMD identifier. This prevents an attacker who controls a domain root but not a specific path from impersonating a registered client.
12. **No secret logging.** Bearer tokens, authorization codes, `code_verifier`, refresh tokens, private keys, and `Authorization`/`Cookie` header values MUST never appear in logs at any level. Enforced via pino redaction.
13. **Token never in URI.** Access tokens MUST NOT appear in the URI query string or path component on any request. Bearer tokens are transmitted only in the `Authorization` header. [RFC 6750 §2.3](https://datatracker.ietf.org/doc/html/rfc6750#section-2.3); reinforced by [OAuth 2.1 §5.1.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/).
14. **CSRF defense on authorize.** Client MUST send a cryptographically random `state` parameter (≥128 bits entropy) on every authorization request and MUST verify it on the callback before exchanging the code. [OAuth 2.1 §4.1.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/).
15. **Refresh token rotation.** The authorization server MUST issue a new refresh token on every refresh exchange, invalidate the old one, and detect reuse of an invalidated refresh token — on reuse, revoke the entire token family. [OAuth 2.1 §6.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/).

## 5. Technology Stack

Floors below are minimums; `package.json` is the source of truth for installed ranges.

| Concern         | Choice                                                                                                        |
| --------------- | ------------------------------------------------------------------------------------------------------------- |
| Runtime         | Node.js 22+ (LTS); 24 LTS is current as of 2026-05                                                            |
| Language        | TypeScript 5.6+ (strict mode, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitOverride`) |
| Package manager | pnpm 10+                                                                                                      |
| HTTP framework  | Hono 4.x                                                                                                      |
| JWT/JWK/JWKS    | jose 6.x                                                                                                      |
| Validation      | zod 4.x (note: 4.x has breaking changes from 3.x)                                                             |
| IdP persistence | better-sqlite3 12.x                                                                                           |
| Logging         | pino 10.x (with redaction)                                                                                    |
| Testing         | vitest 4.x                                                                                                    |
| MCP SDK         | `@modelcontextprotocol/sdk` 1.29+                                                                             |
| Lint/Format     | Biome 2.x                                                                                                     |

## 6. Non-Goals

Explicit non-goals to bound scope. Each may be valuable in a production deployment but is **out of scope** for this PoC:

- **Dynamic Client Registration (RFC 7591).** This system uses CIMD only; the two mechanisms are distinct and MUST NOT be conflated.
- **DPoP / sender-constrained tokens (RFC 9449).** Tokens are plain bearer per RFC 6750; theft is mitigated by short TTL + audience binding + HTTPS-only transport.
- **mTLS client authentication (RFC 8705).** Public client only.
- **Token introspection (RFC 7662)** and **revocation (RFC 7009)** endpoints. Tokens expire naturally; refresh-token reuse detection (§4.15) covers the most common revocation case.
- **Opaque or reference access tokens.** Tokens are JWTs — see §3.2.
- **Multi-tenant authorization server.** One issuer, one signing key family.
- **Production-grade user authentication.** The mock IdP serves a single hard-coded user; real BYOC deployments delegate auth.
- **Token binding to TLS exporter (RFC 8473).** Not widely supported.
