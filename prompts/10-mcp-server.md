# Step 10 — MCP Server: Env, PRM, JWT Middleware

## Spec anchors

- [resource-server.md §1](../specs/resource-server.md) — Endpoints
- [resource-server.md §2](../specs/resource-server.md) — Configuration
- [resource-server.md §3](../specs/resource-server.md) — Protected Resource Metadata
- [resource-server.md §4](../specs/resource-server.md) — Token validation
- [architecture.md §4.1](../specs/architecture.md), [§4.2](../specs/architecture.md), [§4.3](../specs/architecture.md), [§4.6](../specs/architecture.md), [§4.7](../specs/architecture.md), [§4.11](../specs/architecture.md), [§4.13](../specs/architecture.md) — Relevant invariants
- [apps/mcp-server/.env.example](../apps/mcp-server/.env.example) — canonical env var list

## Goal

Stand up the MCP server with env validation, the PRM endpoint, the JWT verification middleware (using shared slice 5's `createJWTVerifier` + `discoverASMetadata`), and a `/healthz`. Tools come in slice 11.

## Deliverables

- `apps/mcp-server/src/index.ts` — boot sequence
- `apps/mcp-server/src/env.ts` — zod schema for `MCP_*` vars
- `apps/mcp-server/src/log.ts` — pino with redaction (same secret list as the IdP)
- `apps/mcp-server/src/app.ts` — Hono app factory
- `apps/mcp-server/src/routes/healthz.ts`
- `apps/mcp-server/src/routes/prm.ts` — Protected Resource Metadata endpoint
- `apps/mcp-server/src/middleware/auth.ts` — JWT verify middleware + WWW-Authenticate emission
- `apps/mcp-server/src/integration.test.ts`

## Public API (internal)

```ts
// app.ts
export function createMCPServerApp(deps: {
  env: MCPServerEnv;
  log: Logger;
}): Promise<Hono>;  // async because of JWKS discovery on construction

// env.ts
export interface MCPServerEnv {
  MCP_OIDC_ISSUER_URL: CanonicalURI;
  MCP_AUDIENCE: CanonicalURI;
  MCP_PRM_AUTH_SERVERS: CanonicalURI[];
  MCP_PORT: number;
}
export function parseEnv(raw: Record<string, string | undefined>): MCPServerEnv;

// middleware/auth.ts
export function createAuthMiddleware(deps: {
  env: MCPServerEnv;
  verifier: ReturnType<typeof createJWTVerifier>;
  log: Logger;
}): MiddlewareHandler;
```

## Acceptance criteria

### Boot sequence (in `index.ts`)

1. `parseEnv(process.env)` — all three identity vars required. Invalid → log + exit 1.
2. Discover the authorization server's metadata via shared slice 5's `discoverASMetadata(env.MCP_OIDC_ISSUER_URL)`. Cache for the process lifetime; if discovery fails at boot, fail-fast with a clear log line. (Do NOT bootstrap with a half-configured server.)
3. Construct the JWT verifier via shared `createJWTVerifier({ issuer: env.MCP_OIDC_ISSUER_URL, audience: env.MCP_AUDIENCE })`.
4. Create the Hono app via `createMCPServerApp({ env, log })` — this wires the routes and middleware.
5. `serve` via `@hono/node-server` on `MCP_PORT`.
6. Log a single startup line and graceful shutdown on SIGINT/SIGTERM.

### Env validation (§2)

- `MCP_OIDC_ISSUER_URL`, `MCP_AUDIENCE`, `MCP_PRM_AUTH_SERVERS`: all required, all canonicalized via slice 1's `canonicalize`.
- `MCP_PRM_AUTH_SERVERS` is a comma-separated list → array. Each entry canonicalizes independently.
- `MCP_PORT`: `z.coerce.number().int().positive()`, default 3333.

### `GET /.well-known/oauth-protected-resource` (§3)

Response (`Content-Type: application/json`, `Cache-Control: max-age=3600`):

```json
{
  "resource": "<canonical MCP_AUDIENCE>",
  "authorization_servers": ["<each canonical MCP_PRM_AUTH_SERVERS entry, in order>"],
  "scopes_supported": ["weather:read"],
  "bearer_methods_supported": ["header"]
}
```

`scopes_supported` advertises only the minimum scope (`weather:read`); the premium scope surfaces only through the 403 step-up challenge per §3.1.

### JWT middleware (§4.1)

Apply on every `/mcp` request (NOT `/healthz`, NOT PRM):

1. Extract `Authorization`. Missing/non-`Bearer` → 401 with `WWW-Authenticate: Bearer realm="<MCP_AUDIENCE>", resource_metadata="<prm_url>", scope="weather:read"`. Use shared slice 4's `buildUnauthorizedHeader`.
2. If a token-shaped parameter appears in URL query/path, reject with 401 — invariant §4.13. (Implement: any query/path component matching `eyJ` JWT prefix triggers rejection. Simple regex is fine.)
3. Verify token via the JWT verifier (slice 5). On failure, return 401 with the same `WWW-Authenticate`. Log failure reason (`aud_mismatch`, `expired`, `bad_signature`) — never the token value.
4. On success: attach parsed claims to request context (`c.set("claims", claims)`).

`prm_url` is constructed as `${MCP_AUDIENCE}/.well-known/oauth-protected-resource` (since `MCP_AUDIENCE` has empty path in the PoC).

### Logging redaction

Same redaction list pattern as the IdP (slice 6's `log.ts`). Secrets: `authorization`, `cookie`, `access_token`, `token`. Per invariant §4.12.

### Integration tests

```ts
describe("MCP server", () => {
  let app: Hono;

  beforeAll(async () => {
    // 1. Boot an in-process IdP (from slice 6+) so JWKS is reachable.
    // 2. Boot the MCP server pointed at the IdP.
  });

  it("/healthz returns 200", async () => { /* ... */ });

  it("PRM returns resource + authorization_servers + scopes_supported", async () => {
    const res = await app.request("/.well-known/oauth-protected-resource");
    const body = await res.json();
    expect(body.resource).toBe("http://localhost:3333");
    expect(body.authorization_servers).toEqual(["http://localhost:4444"]);
    expect(body.scopes_supported).toEqual(["weather:read"]);
  });

  it("[INV-4.7] /mcp without auth → 401 + WWW-Authenticate", async () => {
    const res = await app.request("/mcp", { method: "POST" });
    expect(res.status).toBe(401);
    const h = res.headers.get("WWW-Authenticate");
    expect(h).toContain("Bearer");
    expect(h).toContain("resource_metadata=");
    expect(h).toContain('scope="weather:read"');
  });

  it("[INV-4.1] /mcp with token wrong-aud → 401", async () => {
    // mint a JWT via the in-process IdP with resource=http://other.example.com
    /* ... */
  });

  it("[INV-4.3] /mcp with HS256 token → 401", async () => {
    // hand-forge HS256 JWT signed with the public key as the HMAC secret
    /* ... */
  });

  it("[INV-4.13] /mcp with token in query string → 401", async () => {
    const res = await app.request("/mcp?access_token=eyJhbGciOiJSUzI1NiI.fake.fake");
    expect(res.status).toBe(401);
  });
});
```

## Out of scope

- MCP tools registration via `@modelcontextprotocol/sdk` (slice 11).
- `requireScope` enforcement (slice 11).
- The actual `POST /mcp` handler — for this slice, `/mcp` can be a stub that returns 200 with `{ ok: true }` once the middleware passes. Slice 11 wires the real MCP transport.

## Verification

```bash
test -f apps/mcp-server/src/index.ts
test -f apps/mcp-server/src/env.ts
test -f apps/mcp-server/src/log.ts
test -f apps/mcp-server/src/app.ts
test -f apps/mcp-server/src/routes/healthz.ts
test -f apps/mcp-server/src/routes/prm.ts
test -f apps/mcp-server/src/middleware/auth.ts
test -f apps/mcp-server/src/integration.test.ts

pnpm typecheck
pnpm lint
pnpm test

pnpm exec vitest run -t '[INV-4.1]' --reporter=verbose
pnpm exec vitest run -t '[INV-4.7]' --reporter=verbose
pnpm exec vitest run -t '[INV-4.13]' --reporter=verbose

# Independent AI review — address findings before commit
cr review --agent --type uncommitted -c CLAUDE.md -c specs/resource-server.md
```

All gate commands must exit 0. CodeRabbit findings: address or explicitly acknowledge.
