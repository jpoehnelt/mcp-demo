# Step 11 — MCP Tools + `requireScope`

## Spec anchors

- [resource-server.md §5](../specs/resource-server.md) — Scope enforcement
- [resource-server.md §6](../specs/resource-server.md) — MCP tools table
- [resource-server.md §4.3](../specs/resource-server.md) — Token forwarding prohibition
- [architecture.md §4.8](../specs/architecture.md) — Invariant: WWW-Authenticate on 403

## Goal

Wire `@modelcontextprotocol/sdk` to the MCP server, register the three demo tools, enforce per-tool scope via `requireScope`, and emit the correct 403 + `WWW-Authenticate` on insufficient scope.

## Deliverables

- `apps/mcp-server/src/mcp/tools.ts` — tool registrations
- `apps/mcp-server/src/mcp/server.ts` — MCP server setup + transport binding
- `apps/mcp-server/src/middleware/require-scope.ts` — `requireScope` helper + `InsufficientScopeError` handler
- New tests in `apps/mcp-server/src/integration.test.ts`

## Public API (internal)

```ts
// middleware/require-scope.ts
export function requireScope(claims: TokenClaims, scope: string): void;
//   throws InsufficientScopeError when claims.scope doesn't include `scope`

// mcp/server.ts
export function createMCPTransport(app: Hono, deps: {
  env: MCPServerEnv;
  log: Logger;
}): void;
//   registers POST /mcp using the MCP SDK Streamable HTTP transport
```

## Acceptance criteria

### `requireScope` (§5)

```ts
export function requireScope(claims: TokenClaims, scope: string): void {
  const granted = (claims.scope ?? "").split(" ").filter(Boolean);
  if (!granted.includes(scope)) {
    throw new InsufficientScopeError(scope);
  }
}
```

`InsufficientScopeError` already defined in slice 1 with `code: "insufficient_scope"`. The error message MUST include the required scope so the global error handler can build the `WWW-Authenticate` value.

### Global error handler (extend `app.ts` or wherever appropriate)

When any handler throws `InsufficientScopeError`, the app responds:

```
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer realm="<MCP_AUDIENCE>", error="insufficient_scope", scope="<required>", resource_metadata="<prm_url>"
```

Use shared slice 4's `buildInsufficientScopeHeader`. Tag with `[INV-4.8]`.

The `scope` value in the 403 SHOULD include both the newly-required scope and any existing granted scopes the tool needs (per §5). For this PoC with single-scope tools, it's just the missing scope.

### Tools (§6)

| Tool | Required Scope | Input | Output |
|---|---|---|---|
| `list_cities` | *(none — any valid token)* | — | Hardcoded list of 3 cities, e.g. `["Denver", "Seattle", "Austin"]` |
| `get_weather` | `weather:read` | `{ city: string }` | Mock weather, e.g. `{ city, tempF: 72, conditions: "sunny" }` |
| `get_premium_forecast` | `weather:premium` | `{ city: string }` | Mock 14-day forecast |

Implementation rules:

- Each tool registered via the MCP SDK.
- Tools whose row names a scope MUST call `requireScope(claims, "<scope>")` before executing.
- `list_cities` MUST NOT call `requireScope` — authentication is already enforced by the JWT middleware (slice 10), and `requireScope` requires a concrete scope string.
- Claims are read from request context (`c.get("claims")` — set by slice 10's middleware).
- `get_premium_forecast` deliberately requires a scope NOT advertised in PRM `scopes_supported` — this triggers the client step-up flow (slice 12).
- **Token forwarding prohibition** (§4.3): no tool calls outbound to other services with the user's token. Tool outputs are computed locally.

### Tool input validation

Use zod schemas on the tool input. Invalid input → MCP-level error (the SDK handles this; just provide the schema).

### `createMCPTransport`

Wire the MCP SDK's `StreamableHTTPServerTransport` (or equivalent in the current SDK) to `POST /mcp`. Pass `claims` from request context into the tool handlers via SDK request context.

## Integration tests

```ts
describe("MCP tools", () => {
  it("list_cities works with any valid token", async () => {
    const token = await mintTestToken({ scope: "" });  // no scope
    const res = await callTool(app, "list_cities", {}, token);
    expect(res.status).toBe(200);
    // assert MCP response shape
  });

  it("get_weather works with weather:read", async () => {
    const token = await mintTestToken({ scope: "weather:read" });
    const res = await callTool(app, "get_weather", { city: "Denver" }, token);
    expect(res.status).toBe(200);
  });

  it("[INV-4.8] get_premium_forecast without weather:premium → 403 + WWW-Authenticate", async () => {
    const token = await mintTestToken({ scope: "weather:read" });
    const res = await callTool(app, "get_premium_forecast", { city: "Denver" }, token);
    expect(res.status).toBe(403);
    const h = res.headers.get("WWW-Authenticate");
    expect(h).toContain('error="insufficient_scope"');
    expect(h).toContain('scope="weather:premium"');
    expect(h).toContain("resource_metadata=");
  });

  it("get_premium_forecast works with weather:premium", async () => {
    const token = await mintTestToken({ scope: "weather:read weather:premium" });
    const res = await callTool(app, "get_premium_forecast", { city: "Denver" }, token);
    expect(res.status).toBe(200);
  });

  it("get_weather with invalid input → MCP-level validation error", async () => {
    const token = await mintTestToken({ scope: "weather:read" });
    const res = await callTool(app, "get_weather", { city: 123 }, token);
    // assert MCP error shape (not a 5xx)
  });
});
```

`mintTestToken` is a helper that uses the in-process IdP from slice 6+ to issue a real JWT bound to the test MCP server's audience.

`callTool` is a helper that POSTs the appropriate MCP JSON-RPC envelope to `/mcp` with the bearer token. Use the MCP SDK's client transport in-process if convenient, or hand-craft the JSON-RPC body.

## Out of scope

- Client-side step-up flow (slice 12 — handles the 403 → re-authorize → retry loop).
- Refresh-token redemption.
- Persistent tool state (everything mock).

## Verification

```bash
test -f apps/mcp-server/src/mcp/tools.ts
test -f apps/mcp-server/src/mcp/server.ts
test -f apps/mcp-server/src/middleware/require-scope.ts

pnpm typecheck
pnpm lint
pnpm test

pnpm exec vitest run -t '[INV-4.8]' --reporter=verbose

# Independent AI review — address findings before commit
cr review --agent --type uncommitted -c CLAUDE.md -c specs/resource-server.md
```

All gate commands must exit 0. CodeRabbit findings: address or explicitly acknowledge.

Smoke (optional, with `pnpm dev` running):

```bash
# Need a token first — manual flow via the IdP (or wait for slice 12's client).
TOKEN=...
curl -s -X POST http://localhost:3333/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{"city":"Denver"}}}' \
  | jq .
```
