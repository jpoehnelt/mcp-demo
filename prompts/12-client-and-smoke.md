# Step 12 — MCP Client + Step-Up + Smoke Tests

## Spec anchors

- [client.md §1](../specs/client.md) — CLI interface
- [client.md §2](../specs/client.md) — Local CIMD server
- [client.md §3](../specs/client.md) — Authorization flow (all subsections)
- [client.md §4](../specs/client.md) — Security requirements
- [architecture.md §4.13](../specs/architecture.md), [§4.14](../specs/architecture.md) — Relevant invariants

## Goal

Close the loop. Implement the MCP client CLI: discovery → local CIMD self-host → authorize → callback → token exchange → tool call → step-up on 403. Add cross-app integration tests and a subprocess smoke test that exercises the full demo.

## Deliverables

### Client implementation

- `apps/mcp-client/src/index.ts` — commander CLI entry
- `apps/mcp-client/src/cli.ts` — argument parsing + default values
- `apps/mcp-client/src/cimd-server.ts` — local `127.0.0.1:<port>` HTTP server (CIMD doc + callback route)
- `apps/mcp-client/src/discovery.ts` — PRM fetch → AS metadata cascade (via shared)
- `apps/mcp-client/src/authorize.ts` — build authorize URL, open browser, await callback
- `apps/mcp-client/src/token.ts` — POST `/token`, parse response
- `apps/mcp-client/src/mcp-call.ts` — invoke an MCP tool via the SDK client transport
- `apps/mcp-client/src/flow.ts` — orchestrates the full sequence including step-up
- `apps/mcp-client/src/log.ts` — pino with redaction
- `apps/mcp-client/src/integration.test.ts` — in-process tests for the local CIMD server + callback handler

### Cross-app integration

- `test/integration/auth-flow.test.ts` — boots IdP + MCP server in-process, drives the client's flow functions, asserts end-to-end success
- `test/integration/smoke.test.ts` — spawns IdP + MCP server as actual subprocesses, runs the client subprocess, asserts the demo prints expected output

### Invariant smoke tests (the 3 required by the plan)

These live in `test/integration/` (or co-located in the relevant app — agent's call):

- `[INV-4.1]` audience binding: token minted for `aud=http://other.example.com` is rejected by the MCP server
- `[INV-4.4]` PKCE: token endpoint rejects a `code_verifier` whose SHA-256 ≠ stored `code_challenge`
- `[INV-4.9]` CIMD URL mismatch: IdP rejects a CIMD whose `client_id` field ≠ the URL it was fetched from

(Some of these are already covered in prior slices' unit tests. This slice ensures end-to-end coverage of the three named smoke invariants.)

## CLI surface (§1)

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

Also accept `connect` implicitly (running `mcp-client --tool ...` works the same as `mcp-client connect --tool ...`).

## Local CIMD server (§2)

- Bind to `127.0.0.1:<cimd-port>` literally — NOT `localhost`. (Per [client.md §2.1](../specs/client.md), the authorization server's SSRF check needs a deterministic IP to match.)
- Two routes:
  - `GET /client.json` — serves the runtime-generated CIMD document
  - `GET /callback` — captures OAuth `code` + `state` (or `error`)
- CIMD document fields per [client.md §2.1](../specs/client.md):

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

- On the callback request, the server MUST: (1) capture `code`+`state` (or `error`), (2) send a successful HTTP response to the browser (e.g., "Authorization complete, you may close this window"), then (3) exit or unbind the port. Don't hold a listener open across the rest of the flow.

## Flow orchestration (§3)

Implemented in `flow.ts`:

1. Boot the local CIMD + callback server (`cimd-server.ts`).
2. `POST <server>/mcp` unauthenticated with an MCP `initialize`. Expect 401 + `WWW-Authenticate`.
3. Parse `WWW-Authenticate` (use shared slice 4's `parseWWWAuthenticate`). Extract `resource_metadata` and `scope`.
4. `fetchPRM(resource_metadata)` (shared slice 5). Read canonical `resource` field. If `authorization_servers` has multiple entries, select the first.
5. `discoverASMetadata(authorization_servers[0])` (shared slice 5). Hard-fail if `code_challenge_methods_supported` doesn't include `S256`.
6. Generate PKCE pair via shared `generatePKCE` (slice 3) and `state` via shared `generateState`.
7. Build authorize URL with the params per [client.md §3.2](../specs/client.md) table. `resource` = canonical from PRM.
8. Open the URL in the browser (use `open` package), or in `--headless` mode hit the IdP's auto-approve path directly.
9. Wait for callback at `/callback`.
   - If `error` query param present: validate `state`, then exit with a human-readable message (`access_denied` → "User denied consent"). Do NOT proceed.
   - Else: verify `state` matches (constant-time via shared `verifyState`). Tag `[INV-4.14]`.
10. POST to token endpoint per [client.md §3.3](../specs/client.md) table. Receive `access_token` + `refresh_token`.
11. Call the MCP tool with `Authorization: Bearer <token>`. Use MCP SDK client transport.
12. On 200: pretty-print result, exit 0.
13. On 403 `error="insufficient_scope"`: enter step-up (§3.5).

### Step-up (§3.5)

1. Parse `scope` from the 403 `WWW-Authenticate` header.
2. Loop back to step 6 above with `scope = union(previously_granted, newly_required)`. Never narrow.
3. After the new token is issued, automatically re-invoke the original `POST /mcp` tool call using the NEW access token from the step-up flow (NOT the previously-insufficient one). The user's intent (the original `--tool`/`--args`) is what triggered the flow — replay it with the upgraded token.
4. Cap at 2 retries. Further 403s → permanent failure, exit nonzero.

## Security requirements (§4)

- Tokens MUST be sent only in `Authorization: Bearer` — never query or path. Invariant §4.13.
- Tokens, codes, and `code_verifier` MUST NOT be logged at any level. Invariant §4.12 — `log.ts` enforces redaction.
- Tokens MUST NOT be decoded for authorization decisions; only for human display when `--verbose`. Treat them as opaque even though they happen to be JWTs.

## CLI output (§5)

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

(Use ansi colors if convenient. Match the spec example closely.)

## Test patterns

### `apps/mcp-client/src/integration.test.ts`

- Local CIMD server: GET `/client.json` returns the expected JSON; binds to `127.0.0.1`.
- Callback handler: `?code=X&state=S` captures correctly; `?error=access_denied&state=S` is recognized and short-circuits.

### `test/integration/auth-flow.test.ts`

Boots IdP + MCP server in-process (using their `createXApp` factories). Drives the client's `flow.ts` against them. Asserts:

- `[INV-4.1]` audience binding — modify the test to mint a token for a wrong audience and assert MCP server returns 401.
- Step-up flow: call `get_premium_forecast` with initial scope `weather:read` only; assert the client successfully step-ups and gets a result.

### `test/integration/smoke.test.ts`

Subprocess spawn — closest to production demo:

```ts
import { spawn } from "node:child_process";

it("end-to-end happy path via real subprocesses", async () => {
  const idp = spawn("pnpm", ["dev:idp"], { env: { ...process.env, AS_AUTO_APPROVE: "true" } });
  const mcp = spawn("pnpm", ["dev:mcp"]);
  try {
    await waitForHttp("http://localhost:4444/healthz");
    await waitForHttp("http://localhost:3333/healthz");

    const client = spawn("pnpm", [
      "dev:client",
      "--headless",
      "--tool", "get_weather",
      "--args", '{"city":"Denver"}',
    ]);
    const output = await collectStdout(client);
    expect(output).toContain("72°F");
    expect(client.exitCode).toBe(0);
  } finally {
    idp.kill();
    mcp.kill();
  }
}, 30_000);
```

Long timeout because subprocess boot is slow. Skip when `process.env.CI_SKIP_SMOKE` is set (lets you run unit tests fast locally).

### Step-up smoke

A second smoke test invokes `get_premium_forecast` with `--headless` and asserts the client recovers via step-up. The IdP's auto-approve mode grants the requested scope set automatically.

## Out of scope

- Refresh-token redemption (the token simply expires; user reauthorizes).
- Multi-AS selection UI (PoC picks the first authorization server).
- Real browser automation in tests (the `--headless` path hits the IdP's auto-approve endpoint directly).

## Verification

```bash
test -f apps/mcp-client/src/index.ts
test -f apps/mcp-client/src/cli.ts
test -f apps/mcp-client/src/cimd-server.ts
test -f apps/mcp-client/src/discovery.ts
test -f apps/mcp-client/src/authorize.ts
test -f apps/mcp-client/src/token.ts
test -f apps/mcp-client/src/mcp-call.ts
test -f apps/mcp-client/src/flow.ts
test -f apps/mcp-client/src/integration.test.ts
test -f test/integration/auth-flow.test.ts
test -f test/integration/smoke.test.ts

pnpm typecheck
pnpm lint
pnpm test

pnpm exec vitest run -t '[INV-4.1]' --reporter=verbose
pnpm exec vitest run -t '[INV-4.4]' --reporter=verbose
pnpm exec vitest run -t '[INV-4.9]' --reporter=verbose
pnpm exec vitest run -t '[INV-4.14]' --reporter=verbose

# Independent AI review — address findings before commit
cr review --agent --type uncommitted -c CLAUDE.md -c specs/client.md
```

All gate commands must exit 0. CodeRabbit findings: address or explicitly acknowledge.

### Manual demo (the deliverable interview moment)

```bash
cp apps/mock-customer-idp/.env.example apps/mock-customer-idp/.env
cp apps/mcp-server/.env.example apps/mcp-server/.env
pnpm install
pnpm dev &
sleep 3
pnpm dev:client --tool get_weather --args '{"city":"Denver"}'
# → expects "72°F and sunny" or similar
pnpm dev:client --tool get_premium_forecast --args '{"city":"Denver"}'
# → expects step-up flow + 14-day forecast
```
