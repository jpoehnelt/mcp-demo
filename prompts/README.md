# Implementation Prompts

Twelve numbered slices to implement the MCP OAuth 2.1 + CIMD demo end-to-end. Each slice is one focused implementation session — read the prompt, implement, verify, commit.

## How to use a prompt

1. **Read the prompt cold.** Don't assume context from earlier prompts; the prompt names its spec anchors, deliverables, and acceptance criteria explicitly.
2. **Read the spec anchors** listed at the top. The specs are the contract; the prompt is the work order.
3. **Implement.** Write code + tests in the same session.
4. **Verify (hard gates).** Run every command in the `## Verification` block; all MUST exit 0. Per [CLAUDE.md](../CLAUDE.md), claiming "done" without running these is forbidden.
5. **Verify (independent AI review).** Run `cr review --agent ...` from the prompt — CodeRabbit's findings catch semantic / spec-alignment issues that lint and tests miss. Address findings, then re-run step 4.
6. **Commit.** Pre-commit hook re-runs the gates as a safety net.

## Slice index

| # | File | What lands |
|---|---|---|
| 1 | [01-shared-foundations.md](01-shared-foundations.md) | Branded types, error classes, `canonicalize()` |
| 2 | [02-shared-schemas.md](02-shared-schemas.md) | Zod schemas: CIMD, PRM, AS-metadata, token-claims |
| 3 | [03-shared-pkce-state.md](03-shared-pkce-state.md) | PKCE generate+verify, state generate+verify |
| 4 | [04-shared-http.md](04-shared-http.md) | SSRF-safe fetch, WWW-Authenticate header helpers |
| 5 | [05-shared-identity.md](05-shared-identity.md) | JWT verifier, AS metadata discovery, CIMD validator |
| 6 | [06-idp-bootstrap.md](06-idp-bootstrap.md) | IdP Hono app, env, SQLite, signing keys, healthz |
| 7 | [07-idp-metadata.md](07-idp-metadata.md) | `/.well-known/oauth-authorization-server`, OIDC mirror, `/jwks.json` |
| 8 | [08-idp-authorize.md](08-idp-authorize.md) | `/authorize` + consent UI + CIMD fetch/validate |
| 9 | [09-idp-token.md](09-idp-token.md) | `/token` (authorization_code grant) |
| 10 | [10-mcp-server.md](10-mcp-server.md) | MCP server env, PRM, JWT middleware |
| 11 | [11-mcp-tools.md](11-mcp-tools.md) | Three MCP tools + `requireScope` |
| 12 | [12-client-and-smoke.md](12-client-and-smoke.md) | Client CLI, step-up flow, cross-app + subprocess smoke tests |

## Dependency order

Slices 1–5 are bottom-up shared library; 6–9 are the IdP; 10–11 are the MCP server; 12 closes the loop. Do them in order — later slices import from earlier ones.

## Convention reminders (also in [CLAUDE.md](../CLAUDE.md))

- TypeScript strict; no `any`. Use `unknown` and narrow.
- All external boundaries parse with zod.
- Every MUST/SHOULD gets a test whose name cites the invariant (`[INV-4.5]` etc).
- Each app slice (IdP, MCP server, client) MUST include in-process integration tests using Hono's `app.request()` for its new endpoints. Cross-app integration tests live in `test/integration/`.
- No `console.log` — use the pino logger configured in each app's `log.ts`.
- All thrown errors MUST be typed (see [shared-library.md §4](../specs/shared-library.md)).

## Done means

For every slice:

```bash
pnpm typecheck
pnpm lint
pnpm test
```

All three exit 0. Pre-commit double-checks. Do not claim done based on inspection.
