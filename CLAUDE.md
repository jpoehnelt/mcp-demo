# CLAUDE.md

Project context for the MCP OAuth 2.1 + CIMD authorization demo. This file is a pointer index — the specs themselves are the source of truth. Read them; do not duplicate their content here.

## Always read before any code change

- `specs/architecture.md` — system roles, trust boundaries, invariants, non-goals, technology stack.

## Read before touching a specific area

| Path you're editing         | Spec to read first              |
| --------------------------- | ------------------------------- |
| `apps/mock-customer-idp/**` | `specs/authorization-server.md` |
| `apps/mcp-server/**`        | `specs/resource-server.md`      |
| `apps/mcp-client/**`        | `specs/client.md`               |
| `packages/shared/**`        | `specs/shared-library.md`       |

## Conventions

- Atomic commits per logical change.
- Every external boundary parses with zod.
- Every MUST/SHOULD implementation gets a test.
- Each app slice (IdP, MCP server, MCP client) MUST include in-process integration tests using `app.request()` (Hono) for its new endpoints; cross-app integration tests live under `test/integration/`.
- App env vars are documented in each app's `.env.example`; copy to `.env` before running. `dev`/`start` scripts use Node's `--env-file-if-exists` so apps still boot from pure shell env when no `.env` is present.

## Done means

A change is "done" only when all three exit 0:

```bash
pnpm typecheck
pnpm lint # Run pnpm lint:fix or pnpm lint:fix:unsafe to start autofixing
pnpm test
```

Pre-commit runs the same three on staged TypeScript changes, so a clean commit is the gate. Do not claim work is complete based on inspection — run the commands.

## Common commands

| Task                         | Command                               |
| ---------------------------- | ------------------------------------- |
| Install deps                 | `pnpm install`                        |
| Typecheck all workspaces     | `pnpm typecheck`                      |
| Typecheck one workspace      | `pnpm --filter @poc/<name> typecheck` |
| Build all                    | `pnpm build`                          |
| Lint + format check          | `pnpm lint`                           |
| Lint + format autofix (safe) | `pnpm lint:fix`                       |
| Lint + format autofix (any)  | `pnpm lint:fix:unsafe`                |
| Run all tests                | `pnpm test`                           |
| Watch tests                  | `pnpm test:watch`                     |
| Run both servers (IdP + MCP) | `pnpm dev`                            |
| Run dev — IdP only           | `pnpm dev:idp`                        |
| Run dev — MCP server only    | `pnpm dev:mcp`                        |
| Run dev — MCP client         | `pnpm dev:client`                     |

Composite project references mean incremental builds are fast — prefer `pnpm typecheck` over per-file checks.
