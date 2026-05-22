# Notes on the build

MCP OAuth 2.1 + CIMD demo, built mostly by Claude Code via a 12-slice prompt sequence.

## CIMD

CIMD is now the recommended pattern for OAuth + MCP based on the [docs](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#client-registration-approaches). It was new to me as I was stuck with pregistered clients at Google that added way too much friction for users connecting to MCP servers. The entire demo is built around this as requested. It makes sense given the ephemeral nature of MCP clients and not having to track every client in a database. Makes less sense if all clients are first party.

## What I picked and why

**`mock-customer-idp` stands in for the customer's IdP.** It implements just enough to be useful for this demo. But the pattern works for swapping in a real IdP. The only surface area that changes are three env vars: `MCP_OIDC_ISSUER_URL`, `MCP_AUDIENCE`, `MCP_PRM_AUTH_SERVERS`. Makes sense for BYOC. Easier dev loop. Could have been replaced by numerous options.

**Two scopes to exercise step-up.** `weather:read` and `weather:premium`. The 403 → re-authorize loop works and is interesting to see and consider for human in the loop and more granular consent.

**Invariants as tests.** Tests are named after the invariants in the spec. Tried to ensure correctness as much as possible. Would probably make this more strict if it was more than a demo.

**TypeScript/Zod/Hono/etc.** Claude knows these well. MCP libraries are robust. Would use a different statically typed language for prod.

## Working with Claude

There was a good amount of back and forth on setting up the spec, skeleton, and prompts. Basically technical discovery and design.

I split the build into 12 numbered prompts (`prompts/01-*` through `prompts/12-*`) and ran them in order. Most of the code was written while I was away from the keyboard and monitoring progress with my phone. There were a few commits afterwards to fix the CLI arg parsing and some other demo issues. I verified the demo with the client, curl, etc. Also attempted to use the MCP inspector, but was blocked since it doesn't support CIMD.

A few things that helped:

- **Specs in the repo, prompts point at them.** `CLAUDE.md` is a pointer index, not a duplicate.
- **Invariants as tests.** The spec has invariants and there are tests named for them.
- **Basic loop best practices.** Well defined tasks combined with an explicit verification leads to a tight loop. Also has git commit hooks.
- **Independent review before commit.** Each prompt's verification block ends with a CodeRabbit pass. The agent didn't do this correctly on the first few slices. This helps with spec alignment.

Starting any project with AI coding agents takes more time putting up guard rails and writing specs than actually implementing the code. Same as it has always been!
