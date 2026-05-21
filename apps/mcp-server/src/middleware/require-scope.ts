// Scope-enforcement helper + global error handler. See
// specs/resource-server.md §5 and architecture invariant §4.8.
//
// The two pieces are paired by contract: `requireScope` throws
// `InsufficientScopeError` whose `.message` is the missing scope, and the
// `attachInsufficientScopeHandler` Hono `onError` hook recovers that scope to
// build the RFC 6750 §3.1 `WWW-Authenticate` challenge. Anything else that
// bubbles up to `onError` is re-thrown so Hono's default 500 path still owns
// unexpected failures.
//
// The handler is wired once at app construction (`app.ts`) so every route —
// not just `/mcp` — emits a consistent 403 if a downstream module starts
// throwing `InsufficientScopeError` in the future.

import {
  buildInsufficientScopeHeader,
  type CanonicalURI,
  InsufficientScopeError,
  type TokenClaims,
} from "@poc/shared";
import type { Context, Hono } from "hono";
import type { MCPServerEnv } from "../env.js";

/**
 * Throw `InsufficientScopeError` if `scope` is not present in the
 * space-separated `claims.scope` list. The thrown error's `.message` is the
 * required scope verbatim — the global handler reads it back to populate the
 * `scope=` parameter on the 403 `WWW-Authenticate` header.
 *
 * Contract: callers MUST pass a non-empty scope string. Tools whose row in
 * the §6 table has no required scope (e.g. `list_cities`) MUST NOT call this
 * function — authentication alone gates them.
 */
export function requireScope(claims: TokenClaims, scope: string): void {
  if (scope.length === 0) {
    // Defensive: a caller that passes an empty scope is a bug. Throw a
    // distinct error so the bug surfaces as a 500 (not as a misleading 403
    // claiming "scope required: <empty>").
    throw new Error("requireScope called with empty scope");
  }
  const granted = (claims.scope ?? "").split(" ").filter((s) => s.length > 0);
  if (!granted.includes(scope)) {
    throw new InsufficientScopeError(scope);
  }
}

interface InsufficientScopeHandlerDeps {
  env: MCPServerEnv;
}

function prmUrlFor(audience: CanonicalURI): string {
  // Mirrors the helper in middleware/auth.ts. The PoC's MCP_AUDIENCE has an
  // empty path, so simple concatenation is correct. The PRM mount path is
  // fixed by RFC 9728 §3.
  return `${audience}/.well-known/oauth-protected-resource`;
}

function buildChallenge(env: MCPServerEnv, scope: string): string {
  return buildInsufficientScopeHeader({
    realm: env.MCP_AUDIENCE,
    scope,
    resourceMetadata: prmUrlFor(env.MCP_AUDIENCE),
  });
}

/**
 * Register a Hono `onError` hook that converts thrown
 * `InsufficientScopeError` into a 403 with the spec-mandated
 * `WWW-Authenticate` header. Other error types are re-thrown so Hono's
 * default error path handles them.
 *
 * Idempotent in practice — Hono's `onError` is last-write-wins, so callers
 * MUST register this hook before any custom handlers that intend to stack.
 * `app.ts` calls it exactly once.
 */
export function attachInsufficientScopeHandler(
  app: Hono<{ Variables: { claims: TokenClaims } }>,
  deps: InsufficientScopeHandlerDeps,
): void {
  app.onError((err, c: Context) => {
    if (err instanceof InsufficientScopeError) {
      const scope = err.message;
      c.header("WWW-Authenticate", buildChallenge(deps.env, scope));
      return c.json({ error: "insufficient_scope", scope }, 403);
    }
    // Re-throw to let Hono apply its default 500 handling.
    throw err;
  });
}
