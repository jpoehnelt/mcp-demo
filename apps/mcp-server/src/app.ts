// Hono app factory for the MCP resource server. Exported separately from
// `index.ts` so integration tests can construct an app and drive it via
// `app.request()` without binding a real port. `index.ts` is the only place
// that calls `serve` from `@hono/node-server`.
//
// The factory is async because it performs RFC 8414 metadata discovery
// against the authorization server at construction time (per the slice 10
// spec — fail-fast on boot if discovery can't reach the AS). The discovered
// `jwks_uri` feeds the shared JWT verifier.

import { createJWTVerifier, discoverASMetadata } from "@poc/shared";
import { Hono } from "hono";
import type { MCPServerEnv } from "./env.js";
import type { Logger } from "./log.js";
import type { AuthVariables } from "./middleware/auth.js";
import { createAuthMiddleware } from "./middleware/auth.js";
import { healthzRoute } from "./routes/healthz.js";
import { prmRoute } from "./routes/prm.js";

export interface MCPServerDeps {
  env: MCPServerEnv;
  log: Logger;
}

/**
 * Hono `Variables` shape — `claims` is populated by the auth middleware on
 * authenticated `/mcp` requests. Exporting the type lets slice 11 register
 * tool handlers with a typed `c.var.claims`.
 */
export type MCPServerVariables = AuthVariables;

export type MCPServerApp = Hono<{ Variables: MCPServerVariables }>;

/**
 * Build the MCP server app. Performs JWKS-via-AS-discovery at construction
 * time; throws on discovery failure so the caller can exit non-zero before
 * binding a port.
 */
export async function createMCPServerApp(deps: MCPServerDeps): Promise<MCPServerApp> {
  // 1. RFC 8414 discovery — fail-fast on boot. The shared helper runs the
  //    full cascade (`/.well-known/oauth-authorization-server` first, then
  //    OIDC fallbacks) and asserts S256 PKCE support.
  const asMetadata = await discoverASMetadata(deps.env.MCP_OIDC_ISSUER_URL);

  // 2. JWT verifier bound to (issuer, audience, jwks_uri). The verifier
  //    holds a jose remote JWKS set internally — constructed once, reused
  //    for every request (per spec §4.2).
  const verifier = createJWTVerifier({
    issuer: deps.env.MCP_OIDC_ISSUER_URL,
    audience: deps.env.MCP_AUDIENCE,
    jwksUri: asMetadata.jwks_uri,
  });

  const app = new Hono<{ Variables: MCPServerVariables }>();

  // Unauthenticated endpoints. Order matters: register before the `/mcp`
  // middleware so a misconfigured catch-all can't shadow them.
  app.route("/", healthzRoute());
  app.route("/", prmRoute(deps.env));

  // Authenticated MCP transport. Slice 11 will replace the stub handler
  // with the real `@modelcontextprotocol/sdk` streamable-HTTP transport.
  const auth = createAuthMiddleware({ env: deps.env, verifier, log: deps.log });
  app.use("/mcp", auth);
  app.use("/mcp/*", auth);
  app.post("/mcp", (c) => c.json({ ok: true }));

  return app;
}
