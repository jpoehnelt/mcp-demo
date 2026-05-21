// GET /.well-known/oauth-protected-resource — Protected Resource Metadata
// per RFC 9728 §3 and specs/resource-server.md §3.
//
// The response body is frozen at construction (env doesn't change after
// boot) so subsequent requests serve the same JSON-stringified bytes.
// `scopes_supported` advertises ONLY `weather:read`: the premium scope
// surfaces through the 403 step-up challenge (§3.1), not through PRM.

import { Hono } from "hono";
import type { MCPServerEnv } from "../env.js";

const CACHE_CONTROL = "max-age=3600";

interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: readonly string[];
  scopes_supported: readonly ["weather:read"];
  bearer_methods_supported: readonly ["header"];
}

function buildPRM(env: MCPServerEnv): ProtectedResourceMetadata {
  return {
    resource: env.MCP_AUDIENCE,
    // Spec §3: emit the full list, in input order. Each entry is already
    // canonicalized at env parse time.
    authorization_servers: [...env.MCP_PRM_AUTH_SERVERS],
    scopes_supported: ["weather:read"],
    bearer_methods_supported: ["header"],
  };
}

export function prmRoute(env: MCPServerEnv): Hono {
  const app = new Hono();
  const body = buildPRM(env);
  app.get("/.well-known/oauth-protected-resource", (c) => {
    c.header("Cache-Control", CACHE_CONTROL);
    return c.json(body);
  });
  return app;
}
