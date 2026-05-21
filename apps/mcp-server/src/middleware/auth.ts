// JWT bearer-token middleware per specs/resource-server.md §4.1 and
// architecture invariants §4.1, §4.2, §4.3, §4.7, §4.12, §4.13.
//
// Order of checks (matches §4.1 step list):
//   1. Reject token-shaped values in URI query or path  (§4.13)
//   2. Require `Authorization: Bearer <token>`          (§4.7)
//   3. Verify the JWT via the shared verifier           (§4.1/§4.2/§4.3)
//   4. Attach claims to context on success
//
// Every 401 carries the SAME `WWW-Authenticate` header — clients receive a
// consistent step-up signal regardless of which check failed. Logged
// failures carry a short reason code (`token_in_uri`, `missing_bearer`,
// `verification_failed`) and never the token value itself (§4.12).

import {
  buildUnauthorizedHeader,
  type CanonicalURI,
  InvalidAudienceError,
  InvalidIssuerError,
  InvalidTokenError,
  type JWTVerifier,
  type TokenClaims,
  TokenExpiredError,
} from "@poc/shared";
import type { Context, MiddlewareHandler } from "hono";
import type { MCPServerEnv } from "../env.js";
import type { Logger } from "../log.js";

/**
 * Hono context Variables surface contributed by this middleware. Other
 * middleware / handlers can pull the verified claims off `c.var.claims`.
 */
export interface AuthVariables {
  claims: TokenClaims;
}

interface AuthMiddlewareDeps {
  env: MCPServerEnv;
  verifier: JWTVerifier;
  log: Logger;
}

// JWTs are three base64url segments. The header always starts with `eyJ`
// (`{"` base64url-encoded). We reject any query value or path segment that
// looks JWT-shaped to defend invariant §4.13.
const JWT_SHAPED_RE = /eyJ[A-Za-z0-9_-]+/;

function prmUrlFor(audience: CanonicalURI): string {
  // PoC constraint: MCP_AUDIENCE has empty path, so simple concatenation
  // is correct. The PRM mount path is fixed by RFC 9728 §3.
  return `${audience}/.well-known/oauth-protected-resource`;
}

function buildChallenge(env: MCPServerEnv): string {
  return buildUnauthorizedHeader({
    realm: env.MCP_AUDIENCE,
    resourceMetadata: prmUrlFor(env.MCP_AUDIENCE),
    scope: "weather:read",
  });
}

/**
 * Map a verifier exception to a stable short reason code suitable for logs.
 * Returning a literal union (rather than `Error.name`) keeps the log
 * vocabulary controlled — every distinct failure path lands on one of
 * these labels, and a regression that introduces a new error type surfaces
 * as `unknown`.
 */
function classifyVerificationError(err: unknown): string {
  if (err instanceof TokenExpiredError) return "expired";
  if (err instanceof InvalidAudienceError) return "aud_mismatch";
  if (err instanceof InvalidIssuerError) return "iss_mismatch";
  if (err instanceof InvalidTokenError) return "bad_signature";
  return "unknown";
}

function reject(
  c: Context,
  challenge: string,
  log: Logger,
  reason: string,
  extra: Record<string, unknown> = {},
): Response {
  log.warn({ reason, ...extra }, "mcp auth rejected");
  c.header("WWW-Authenticate", challenge);
  return c.json({ error: "invalid_token" }, 401);
}

/**
 * Build the auth middleware bound to (env, verifier, log). The middleware
 * applies only to routes the caller mounts it on — `app.ts` wires it under
 * `/mcp` so PRM + /healthz remain anonymous.
 */
export function createAuthMiddleware(deps: AuthMiddlewareDeps): MiddlewareHandler {
  const challenge = buildChallenge(deps.env);

  return async (c, next) => {
    // 1. Token-in-URI rejection (§4.13). We scan the raw URL string because
    //    Hono's `c.req.query()` percent-decodes values — a JWT inside a query
    //    value would survive that decode unchanged, but checking the raw URL
    //    catches both query and path placements in one pass.
    const rawUrl = c.req.url;
    // Strip scheme + host to focus the regex on path + query, since `eyJ`
    // could theoretically appear in the host on some adversarial input.
    let pathAndQuery: string;
    try {
      const parsed = new URL(rawUrl);
      pathAndQuery = `${parsed.pathname}${parsed.search}`;
    } catch {
      pathAndQuery = rawUrl;
    }
    if (JWT_SHAPED_RE.test(pathAndQuery)) {
      return reject(c, challenge, deps.log, "token_in_uri", { path: c.req.path });
    }

    // 2. Authorization header parse (§4.7).
    const authHeader = c.req.header("authorization");
    if (authHeader === undefined || authHeader.length === 0) {
      return reject(c, challenge, deps.log, "missing_authorization");
    }
    const bearerMatch = /^Bearer\s+(\S+)\s*$/i.exec(authHeader);
    if (bearerMatch === null) {
      return reject(c, challenge, deps.log, "non_bearer_scheme");
    }
    const token = bearerMatch[1];
    if (token === undefined || token.length === 0) {
      return reject(c, challenge, deps.log, "empty_bearer_token");
    }

    // 3. Verify the JWT (§4.1/§4.2/§4.3). The verifier already rejects
    //    HS*/none, enforces canonical iss + aud, and validates exp/nbf.
    let claims: TokenClaims;
    try {
      claims = await deps.verifier.verify(token);
    } catch (err) {
      const reason = classifyVerificationError(err);
      return reject(c, challenge, deps.log, reason);
    }

    // 4. Attach claims for downstream handlers (slice 11 scope checks).
    c.set("claims", claims);
    await next();
    return; // explicit return — middleware handlers must return void/Response
  };
}
