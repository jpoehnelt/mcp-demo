// MCP server environment validation. Source of truth:
// specs/resource-server.md §2 and apps/mcp-server/.env.example.
//
// Invalid configuration MUST prevent startup — `parseEnv` throws a `ZodError`
// the caller (`index.ts`) catches to log + exit non-zero. No partial startup.
//
// Identity-side vars (`MCP_OIDC_ISSUER_URL`, `MCP_AUDIENCE`,
// `MCP_PRM_AUTH_SERVERS`) are the entire BYOC contract per architecture §2.1 —
// swapping these three at a real IdP MUST NOT require code changes.

import type { CanonicalURI } from "@poc/shared";
import { canonicalize } from "@poc/shared";
import { z } from "zod";

export interface MCPServerEnv {
  MCP_OIDC_ISSUER_URL: CanonicalURI;
  MCP_AUDIENCE: CanonicalURI;
  MCP_PRM_AUTH_SERVERS: CanonicalURI[];
  MCP_PORT: number;
}

/**
 * Canonicalize a single URL inside a zod transform, attaching a custom issue
 * + `z.NEVER` on failure so the caller sees a clean `ZodError` instead of a
 * thrown `InvalidCanonicalURIError`.
 */
function canonicalizeWithIssue(
  raw: string,
  ctx: z.RefinementCtx,
  field: string,
): CanonicalURI | typeof z.NEVER {
  try {
    return canonicalize(raw);
  } catch (err) {
    ctx.addIssue({
      code: "custom",
      message: `${field} is not a valid absolute URL: ${
        err instanceof Error ? err.message : String(err)
      }`,
    });
    return z.NEVER;
  }
}

const canonicalUrlSchema = (field: string) =>
  z
    .string()
    .min(1, `${field} is required`)
    .transform((raw, ctx): CanonicalURI => canonicalizeWithIssue(raw, ctx, field));

// `MCP_PRM_AUTH_SERVERS` is comma-separated. Empty entries (e.g. trailing
// commas) are silently dropped before canonicalization; a fully-empty list
// fails the `.min(1)` check.
const authServersSchema = z
  .string()
  .min(1, "MCP_PRM_AUTH_SERVERS is required")
  .transform((raw, ctx): CanonicalURI[] => {
    const parts = raw
      .split(",")
      .map((p) => p.trim())
      .filter((p) => p.length > 0);
    if (parts.length === 0) {
      ctx.addIssue({
        code: "custom",
        message: "MCP_PRM_AUTH_SERVERS must contain at least one URL",
      });
      return z.NEVER;
    }
    const out: CanonicalURI[] = [];
    for (const part of parts) {
      const canonical = canonicalizeWithIssue(part, ctx, "MCP_PRM_AUTH_SERVERS entry");
      if (canonical === z.NEVER) return z.NEVER;
      out.push(canonical);
    }
    return out;
  });

const EnvSchema = z.object({
  MCP_OIDC_ISSUER_URL: canonicalUrlSchema("MCP_OIDC_ISSUER_URL"),
  MCP_AUDIENCE: canonicalUrlSchema("MCP_AUDIENCE"),
  MCP_PRM_AUTH_SERVERS: authServersSchema,
  MCP_PORT: z.coerce.number().int().positive().default(3333),
});

/**
 * Parse + validate MCP server environment. Throws `ZodError` on any violation
 * (missing required, malformed URL, empty auth-servers list, non-positive
 * port, etc.).
 *
 * Pure: accepts a `raw` map so tests can construct envs without poking
 * `process.env`.
 */
export function parseEnv(raw: Record<string, string | undefined>): MCPServerEnv {
  return EnvSchema.parse(raw);
}
