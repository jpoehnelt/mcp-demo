// IdP environment validation. Source of truth: specs/authorization-server.md §2
// and apps/mock-customer-idp/.env.example.
//
// Invalid configuration MUST prevent startup — `parseEnv` throws a `ZodError`
// the caller (`index.ts`) catches to log + exit non-zero. No partial startup.

import type { CanonicalURI } from "@poc/shared";
import { canonicalize } from "@poc/shared";
import { z } from "zod";

export interface IdPEnv {
  AS_ISSUER_URL: CanonicalURI;
  AS_PORT: number;
  AS_DB_PATH: string;
  AS_SIGNING_ALG: "RS256" | "ES256" | "EdDSA";
  AS_TOKEN_TTL_SEC: number;
  AS_REFRESH_TOKEN_TTL_SEC: number;
  AS_AUTO_APPROVE: boolean;
  AS_DEMO_USER_SUB: string;
  AS_DEV_ALLOW_INSECURE_CIMD: boolean;
}

// `AS_AUTO_APPROVE` / `AS_DEV_ALLOW_INSECURE_CIMD` arrive as strings from
// `process.env`; treat anything but the literal "true" as `false` (matches
// dotenv convention; avoids accidentally enabling dev flags on typos).
const boolFromString = z.string().transform((v) => v === "true");

// `AS_ISSUER_URL`:
//   - Required (no default).
//   - Canonicalized via shared `canonicalize`. Throws on malformed URL.
//   - MUST have an empty path component (PoC constraint per
//     specs/authorization-server.md §2). `canonicalize` collapses `/` to "",
//     so any non-empty `URL#pathname` after canonicalization fails this check.
const issuerUrlSchema = z
  .string()
  .min(1, "AS_ISSUER_URL is required")
  .transform((raw, ctx): CanonicalURI => {
    let canonical: CanonicalURI;
    try {
      canonical = canonicalize(raw);
    } catch (err) {
      ctx.addIssue({
        code: "custom",
        message: `AS_ISSUER_URL is not a valid absolute URL: ${
          err instanceof Error ? err.message : String(err)
        }`,
      });
      return z.NEVER;
    }
    // Re-parse the canonical form to inspect its pathname. `canonicalize`
    // already verified the URL is absolute, so `new URL` cannot throw.
    const parsed = new URL(canonical);
    if (parsed.pathname !== "" && parsed.pathname !== "/") {
      ctx.addIssue({
        code: "custom",
        message:
          "AS_ISSUER_URL MUST have an empty path component (PoC constraint, " +
          "specs/authorization-server.md §2)",
      });
      return z.NEVER;
    }
    return canonical;
  });

const EnvSchema = z.object({
  AS_ISSUER_URL: issuerUrlSchema,
  AS_PORT: z.coerce.number().int().positive().default(4444),
  AS_DB_PATH: z.string().min(1).default("./as.db"),
  AS_SIGNING_ALG: z.enum(["RS256", "ES256", "EdDSA"]).default("RS256"),
  AS_TOKEN_TTL_SEC: z.coerce.number().int().positive().default(300),
  AS_REFRESH_TOKEN_TTL_SEC: z.coerce.number().int().positive().default(86400),
  AS_AUTO_APPROVE: boolFromString.default(false),
  AS_DEMO_USER_SUB: z.string().min(1).default("demo-user"),
  AS_DEV_ALLOW_INSECURE_CIMD: boolFromString.default(false),
});

/**
 * Parse + validate IdP environment. Throws `ZodError` on any violation
 * (missing required, malformed URL, path-having issuer, invalid alg, etc.).
 *
 * Pure: accepts a `raw` map so tests can construct envs without poking
 * `process.env`.
 */
export function parseEnv(raw: Record<string, string | undefined>): IdPEnv {
  return EnvSchema.parse(raw);
}
