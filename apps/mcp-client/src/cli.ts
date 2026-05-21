// CLI argument schema + defaults for the MCP client.
//
// Source of truth: specs/client.md §1.
//
// `parseArgs` accepts the commander-parsed options bag (already coerced to
// typed values where commander could do so) and produces a strongly-typed
// `ClientOptions` record. Defaults live here so `index.ts` (the commander
// glue) only has to forward `process.argv`.

import { z } from "zod";

export const DEFAULT_SERVER_URL = "http://localhost:3333";
export const DEFAULT_TOOL = "get_weather";
export const DEFAULT_ARGS_JSON = '{"city":"Denver"}';
export const DEFAULT_CIMD_PORT = 7777;

export interface ClientOptions {
  /** Canonical MCP server URL (no trailing slash, no userinfo). */
  server: string;
  /** Tool name to call. */
  tool: string;
  /** Tool arguments (already parsed from `--args` JSON). */
  args: Record<string, unknown>;
  /** Initial scope request; `undefined` means "use scope from 401 challenge". */
  scope: string | undefined;
  /** Port for the local CIMD/callback server. */
  cimdPort: number;
  /** Open a browser to drive consent. False in --headless or CI. */
  autoOpen: boolean;
  /** Drive consent via direct HTTP against the IdP (auto-approve path). */
  headless: boolean;
  /** Print the full handshake timeline (vs. just the tool result). */
  verbose: boolean;
}

/**
 * Raw shape commander hands us. Every field is a string except boolean flags;
 * we coerce to the typed `ClientOptions` shape with zod.
 */
export interface RawOptions {
  server?: string;
  tool?: string;
  args?: string;
  scope?: string;
  cimdPort?: string | number;
  autoOpen?: boolean;
  headless?: boolean;
  verbose?: boolean;
}

const argsJsonSchema = z
  .string()
  .default(DEFAULT_ARGS_JSON)
  .transform((raw, ctx): Record<string, unknown> => {
    let json: unknown;
    try {
      json = JSON.parse(raw);
    } catch (err) {
      ctx.addIssue({
        code: "custom",
        message: `--args is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
      });
      return z.NEVER;
    }
    if (typeof json !== "object" || json === null || Array.isArray(json)) {
      ctx.addIssue({
        code: "custom",
        message: '--args must be a JSON object (e.g. \'{"city":"Denver"}\')',
      });
      return z.NEVER;
    }
    return json as Record<string, unknown>;
  });

const portSchema = z.coerce
  .number()
  .int()
  .positive()
  .max(65_535, "cimd-port must be a valid TCP port")
  .default(DEFAULT_CIMD_PORT);

/**
 * Parse + validate raw commander options into a typed `ClientOptions`.
 *
 * Throws `ZodError` on malformed input. The caller (`index.ts`) catches and
 * logs to stderr + exits non-zero — consistent with the IdP / MCP server
 * env-validation handling.
 */
export function parseOptions(raw: RawOptions): ClientOptions {
  const isCi = process.env.CI !== undefined && process.env.CI !== "";
  // commander only sets a boolean when the flag is present; absence means
  // "use default". `auto-open` defaults to true unless we're in CI or the
  // caller passed `--headless`.
  const headless = raw.headless === true;
  const autoOpenDefault = !isCi && !headless;

  const parsed = z
    .object({
      server: z.string().url().default(DEFAULT_SERVER_URL),
      tool: z.string().min(1).default(DEFAULT_TOOL),
      args: argsJsonSchema,
      scope: z.string().min(1).optional(),
      cimdPort: portSchema,
      autoOpen: z.boolean().default(autoOpenDefault),
      headless: z.boolean().default(false),
      verbose: z.boolean().default(false),
    })
    .parse({
      server: raw.server,
      tool: raw.tool,
      args: raw.args,
      scope: raw.scope,
      cimdPort: raw.cimdPort,
      autoOpen: raw.autoOpen,
      headless,
      verbose: raw.verbose,
    });

  return {
    server: parsed.server,
    tool: parsed.tool,
    args: parsed.args,
    scope: parsed.scope,
    cimdPort: parsed.cimdPort,
    autoOpen: parsed.autoOpen,
    headless: parsed.headless,
    verbose: parsed.verbose,
  };
}
