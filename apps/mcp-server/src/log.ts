// pino logger with the redaction list from specs/resource-server.md §4.1
// (and the spec-anchor list in the slice 10 prompt) — enforces architecture
// invariant §4.12 (no-secret-logging) at the transport layer. The redaction
// config is centralized here so a single edit covers every log call site.
//
// `redact: { paths, remove: true }` deletes the field entirely rather than
// replacing with `"[REDACTED]"`, so a redacted secret never reaches the log
// output regardless of formatter / transport.

import type { Logger, LoggerOptions } from "pino";
import pino from "pino";

export type { Logger };

// Secret field names that may appear as top-level keys or nested values on
// any logged object (e.g. `tokenResponse.access_token`,
// `bodyParams.token`).
const SECRET_FIELDS = ["token", "access_token"] as const;

// HTTP header names that may carry credentials. Case-sensitive against the
// actual object keys — Node's `http` lowercases header names while Hono /
// fetch preserve canonical casing, so cover both spellings.
const HEADER_FIELDS = ["authorization", "cookie"] as const;

function buildRedactPaths(): string[] {
  const paths: string[] = [];

  for (const field of SECRET_FIELDS) {
    paths.push(field, `*.${field}`, `*.*.${field}`);
  }

  for (const field of HEADER_FIELDS) {
    const canonical = field
      .split("-")
      .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
      .join("-");
    paths.push(
      `req.headers.${field}`,
      `req.headers.${canonical}`,
      `res.headers.${field}`,
      `res.headers.${canonical}`,
      `headers.${field}`,
      `headers.${canonical}`,
    );
  }

  // /mcp may carry query params; drop request bodies + query strings
  // wholesale on the off chance a misbehaving client smuggles a token in
  // there (the §4.1 middleware rejects such requests, but we still must
  // not log the smuggled value before the rejection).
  paths.push("req.body", "req.query", "request.body", "request.query", "body", "query");

  return paths;
}

const REDACT_PATHS = buildRedactPaths();

export interface CreateLoggerOptions {
  /** Underlying pino destination — defaults to stdout. Tests pass a buffer. */
  destination?: pino.DestinationStream;
  /** pino level override; default "info". */
  level?: LoggerOptions["level"];
}

/**
 * Build the MCP server logger with the §4.12 redaction list applied.
 * Exported for the boot path and for tests that need to assert redaction on
 * captured output.
 */
export function createLogger(options: CreateLoggerOptions = {}): Logger {
  const opts: LoggerOptions = {
    level: options.level ?? "info",
    redact: { paths: REDACT_PATHS, remove: true },
  };
  return options.destination === undefined ? pino(opts) : pino(opts, options.destination);
}

/** Exposed for tests that want to assert the spec-mandated paths are present. */
export const _redactPathsForTest: readonly string[] = REDACT_PATHS;
