// pino logger for the MCP client CLI with the same redaction list as the
// IdP / MCP server. Enforces architecture invariant §4.12 (no-secret-logging)
// — codes, verifiers, tokens, refresh tokens, and credential headers are
// removed from log output regardless of formatter or destination.
//
// Mirrors apps/mcp-server/src/log.ts so the three apps share a single
// redaction policy. Field list cited from specs/client.md §4 (security
// requirements: tokens, codes, code_verifier MUST NOT be logged).

import type { Logger, LoggerOptions } from "pino";
import pino from "pino";

export type { Logger };

// Secret field names that may appear as top-level keys or nested values on
// any logged object.
const SECRET_FIELDS = ["token", "access_token", "refresh_token", "code", "code_verifier"] as const;

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

  // Drop bodies + query strings wholesale on the off chance a misbehaving
  // dependency smuggles a token in there.
  paths.push("req.body", "req.query", "request.body", "request.query", "body", "query");

  return paths;
}

const REDACT_PATHS = buildRedactPaths();

export interface CreateLoggerOptions {
  /** Underlying pino destination — defaults to stderr (CLI uses stdout for UX). */
  destination?: pino.DestinationStream;
  /** pino level override; default "info". */
  level?: LoggerOptions["level"];
}

/**
 * Build the MCP client logger with the §4.12 redaction list applied.
 *
 * Defaults to stderr because the CLI's user-visible output (the
 * checkmark/timeline lines) goes to stdout via `process.stdout.write` — we
 * don't want the structured pino lines bleeding into the demo's pretty
 * output. Tests pass a buffer to capture lines.
 */
export function createLogger(options: CreateLoggerOptions = {}): Logger {
  const opts: LoggerOptions = {
    level: options.level ?? "info",
    redact: { paths: REDACT_PATHS, remove: true },
  };
  const destination = options.destination ?? pino.destination(2); // stderr
  return pino(opts, destination);
}

/** Exposed for tests that want to assert the spec-mandated paths are present. */
export const _redactPathsForTest: readonly string[] = REDACT_PATHS;
