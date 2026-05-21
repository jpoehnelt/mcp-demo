// pino logger with the redaction list from specs/authorization-server.md §8
// — enforces architecture invariant §4.12 (no-secret-logging) at the
// transport layer. The redaction config is centralized here so a single
// edit covers every log call site.
//
// `redact: { paths, remove: true }` deletes the field entirely rather than
// replacing with `"[REDACTED]"`, so a redacted secret never reaches the
// log output regardless of formatter / transport.

import type { Logger, LoggerOptions } from "pino";
import pino from "pino";

export type { Logger };

// Paths cover both top-level fields (e.g. `code`, `password`) and the
// common nested shapes pino observes in HTTP middleware: `req.headers.*`,
// `res.headers.*`, request bodies, URL query strings.
//
// We use `*.<field>` wildcards so the redaction catches arbitrary nesting
// (e.g. `tokenResponse.access_token`, `consentBody.code_verifier`) without
// having to enumerate every possible location ahead of time.
const SECRET_FIELDS = [
  "token",
  "access_token",
  "refresh_token",
  "code",
  "code_verifier",
  "private_jwk",
  "client_secret",
  "password",
] as const;

const HEADER_FIELDS = ["authorization", "cookie", "set-cookie", "proxy-authorization"] as const;

function buildRedactPaths(): string[] {
  const paths: string[] = [];

  for (const field of SECRET_FIELDS) {
    paths.push(field, `*.${field}`, `*.*.${field}`);
  }

  // Pino redaction is case-sensitive against the actual object keys. Node's
  // `http` lowercases header names on the request, but Hono / fetch keep
  // canonical casing — cover both.
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

  // /token and /authorize/consent carry secrets in the request body and
  // query string — drop the entire payloads (per §8 last bullet).
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
 * Build the IdP logger with the §8 redaction list applied. Exported for
 * the boot path and for tests that need to assert redaction on captured
 * output.
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
