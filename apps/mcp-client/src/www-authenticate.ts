// Thin wrapper around the shared `parseWWWAuthenticate` helper that extracts
// the four params the client cares about for the 401-then-discovery and the
// 403-then-step-up flows.
//
// The shared helper returns a raw `Record<string, string>`; we keep a typed
// projection here so call sites don't repeat the same `params[…] ?? undefined`
// pattern.

import { parseWWWAuthenticate } from "@poc/shared";

export interface ParsedAuthChallenge {
  scheme: string;
  realm: string | undefined;
  /** Per RFC 9728 — URL to the PRM document. Present on 401, absent on 403. */
  resourceMetadata: string | undefined;
  /** Space-separated scope list — may be union on step-up, single on 401. */
  scope: string | undefined;
  /** OAuth error code (e.g. "insufficient_scope") — only on 4xx-with-error. */
  error: string | undefined;
  errorDescription: string | undefined;
}

/**
 * Parse a `WWW-Authenticate` header value into the four canonical fields.
 *
 * Returns `undefined` when the header is missing, empty, or malformed —
 * callers that need to drive step-up should treat any of these as a hard
 * failure rather than reattempting.
 */
export function parseAuthChallenge(header: string | null): ParsedAuthChallenge | undefined {
  if (header === null || header.length === 0) return undefined;
  let parsed: ReturnType<typeof parseWWWAuthenticate>;
  try {
    parsed = parseWWWAuthenticate(header);
  } catch {
    return undefined;
  }
  return {
    scheme: parsed.scheme,
    realm: parsed.params.realm,
    resourceMetadata: parsed.params.resource_metadata,
    scope: parsed.params.scope,
    error: parsed.params.error,
    errorDescription: parsed.params.error_description,
  };
}
