// OAuth/OIDC metadata discovery per shared-library §2.5.
//
// Three pieces:
//   1. resolvePRMUrl       — RFC 9728 §3 path-aware Protected Resource Metadata URL.
//   2. fetchPRM            — SSRF-safe fetch + zod-parse for PRM.
//   3. discoverASMetadata  — RFC 8414 §3.1 + OIDC fallback cascade for AS metadata.
//
// Both PRM and AS lookups go through `safeFetch` from slice 4 with strict
// `application/json` content-type. The AS discovery hard-fails (typed error)
// if the resulting metadata lacks `S256` in `code_challenge_methods_supported`
// — the MCP spec mandates S256 PKCE.

import { InvalidTokenError } from "../errors.js";
import type { SafeFetchOptions } from "../http/ssrf.js";
import { safeFetch } from "../http/ssrf.js";
import type { ASMetadata } from "../types/as-metadata.js";
import { parseASMetadata } from "../types/as-metadata.js";
import type { CanonicalURI } from "../types/brands.js";
import type { ProtectedResourceMetadata } from "../types/prm.js";
import { parsePRM } from "../types/prm.js";

// ---------------------------------------------------------------------------
// Test seam
// ---------------------------------------------------------------------------

type FetcherFn = (
  url: string,
  opts: SafeFetchOptions,
) => Promise<{ status: number; body: string; headers: Headers }>;

/**
 * Injectable fetcher. Production uses `safeFetch` from slice 4. Tests swap
 * it via `__setFetcherForTests` to drive the cascade without an HTTPS
 * listener (HTTPS is the only allowed scheme for discovery, and standing up
 * a self-signed-cert listener in unit tests is heavy).
 */
let fetcherImpl: FetcherFn = safeFetch;

/**
 * Test-only: replace the fetcher used by `fetchPRM` and `discoverASMetadata`.
 * Returns the previous implementation so tests can restore it.
 *
 * @internal
 */
export function __setFetcherForTests(fn: FetcherFn): FetcherFn {
  const previous = fetcherImpl;
  fetcherImpl = fn;
  return previous;
}

const JSON_MEDIA_TYPE = "application/json";
const METADATA_MAX_BYTES = 64 * 1024;
const METADATA_TIMEOUT_MS = 5000;

/**
 * Build SafeFetch options for metadata-document GETs. Production callers
 * MUST pass `allowInsecure: false` so discovery refuses `http://` (avoids
 * SSRF + plaintext credential exposure). The localhost demo opts in via
 * env-var-driven `allowInsecure: true` per [authorization-server.md §4.3]
 * style — see the `MCP_DEV_ALLOW_INSECURE_DISCOVERY` env var on the MCP
 * server and the CLI behavior on the client.
 */
function metadataFetchOptions(allowInsecure: boolean): {
  allowInsecure: boolean;
  maxBytes: number;
  timeoutMs: number;
  expectContentType: string;
} {
  return {
    allowInsecure,
    maxBytes: METADATA_MAX_BYTES,
    timeoutMs: METADATA_TIMEOUT_MS,
    expectContentType: JSON_MEDIA_TYPE,
  };
}

// ---------------------------------------------------------------------------
// PRM resolution (RFC 9728 §3)
// ---------------------------------------------------------------------------

/**
 * Resolve the Protected Resource Metadata URL for a canonical MCP server
 * URI per [RFC 9728 §3](https://datatracker.ietf.org/doc/html/rfc9728#section-3).
 *
 * Path-aware rule: the `.well-known` segment is inserted between authority
 * and path. The original path becomes a suffix.
 *
 * Examples:
 *   * `https://example.com`               → `https://example.com/.well-known/oauth-protected-resource`
 *   * `https://example.com/`              → `https://example.com/.well-known/oauth-protected-resource`
 *   * `https://example.com/mcp`           → `https://example.com/.well-known/oauth-protected-resource/mcp`
 *   * `https://example.com/public/mcp`    → `https://example.com/.well-known/oauth-protected-resource/public/mcp`
 *
 * Throws via `URL()` if the canonical URI is somehow unparseable — should
 * never happen for a `CanonicalURI` brand.
 */
export function resolvePRMUrl(mcpServerUrl: CanonicalURI): string {
  const parsed = new URL(mcpServerUrl);
  // CanonicalURI guarantees no trailing slash and empty `pathname` for
  // bare-domain inputs. Defensively handle "/" anyway.
  const path = parsed.pathname === "/" ? "" : parsed.pathname;
  const base = `${parsed.protocol}//${parsed.host}/.well-known/oauth-protected-resource`;
  return path === "" ? base : `${base}${path}`;
}

/**
 * Fetch and validate a Protected Resource Metadata document.
 * Throws on transport / SSRF / content-type / schema errors per `safeFetch`
 * and zod.
 */
export async function fetchPRM(
  url: string,
  opts: { allowInsecure?: boolean } = {},
): Promise<ProtectedResourceMetadata> {
  const allowInsecure = opts.allowInsecure ?? false;
  const { status, body } = await fetcherImpl(url, metadataFetchOptions(allowInsecure));
  if (status < 200 || status >= 300) {
    throw new InvalidTokenError(`PRM fetch returned HTTP ${String(status)} (${url})`);
  }
  let json: unknown;
  try {
    json = JSON.parse(body);
  } catch (cause) {
    throw new InvalidTokenError(`PRM body is not valid JSON (${url})`, { cause });
  }
  return parsePRM(json);
}

// ---------------------------------------------------------------------------
// AS Metadata discovery cascade (RFC 8414 §3.1 + MCP fallback)
// ---------------------------------------------------------------------------

/**
 * Result helper for cascade attempts. We never let a failed step abort the
 * cascade — only the LAST step's failure propagates.
 */
interface CascadeAttempt {
  url: string;
  /**
   * The parsed result on success. `undefined` means the step is a soft miss
   * (e.g. 404, network error, JSON parse error, schema error).
   */
  metadata?: ASMetadata;
  /** Last error captured for the final-error message. */
  error?: unknown;
}

/**
 * RFC 8414 §3.1 path-insertion: place `.well-known/<doc>` between authority
 * and path. `https://idp.example.com/tenant1` →
 *   `https://idp.example.com/.well-known/oauth-authorization-server/tenant1`.
 */
function buildInsertedURL(parsed: URL, wellKnown: string): string {
  const path = parsed.pathname === "/" ? "" : parsed.pathname;
  return `${parsed.protocol}//${parsed.host}/.well-known/${wellKnown}${path}`;
}

/**
 * OIDC-style path-appending (legacy compatibility): append
 * `.well-known/<doc>` to the issuer path. `https://idp.example.com/tenant1`
 * → `https://idp.example.com/tenant1/.well-known/openid-configuration`.
 */
function buildAppendedURL(parsed: URL, wellKnown: string): string {
  // Strip exactly one trailing slash from the path, then append the
  // well-known segment. A bare-domain issuer ends up as `/.well-known/...`.
  const base = parsed.pathname.endsWith("/") ? parsed.pathname.slice(0, -1) : parsed.pathname;
  return `${parsed.protocol}//${parsed.host}${base}/.well-known/${wellKnown}`;
}

async function tryFetchASMetadata(url: string, allowInsecure: boolean): Promise<CascadeAttempt> {
  try {
    const { status, body } = await fetcherImpl(url, metadataFetchOptions(allowInsecure));
    if (status < 200 || status >= 300) {
      return { url, error: new Error(`HTTP ${String(status)} from ${url}`) };
    }
    let json: unknown;
    try {
      json = JSON.parse(body);
    } catch (cause) {
      return { url, error: cause };
    }
    const metadata = parseASMetadata(json);
    return { url, metadata };
  } catch (cause) {
    return { url, error: cause };
  }
}

/**
 * Implements the AS metadata discovery cascade per the MCP authorization
 * spec:
 *   1. `{issuer}/.well-known/oauth-authorization-server`  (path-insertion, RFC 8414 §3.1)
 *   2. `{issuer}/.well-known/openid-configuration`        (path-insertion)
 *   3. `{issuer}/.well-known/openid-configuration`        (path-append, OIDC legacy)
 *
 * If all three steps fail, throws an `InvalidTokenError` summarizing the
 * final attempt. Successful steps return immediately.
 *
 * Hard-fail: the returned metadata MUST list `S256` in
 * `code_challenge_methods_supported`. Anything else throws.
 */
export async function discoverASMetadata(
  issuerUrl: CanonicalURI,
  opts: { allowInsecure?: boolean } = {},
): Promise<ASMetadata> {
  const allowInsecure = opts.allowInsecure ?? false;
  const parsed = new URL(issuerUrl);

  const cascade: string[] = [
    buildInsertedURL(parsed, "oauth-authorization-server"),
    buildInsertedURL(parsed, "openid-configuration"),
    buildAppendedURL(parsed, "openid-configuration"),
  ];

  let lastAttempt: CascadeAttempt | undefined;
  for (const url of cascade) {
    const attempt = await tryFetchASMetadata(url, allowInsecure);
    lastAttempt = attempt;
    if (attempt.metadata !== undefined) {
      assertS256Support(attempt.metadata, attempt.url);
      return attempt.metadata;
    }
  }

  // All three steps missed. Surface the last error so logs can pinpoint
  // which step's failure was the proximate cause.
  const detail = lastAttempt?.error instanceof Error ? lastAttempt.error.message : "unknown error";
  throw new InvalidTokenError(
    `AS metadata discovery exhausted all 3 well-known URLs for issuer "${issuerUrl}". Last attempt (${lastAttempt?.url ?? "n/a"}): ${detail}`,
    lastAttempt?.error instanceof Error ? { cause: lastAttempt.error } : undefined,
  );
}

function assertS256Support(metadata: ASMetadata, url: string): void {
  if (!metadata.code_challenge_methods_supported.includes("S256")) {
    throw new InvalidTokenError(
      `AS metadata at ${url} does not advertise S256 in code_challenge_methods_supported (got ${JSON.stringify(metadata.code_challenge_methods_supported)})`,
    );
  }
}
