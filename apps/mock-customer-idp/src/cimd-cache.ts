// CIMD fetch + DB-backed cache.
//
// Spec anchors:
//   - specs/authorization-server.md §4.2 (CIMD resolution flow + cache rules)
//   - specs/authorization-server.md §4.3 (SSRF protections)
//   - specs/architecture.md §4.9, §4.11 (canonical URL + URL-match invariant)
//   - specs/shared-library.md §2.6 (validator)
//
// Cache keying: canonical CIMD URL. Expiry: response `Cache-Control: max-age`
// when present, capped at 1 day; default 5 minutes per spec. A fresh row
// short-circuits the network entirely.

import type { CanonicalURI, ValidatedCIMDDocument } from "@poc/shared";
import {
  canonicalize,
  InvalidCIMDError,
  parseCIMDDocument,
  SSRFBlockedError,
  safeFetch,
  validateFetchedCIMD,
} from "@poc/shared";
import { ZodError } from "zod";
import type { DB } from "./db.js";
import type { IdPEnv } from "./env.js";
import type { Logger } from "./log.js";

/** Default cache TTL (5 minutes) when the response advertises no max-age. */
const DEFAULT_TTL_MS = 5 * 60 * 1000;
/** Hard cap on cache TTL (1 day) regardless of what the server advertised. */
const MAX_TTL_MS = 24 * 60 * 60 * 1000;
/** CIMD documents are tiny; cap fetch size at 100KB per §4.2. */
const MAX_FETCH_BYTES = 100_000;
/** Per-fetch timeout (5s per §4.2). */
const FETCH_TIMEOUT_MS = 5_000;

interface CimdCacheRow {
  url: string;
  document: string;
  fetched_at: number;
  expires_at: number;
}

export interface FetchCimdDeps {
  env: IdPEnv;
  db: DB;
  log: Logger;
}

/**
 * Fetch + validate a CIMD document, consulting the DB cache first.
 *
 * Throws (callers map to OAuth errors):
 *   - `InvalidCIMDError` — schema rejection, URL mismatch (invariant §4.9),
 *     cached row deserialization failure, malformed JSON.
 *   - `SSRFBlockedError` — `safeFetch` rejected the request (private IP,
 *     plaintext when not allowed, denied resolved address, etc).
 *   - Other errors from `safeFetch` (timeout, bad content-type, response
 *     too large). The route layer normalizes these to `invalid_client`.
 */
export async function fetchAndValidateCIMD(
  url: string,
  deps: FetchCimdDeps,
): Promise<ValidatedCIMDDocument> {
  // 1. Canonicalize the URL — every downstream comparison runs on canonical
  //    form. A malformed URL surfaces as `InvalidCanonicalURIError` (a
  //    sub-error of `invalid_request`), which the route layer will map.
  const canonicalUrl: CanonicalURI = canonicalize(url);

  // 2. Cache lookup. `expires_at > now` means the row is still fresh.
  const now = Date.now();
  const cached = readCache(deps.db, canonicalUrl, now);
  if (cached !== undefined) {
    deps.log.debug({ url: canonicalUrl }, "cimd cache hit");
    return cached;
  }

  // 3. Network fetch via the shared SSRF-safe path. The `allowInsecure`
  //    flag opens up `http://127.0.0.1` for the demo CLI; everything else
  //    stays denied.
  deps.log.debug({ url: canonicalUrl }, "cimd cache miss; fetching");
  const response = await safeFetch(canonicalUrl, {
    allowInsecure: deps.env.AS_DEV_ALLOW_INSECURE_CIMD,
    maxBytes: MAX_FETCH_BYTES,
    timeoutMs: FETCH_TIMEOUT_MS,
    expectContentType: "application/json",
  });

  // Non-2xx responses from a CIMD URL are treated as "not a CIMD" — we
  // can't trust a 404 / 5xx body to be a document.
  if (response.status < 200 || response.status >= 300) {
    throw new InvalidCIMDError(`CIMD fetch returned non-2xx status ${String(response.status)}`);
  }

  // 4. Parse + validate. Malformed JSON / schema violations bubble as
  //    `InvalidCIMDError` (or `ZodError` — we normalize that here).
  let json: unknown;
  try {
    json = JSON.parse(response.body);
  } catch (cause) {
    throw new InvalidCIMDError("CIMD response body is not valid JSON", { cause });
  }

  let validated: ValidatedCIMDDocument;
  try {
    validated = validateFetchedCIMD(canonicalUrl, json, {
      allowInsecure: deps.env.AS_DEV_ALLOW_INSECURE_CIMD,
    });
  } catch (err) {
    if (err instanceof ZodError) {
      // Normalize schema failures to InvalidCIMDError so route layer has
      // a uniform code path. Embed the issue summary for debugability —
      // not user-facing.
      throw new InvalidCIMDError(`CIMD schema rejection: ${err.message}`, { cause: err });
    }
    throw err;
  }

  // 5. Persist. Replace any prior row for the same URL (cache invalidation
  //    happens implicitly on the next miss).
  const ttlMs = ttlFromCacheControl(response.headers.get("cache-control"));
  const expiresAt = now + ttlMs;
  writeCache(deps.db, canonicalUrl, validated, now, expiresAt);

  return validated;
}

function readCache(db: DB, url: CanonicalURI, now: number): ValidatedCIMDDocument | undefined {
  const row = db
    .prepare("SELECT url, document, fetched_at, expires_at FROM cimd_cache WHERE url = ?")
    .get(url) as CimdCacheRow | undefined;
  if (row === undefined) return undefined;
  if (row.expires_at <= now) return undefined;
  try {
    const parsed = JSON.parse(row.document) as unknown;
    // Round-trip through the schema parser so a cache row that was somehow
    // corrupted (or written by a prior schema version) is treated as a
    // miss rather than silently returned. We deliberately do NOT re-run
    // `validateFetchedCIMD` — the URL match was checked at write time and
    // the canonical URL on disk matches the lookup key by construction.
    const doc = parseCIMDDocument(parsed, { allowInsecure: true });
    return {
      ...doc,
      // `parseCIMDDocument` returns a `CIMDDocument` whose `client_id` is a
      // bare string. The cached row was written from a `ValidatedCIMDDocument`,
      // so the value already canonicalizes equal to the lookup key.
      // Re-cast to the validated brand.
      client_id: url as unknown as ValidatedCIMDDocument["client_id"],
    };
  } catch {
    return undefined;
  }
}

function writeCache(
  db: DB,
  url: CanonicalURI,
  doc: ValidatedCIMDDocument,
  fetchedAt: number,
  expiresAt: number,
): void {
  db.prepare(
    "INSERT INTO cimd_cache (url, document, fetched_at, expires_at) " +
      "VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(url) DO UPDATE SET document = excluded.document, " +
      "fetched_at = excluded.fetched_at, expires_at = excluded.expires_at",
  ).run(url, JSON.stringify(doc), fetchedAt, expiresAt);
}

/**
 * Derive a TTL from a `Cache-Control` header value. Honors `max-age`,
 * ignores `no-store` / `no-cache` (we always cache for at least the
 * default — a CIMD server cannot opt out of caching). Capped at 1 day.
 *
 * Exported only for tests.
 */
export function ttlFromCacheControl(header: string | null): number {
  if (header === null || header.length === 0) return DEFAULT_TTL_MS;
  const directives = header.split(",");
  for (const raw of directives) {
    const directive = raw.trim().toLowerCase();
    if (directive.startsWith("max-age=")) {
      const value = directive.slice("max-age=".length);
      const seconds = Number.parseInt(value, 10);
      if (!Number.isFinite(seconds) || seconds <= 0) continue;
      const ms = seconds * 1000;
      return Math.min(ms, MAX_TTL_MS);
    }
  }
  return DEFAULT_TTL_MS;
}

/** Re-exported for the route layer's instanceof checks. */
export { InvalidCIMDError, SSRFBlockedError };
