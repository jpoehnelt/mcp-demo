// CIMD validator per shared-library §2.6 and architecture invariant §4.9.
//
// `parseCIMDDocument` (slice 2) handles the schema-level checks: required
// fields, scheme rules for `client_id` / `redirect_uris`, path-required for
// `client_id`, strict unknown-key rejection. This module layers the
// cross-cutting equality check: the URL the document was fetched from
// (canonicalized) MUST byte-equal the document's `client_id` (canonicalized).
//
// The check defeats two attacks:
//   1. Semantic alias (e.g. uppercase host) — `canonicalize` normalizes.
//   2. Literal mismatch (e.g. the fetched URL is `/cimd/a` but `client_id`
//      claims `/cimd/b`) — byte-equality after canonicalization catches it.

import { InvalidCIMDError } from "../errors.js";
import type { CanonicalURI, ClientId } from "../types/brands.js";
import { unsafeBrand } from "../types/brands.js";
import type { CIMDDocument } from "../types/cimd.js";
import { parseCIMDDocument } from "../types/cimd.js";
import { canonicalize, equalsCanonical } from "./canonical-uri.js";

/**
 * The validated document with `client_id` rewritten to its canonical form.
 * Downstream code uses this as the authoritative client identity — anywhere
 * a `ClientId` brand is required, this is the value to mint.
 */
export interface ValidatedCIMDDocument extends Omit<CIMDDocument, "client_id"> {
  client_id: ClientId;
}

/**
 * Validate a CIMD document fetched from `url`.
 *
 * Steps (per spec §2.6):
 *   1. Schema-parse via `parseCIMDDocument` (slice 2).
 *   2. Canonicalize both `url` and the parsed `client_id`; reject mismatch.
 *      [INV-4.9]
 *   3. Re-assert that the canonical URL has a non-empty path. (The schema
 *      already enforces this for `client_id`; this is defense-in-depth in
 *      case `url` itself is bare-domain.)
 *   4. The schema already restricts `redirect_uris` to `https://` or
 *      `http://127.0.0.1[:port]`. We do not re-validate here.
 *   5. Return the document with `client_id` rewritten to its canonical form
 *      and minted as a `ClientId` brand.
 */
export function validateFetchedCIMD(
  url: string,
  json: unknown,
  opts: { allowInsecure: boolean },
): ValidatedCIMDDocument {
  const parsed = parseCIMDDocument(json, opts);

  let canonicalUrl: CanonicalURI;
  try {
    canonicalUrl = canonicalize(url);
  } catch (cause) {
    throw new InvalidCIMDError(`CIMD fetch URL is not a valid canonical URI: ${url}`, {
      cause,
    });
  }

  let canonicalClientId: CanonicalURI;
  try {
    canonicalClientId = canonicalize(parsed.client_id);
  } catch (cause) {
    throw new InvalidCIMDError(`CIMD client_id is not a valid canonical URI: ${parsed.client_id}`, {
      cause,
    });
  }

  // [INV-4.9] — canonical byte-equality of fetch URL and client_id.
  if (!equalsCanonical(canonicalUrl, canonicalClientId)) {
    throw new InvalidCIMDError(
      `CIMD client_id (${canonicalClientId}) does not match fetch URL (${canonicalUrl})`,
    );
  }

  // Defense-in-depth: the canonical URL MUST carry a non-empty path. The
  // schema enforces this on `client_id`; since we just proved they're
  // byte-equal, this is also true of the fetch URL — assert it explicitly
  // so a future schema relaxation doesn't silently break the invariant.
  const parsedURL = new URL(canonicalUrl);
  if (parsedURL.pathname === "" || parsedURL.pathname === "/") {
    throw new InvalidCIMDError(
      `CIMD URL must have a non-empty path component, got ${canonicalUrl}`,
    );
  }

  // Mint the canonical client_id as a `ClientId` brand. `ClientId` is a
  // sub-brand of `CanonicalURI` (see types/brands.ts), so the underlying
  // value carries both phantom types.
  const clientId = unsafeBrand<CanonicalURI, "ClientId">(canonicalClientId);

  return {
    ...parsed,
    client_id: clientId,
  };
}
