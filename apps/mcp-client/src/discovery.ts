// Client-side discovery: PRM → AS metadata cascade.
//
// Thin wrapper over the shared `fetchPRM` + `discoverASMetadata` helpers so
// `flow.ts` can call a single function per stage. Adds a couple of
// client-specific behaviors:
//
//   1. `resource_metadata` from the 401 `WWW-Authenticate` header is the
//      authoritative PRM URL — we use it directly instead of recomputing
//      via `resolvePRMUrl` (the server already did that work).
//   2. If `authorization_servers` is multi-valued, we pick the first per
//      spec §3.1 step 4. (Multi-AS selection UI is out of scope.)
//   3. Surface a soft warning when the AS does not advertise
//      `client_id_metadata_document_supported=true`; the server may still
//      accept CIMD, but the user should know.
//
// Spec: specs/client.md §3.1.

import type { ASMetadata, CanonicalURI, ProtectedResourceMetadata } from "@poc/shared";
import { canonicalize, discoverASMetadata, fetchPRM } from "@poc/shared";
import type { Logger } from "./log.js";

export interface DiscoveryResult {
  prm: ProtectedResourceMetadata;
  /** Canonical resource URI extracted from PRM.resource (already canonical per RFC 9728). */
  resource: CanonicalURI;
  /** First entry from PRM.authorization_servers, canonicalized. */
  authorizationServer: CanonicalURI;
  /** Validated AS metadata (S256 support already asserted by the shared helper). */
  asMetadata: ASMetadata;
}

/**
 * Run the PRM-then-AS-metadata discovery cascade. The PRM URL comes from the
 * 401 `WWW-Authenticate` header captured upstream — we don't recompute it.
 *
 * Throws on any failure (transport, content-type, schema, S256 missing).
 * Errors propagate to `flow.ts` for user-facing reporting.
 */
export async function runDiscovery(opts: {
  prmUrl: string;
  log: Logger;
}): Promise<DiscoveryResult> {
  const prm = await fetchPRM(opts.prmUrl);
  const resource = canonicalize(prm.resource);

  const firstAS = prm.authorization_servers[0];
  if (firstAS === undefined) {
    // Should be impossible — PRMSchema requires `authorization_servers` to
    // be non-empty. Guard anyway for completeness.
    throw new Error("PRM.authorization_servers was empty (schema invariant violation)");
  }
  const authorizationServer = canonicalize(firstAS);

  const asMetadata = await discoverASMetadata(authorizationServer);

  if (asMetadata.client_id_metadata_document_supported !== true) {
    // Per spec §3.1 step 6: warn but proceed. The IdP may still accept CIMD
    // URLs even when not advertised.
    opts.log.warn(
      { issuer: authorizationServer },
      "AS does not advertise client_id_metadata_document_supported=true",
    );
  }

  return { prm, resource, authorizationServer, asMetadata };
}
