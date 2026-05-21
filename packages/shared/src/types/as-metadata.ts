// Authorization Server Metadata schema per RFC 8414 + OIDC Discovery.
// Source of truth: specs/shared-library.md §1.3.
//
// The schema validates the union of RFC 8414 and OIDC Discovery fields the
// demo relies on. The `code_challenge_methods_supported` S256 hard-fail is a
// downstream concern (slice 5) — here we just type the field as `string[]`.
//
// Like PRM, the schema is permissive about extension members: real-world AS
// metadata documents carry many implementation-specific keys we don't model.

import { z } from "zod";

export const ASMetadataSchema = z.object({
  issuer: z.string().url(),
  authorization_endpoint: z.string().url(),
  token_endpoint: z.string().url(),
  jwks_uri: z.string().url(),
  response_types_supported: z
    .array(z.string())
    .min(1, "response_types_supported must be non-empty"),
  code_challenge_methods_supported: z
    .array(z.string())
    .min(1, "code_challenge_methods_supported must be non-empty"),
  grant_types_supported: z.array(z.string()).optional(),
  scopes_supported: z.array(z.string()).optional(),
  token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
  client_id_metadata_document_supported: z.boolean().optional(),
  registration_endpoint: z.string().url().optional(),
});

export type ASMetadata = z.infer<typeof ASMetadataSchema>;

/**
 * Parses an untrusted JSON value as Authorization Server Metadata.
 * Throws `ZodError` on any violation.
 */
export function parseASMetadata(json: unknown): ASMetadata {
  return ASMetadataSchema.parse(json);
}
