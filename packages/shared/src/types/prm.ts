// Protected Resource Metadata schema per RFC 9728 and shared-library §1.2.
//
// The schema validates the document's intrinsic shape only. Canonical URI
// equality and discovery (`.well-known/oauth-protected-resource`) live in
// slice 5 — this layer only checks types/required fields/defaults.
//
// Unlike the CIMD schema, PRM is NOT strict: RFC 9728 explicitly permits
// implementation-defined extension members.

import { z } from "zod";

export const PRMSchema = z.object({
  resource: z.string().min(1),
  authorization_servers: z
    .array(z.string().min(1))
    .min(1, "authorization_servers must be non-empty"),
  scopes_supported: z.array(z.string()).optional(),
  bearer_methods_supported: z.array(z.string()).default(["header"]),
  resource_documentation: z.string().optional(),
});

export type ProtectedResourceMetadata = z.infer<typeof PRMSchema>;

/**
 * Parses an untrusted JSON value as a Protected Resource Metadata document.
 * Throws `ZodError` on any violation.
 */
export function parsePRM(json: unknown): ProtectedResourceMetadata {
  return PRMSchema.parse(json);
}
