// JWT access-token claims schema per shared-library §1.4.
//
// This module only types and parses the JSON payload after `jose` has done
// signature/exp/nbf/iat verification (slice 5). The schema therefore does NOT
// re-check time-sensitive claims (`exp`, `iat`, `nbf`) — it only asserts they
// are numbers in the JWT NumericDate sense. `aud` may be a string or array
// per RFC 7519 §4.1.3.

import { z } from "zod";

export const TokenClaimsSchema = z.object({
  iss: z.string().min(1),
  sub: z.string().min(1),
  aud: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
  exp: z.number(),
  iat: z.number(),
  nbf: z.number().optional(),
  jti: z.string().min(1),
  scope: z.string(),
  client_id: z.string().min(1),
});

export type TokenClaims = z.infer<typeof TokenClaimsSchema>;

/**
 * Parses an untrusted JSON value as a JWT access-token claims set.
 * Throws `ZodError` on any violation.
 */
export function parseTokenClaims(json: unknown): TokenClaims {
  return TokenClaimsSchema.parse(json);
}
