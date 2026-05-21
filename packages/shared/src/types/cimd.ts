// CIMD (Client ID Metadata Document) schema.
// Source of truth: specs/shared-library.md §1.1 and CIMD draft-01 §4.
//
// The schema is strict (zod v4 `.strict()`): unknown top-level keys are
// rejected. The cross-cutting `client_id` ↔ fetch-URL canonical equality
// check lives in slice 5 (`oauth/cimd-validator.ts`) — this module only
// validates the document's intrinsic shape.
//
// `client_id` and each `redirect_uri` enforce the architecture §6 scheme rules:
//   * `https://` always allowed
//   * `http://127.0.0.1[:port]` allowed only when `opts.allowInsecure === true`
//     (and ONLY for `client_id`; redirect URIs always permit the loopback
//     literal, never `http://localhost` — see invariant §4.10)
//   * a bare domain (path empty or `/`) is rejected for `client_id` so the
//     document URL is identifiable.

import { z } from "zod";

const GRANT_TYPES = ["authorization_code", "refresh_token"] as const;

/**
 * URL string check that always permits `https://` and conditionally permits
 * the literal loopback `http://127.0.0.1[:port]`. Used for `client_id`.
 *
 * `pathRequired === true` rejects a bare domain (empty path or `/`).
 */
function isAllowedClientUrl(value: string, allowInsecure: boolean): boolean {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.protocol === "https:") {
    return parsed.pathname !== "" && parsed.pathname !== "/";
  }
  if (parsed.protocol === "http:" && allowInsecure && parsed.hostname === "127.0.0.1") {
    return parsed.pathname !== "" && parsed.pathname !== "/";
  }
  return false;
}

/**
 * Redirect URI check: `https://` OR `http://127.0.0.1[:port]`. The literal
 * `http://localhost` is rejected — localhost resolves dynamically and breaks
 * the SSRF model (invariant §4.10).
 */
function isAllowedRedirectUri(value: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.protocol === "https:") {
    return true;
  }
  if (parsed.protocol === "http:" && parsed.hostname === "127.0.0.1") {
    return true;
  }
  return false;
}

/**
 * Build the CIMD schema bound to an `allowInsecure` flag. The flag only
 * influences whether `client_id` may use the loopback literal — every other
 * field is scheme-flag-independent.
 */
function buildCIMDSchema(allowInsecure: boolean) {
  return z
    .object({
      client_id: z.string().refine((v) => isAllowedClientUrl(v, allowInsecure), {
        message: allowInsecure
          ? "client_id must be https:// or http://127.0.0.1[:port] with a non-empty path"
          : "client_id must be https:// with a non-empty path",
      }),
      client_name: z.string().min(1),
      client_uri: z.string().url().optional(),
      logo_uri: z.string().url().optional(),
      redirect_uris: z
        .array(
          z
            .string()
            .refine(
              isAllowedRedirectUri,
              "redirect_uri must be https:// or http://127.0.0.1[:port]",
            ),
        )
        .min(1, "redirect_uris must contain at least one entry"),
      grant_types: z.array(z.enum(GRANT_TYPES)).default(["authorization_code"]),
      response_types: z.array(z.literal("code")).default(["code"]),
      token_endpoint_auth_method: z.literal("none").default("none"),
      scope: z.string().optional(),
    })
    .strict();
}

// Re-derive the public schema and type from the default (secure) variant so
// downstream consumers have a stable `z.infer` target. The runtime parser
// rebuilds with the actual flag — the type is identical either way because
// `allowInsecure` only changes the refinement, not the shape.
export const CIMDDocumentSchema = buildCIMDSchema(false);
export type CIMDDocument = z.infer<typeof CIMDDocumentSchema>;

/**
 * Parses an untrusted JSON value as a CIMD document. Throws `ZodError` on
 * any violation, including unknown top-level keys (strict mode).
 */
export function parseCIMDDocument(json: unknown, opts: { allowInsecure: boolean }): CIMDDocument {
  return buildCIMDSchema(opts.allowInsecure).parse(json);
}
