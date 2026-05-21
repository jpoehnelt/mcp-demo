// Token endpoint POST helper.
//
// Spec: specs/client.md §3.3 (form fields + resource on both authorize and
// token), §4 (security: tokens treated as opaque even though they happen to
// be JWTs).
//
// The response is validated with a defensive zod schema — the AS could in
// principle return an `error` JSON body with HTTP 400, which we surface with
// a typed `TokenError` so the flow can decide whether to retry or bail.

import type { ASMetadata, PKCEVerifier } from "@poc/shared";
import { z } from "zod";

const TokenResponseSchema = z.object({
  access_token: z.string().min(1),
  token_type: z.string(),
  expires_in: z.number().int().positive().optional(),
  scope: z.string().optional(),
  refresh_token: z.string().optional(),
});

export type TokenResponse = z.infer<typeof TokenResponseSchema>;

const TokenErrorBodySchema = z.object({
  error: z.string().min(1),
  error_description: z.string().optional(),
});

/**
 * Typed failure surface from POST /token. Carries the OAuth error code so
 * the flow can map e.g. `invalid_grant` to a friendly message.
 */
export class TokenError extends Error {
  override readonly name = "TokenError";
  readonly status: number;
  readonly errorCode: string;
  readonly errorDescription: string | undefined;
  constructor(
    status: number,
    errorCode: string,
    errorDescription: string | undefined,
    message: string,
  ) {
    super(message);
    this.status = status;
    this.errorCode = errorCode;
    this.errorDescription = errorDescription;
  }
}

export interface TokenExchangeInput {
  asMetadata: ASMetadata;
  code: string;
  clientId: string;
  redirectUri: string;
  codeVerifier: PKCEVerifier;
  resource: string;
}

/**
 * Exchange an authorization code for an access (and refresh) token.
 *
 * Sends the form-encoded body to the AS-advertised `token_endpoint`. The
 * `resource` parameter is REQUIRED on both authorize and token requests per
 * RFC 8707 + architecture invariant §4.5 — keeping it in this function's
 * signature makes the contract impossible to miss at call sites.
 */
export async function exchangeCodeForToken(input: TokenExchangeInput): Promise<TokenResponse> {
  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("code", input.code);
  body.set("client_id", input.clientId);
  body.set("redirect_uri", input.redirectUri);
  body.set("code_verifier", input.codeVerifier);
  body.set("resource", input.resource);

  const res = await fetch(input.asMetadata.token_endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: body.toString(),
  });

  // Read once. We branch on status afterwards.
  const text = await res.text();

  if (res.status !== 200) {
    // Try to parse a structured OAuth error body; fall back to plain text.
    let errorCode = "token_exchange_failed";
    let errorDescription: string | undefined;
    try {
      const parsed = TokenErrorBodySchema.parse(JSON.parse(text));
      errorCode = parsed.error;
      errorDescription = parsed.error_description;
    } catch {
      // Non-JSON body — leave the defaults.
    }
    throw new TokenError(
      res.status,
      errorCode,
      errorDescription,
      `token endpoint returned HTTP ${String(res.status)} (${errorCode}${
        errorDescription !== undefined ? `: ${errorDescription}` : ""
      })`,
    );
  }

  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new TokenError(
      res.status,
      "invalid_response",
      undefined,
      "token response not valid JSON",
    );
  }
  return TokenResponseSchema.parse(json);
}
