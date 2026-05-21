// JWT access-token minting. Spec anchors:
//   - specs/authorization-server.md §5.1 step 7 (claims), step 8 (signing)
//   - specs/architecture.md §4.5 (aud single canonical string)
//   - specs/architecture.md §3.2 (asymmetric signing, kid in header)
//
// Tokens are signed via `jose.SignJWT`. The header MUST carry `kid` so the
// resource server can pick the right key from JWKS without a roundtrip per
// request. `alg: "none"` is impossible — `SignJWT.sign` requires an
// asymmetric `CryptoKey` and jose refuses unsecured tokens via this API.

import { randomUUID } from "node:crypto";
import type { AccessTokenJWT, CanonicalURI, ClientId, ScopeString } from "@poc/shared";
import { SignJWT } from "jose";
import type { IdPEnv } from "./env.js";
import type { SigningKeyset } from "./keys.js";

export interface MintAccessTokenArgs {
  env: IdPEnv;
  keys: SigningKeyset;
  sub: string;
  clientId: ClientId;
  resource: CanonicalURI;
  scope: ScopeString;
}

export interface MintedAccessToken {
  token: AccessTokenJWT;
  expiresIn: number;
}

/**
 * Mint a signed JWT access token for the authorization-code grant.
 *
 * Claims (§5.1 step 7):
 *   iss        = canonical AS_ISSUER_URL
 *   aud        = canonical resource (string, single-valued per [INV-4.5])
 *   sub        = from the auth-code row (caller passes through)
 *   client_id  = from the auth-code row
 *   scope      = granted scopes (space-delimited)
 *   exp        = now + AS_TOKEN_TTL_SEC
 *   iat        = now
 *   nbf        = now
 *   jti        = random UUID v4
 *
 * Header: `alg = keys.alg`, `kid = keys.kid`. `alg: "none"` cannot be emitted
 * through this path — `SignJWT.sign` requires an asymmetric key.
 */
export async function mintAccessToken(args: MintAccessTokenArgs): Promise<MintedAccessToken> {
  const nowSec = Math.floor(Date.now() / 1000);
  const expSec = nowSec + args.env.AS_TOKEN_TTL_SEC;

  const jwt = await new SignJWT({
    client_id: args.clientId,
    scope: args.scope,
  })
    .setProtectedHeader({ alg: args.keys.alg, kid: args.keys.kid })
    .setIssuer(args.env.AS_ISSUER_URL)
    .setAudience(args.resource)
    .setSubject(args.sub)
    .setIssuedAt(nowSec)
    .setNotBefore(nowSec)
    .setExpirationTime(expSec)
    .setJti(randomUUID())
    .sign(args.keys.privateKey);

  // `AccessTokenJWT` is a phantom-typed brand on `string` (shared brands
  // module). We attach the brand here because this is the only path that
  // produces a signed access token in the IdP — equivalent to `unsafeBrand`
  // in the shared package, kept local because the brand minting helper is
  // intentionally not re-exported from `@poc/shared` (see brands.ts header).
  return {
    token: jwt as AccessTokenJWT,
    expiresIn: args.env.AS_TOKEN_TTL_SEC,
  };
}
