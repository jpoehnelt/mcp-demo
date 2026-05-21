// JWT verifier per shared-library §2.4 and architecture invariants §4.1
// (audience), §4.2 (issuer), §4.3 (MAC-alg rejection).
//
// Wraps `jose.createRemoteJWKSet` + `jose.jwtVerify`. The remote JWKS set
// caches keys in-process per jose's own LRU; we surface its TTL knob through
// `jwksCacheTTLms` (default 3600 s, capped at 24 h per spec).
//
// Algorithm allowlist: `RS256`, `ES256`, `EdDSA`. `HS*` and `alg: "none"` are
// rejected — jose already refuses `alg: "none"` in `jwtVerify`, and we
// double-block by passing an `algorithms` allowlist.
//
// Claim verification order (matches spec §2.4):
//   1. signature              — jose `jwtVerify`
//   2. iss (canonical compare) — `equalsCanonical`
//   3. aud (containment)       — `equalsCanonical` over each candidate
//   4. exp                     — jose
//   5. nbf (if present)        — jose
//   6. iat                     — schema requires `iat: number`
// jose handles 1/4/5 internally; we layer canonical-form checks on 2/3
// because jose compares exact strings.

import { createRemoteJWKSet, errors as joseErrors, jwtVerify } from "jose";
import {
  InvalidAudienceError,
  InvalidIssuerError,
  InvalidTokenError,
  TokenExpiredError,
} from "../errors.js";
import type { CanonicalURI } from "../types/brands.js";
import type { TokenClaims } from "../types/token-claims.js";
import { parseTokenClaims } from "../types/token-claims.js";
import { equalsCanonical } from "./canonical-uri.js";

const ALLOWED_ALGORITHMS = ["RS256", "ES256", "EdDSA"] as const;
const DEFAULT_CACHE_TTL_MS = 3600 * 1000;
const MAX_CACHE_TTL_MS = 24 * 3600 * 1000;
const CLOCK_TOLERANCE_SECONDS = 30;

export interface JWTVerifierOptions {
  /** Expected issuer (canonical form). The verifier compares canonical-form-only. */
  issuer: CanonicalURI;
  /** Expected audience (canonical form). Token `aud` must contain this after canonicalization. */
  audience: CanonicalURI;
  /**
   * JWKS cache TTL (milliseconds). Defaults to 3600 s. Values >24 h are clamped.
   * The underlying jose remote JWKS set honors `cacheMaxAge`.
   */
  jwksCacheTTLms?: number;
  /**
   * JWKS endpoint URL. Slice 5 deliberately requires the caller to supply
   * this — discovery happens in `discoverASMetadata` and the result is passed
   * to the verifier factory. Tests inject an in-process JWKS URL.
   */
  jwksUri: string;
}

export interface JWTVerifier {
  verify(token: string): Promise<TokenClaims>;
}

function clampCacheTTL(ms: number | undefined): number {
  if (ms === undefined) return DEFAULT_CACHE_TTL_MS;
  if (!Number.isFinite(ms) || ms <= 0) return DEFAULT_CACHE_TTL_MS;
  if (ms > MAX_CACHE_TTL_MS) return MAX_CACHE_TTL_MS;
  return ms;
}

/**
 * Build a JWT verifier bound to a specific issuer + audience + JWKS URI.
 *
 * The returned `verify` function:
 *   * Rejects MAC algorithms (`HS*`) and `alg: "none"` — invariant §4.3.
 *   * Verifies signature against the JWKS, then compares `iss` and `aud` in
 *     canonical form (defeats trivial Unicode/case/port aliases).
 *   * Throws typed errors per slice 1.
 */
export function createJWTVerifier(opts: JWTVerifierOptions): JWTVerifier {
  const cacheMaxAge = clampCacheTTL(opts.jwksCacheTTLms);
  let jwksUrl: URL;
  try {
    jwksUrl = new URL(opts.jwksUri);
  } catch (cause) {
    throw new InvalidTokenError(`Invalid jwks_uri: ${opts.jwksUri}`, { cause });
  }
  const remoteJWKS = createRemoteJWKSet(jwksUrl, { cacheMaxAge });

  return {
    async verify(token: string): Promise<TokenClaims> {
      if (typeof token !== "string" || token.length === 0) {
        throw new InvalidTokenError("Token must be a non-empty string");
      }

      let result: Awaited<ReturnType<typeof jwtVerify>>;
      try {
        result = await jwtVerify(token, remoteJWKS, {
          algorithms: [...ALLOWED_ALGORITHMS],
          clockTolerance: CLOCK_TOLERANCE_SECONDS,
        });
      } catch (cause) {
        // Map jose's typed errors to our hierarchy. The order matters: more
        // specific cases first.
        if (cause instanceof joseErrors.JWTExpired) {
          throw new TokenExpiredError("Token expired (exp in past)", { cause });
        }
        if (cause instanceof joseErrors.JWSSignatureVerificationFailed) {
          throw new InvalidTokenError("JWS signature verification failed", { cause });
        }
        if (cause instanceof joseErrors.JOSEAlgNotAllowed) {
          // [INV-4.3] — HS* / alg:none / any other disallowed alg.
          throw new InvalidTokenError("Disallowed JWT alg", { cause });
        }
        if (cause instanceof joseErrors.JWTClaimValidationFailed) {
          // jose surfaces `nbf` / `iat` / `aud` / `iss` claim failures here,
          // but we re-validate `iss` and `aud` ourselves below for canonical
          // semantics, so anything jose flags here is something we did not
          // intercept (e.g. `nbf` in the future).
          throw new InvalidTokenError(`JWT claim validation failed: ${cause.message}`, { cause });
        }
        if (cause instanceof joseErrors.JOSEError) {
          throw new InvalidTokenError(`JWT verification failed: ${cause.message}`, { cause });
        }
        throw new InvalidTokenError("JWT verification failed", { cause });
      }

      // jose returned a parsed payload + verified signature + verified exp/nbf
      // under our clock tolerance. Now layer:
      //   * payload shape (`parseTokenClaims`)
      //   * iss canonical equality
      //   * aud canonical containment
      const claims = parseTokenClaims(result.payload);

      // [INV-4.2] — issuer must match in canonical form.
      if (!equalsCanonical(claims.iss, opts.issuer)) {
        throw new InvalidIssuerError(
          `Issuer mismatch: token iss "${claims.iss}" ≠ expected "${opts.issuer}"`,
        );
      }

      // [INV-4.1] — audience containment after canonicalization. `aud` may be
      // a string or array per RFC 7519 §4.1.3.
      const audValues = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
      let matched = false;
      for (const candidate of audValues) {
        // `equalsCanonical` will throw if a candidate is malformed; we treat
        // that as a non-matching candidate rather than letting it bubble — a
        // malformed entry in `aud` should not produce an SSRF/canonicalize
        // error to the caller.
        try {
          if (equalsCanonical(candidate, opts.audience)) {
            matched = true;
            break;
          }
        } catch {
          // Skip malformed candidate. Loop continues.
        }
      }
      if (!matched) {
        throw new InvalidAudienceError(
          `Audience mismatch: token aud ${JSON.stringify(claims.aud)} does not contain "${opts.audience}"`,
        );
      }

      return claims;
    },
  };
}
