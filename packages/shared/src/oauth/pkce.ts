// PKCE (RFC 7636) helpers per architecture invariant §4.4 (PKCE S256 required)
// and shared-library §2.2.
//
// Verifier: 32 random bytes, base64url-encoded → 43 chars from the unreserved
//   set (RFC 7636 §4.1), ≥256 bits entropy.
// Challenge: base64url(SHA-256(ASCII(verifier))), no padding (S256 method).
// Verification: constant-time compare via `crypto.timingSafeEqual` on the
//   raw SHA-256 byte buffers — no string comparison on user-supplied input.

import { Buffer } from "node:buffer";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { PKCEChallenge, PKCEVerifier } from "../types/brands.js";
import { unsafeBrand } from "../types/brands.js";

/**
 * Generate a PKCE verifier + S256 challenge pair.
 *
 * The verifier is 32 random bytes base64url-encoded (43 chars, unreserved
 * set only). The challenge is `base64url(SHA-256(verifier))` with no padding.
 */
export function generatePKCE(): {
  verifier: PKCEVerifier;
  challenge: PKCEChallenge;
  method: "S256";
} {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return {
    verifier: unsafeBrand<string, "PKCEVerifier">(verifier),
    challenge: unsafeBrand<string, "PKCEChallenge">(challenge),
    method: "S256",
  };
}

/**
 * Constant-time verification that `SHA-256(verifier)` matches the presented
 * challenge.
 *
 * Both inputs are branded, so callers cannot pass arbitrary strings without
 * first minting the brand. We still defensively decode the challenge as
 * base64url and compare raw byte buffers — never the string forms — so any
 * leak via early-exit string comparison is avoided.
 *
 * A length mismatch returns `false` without throwing (`timingSafeEqual`
 * requires equal-length buffers).
 */
export function verifyPKCE(verifier: PKCEVerifier, challenge: PKCEChallenge): boolean {
  const computed = createHash("sha256").update(verifier).digest();
  const presented = Buffer.from(challenge, "base64url");
  if (computed.length !== presented.length) {
    return false;
  }
  return timingSafeEqual(computed, presented);
}
