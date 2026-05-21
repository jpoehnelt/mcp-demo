// OAuth `state` parameter (CSRF defense) per architecture invariant §4.14
// (state ≥128 bits) and shared-library §2.3.
//
// 32 random bytes base64url-encoded → 43 chars, ≥256 bits entropy (well above
// the 128-bit floor). Verification is constant-time on the raw byte buffers.

import { Buffer } from "node:buffer";
import { randomBytes, timingSafeEqual } from "node:crypto";
import type { StateParam } from "../types/brands.js";
import { unsafeBrand } from "../types/brands.js";

/**
 * Generate a fresh CSRF `state` token: 32 random bytes, base64url-encoded.
 */
export function generateState(): StateParam {
  const state = randomBytes(32).toString("base64url");
  return unsafeBrand<string, "StateParam">(state);
}

/**
 * Constant-time comparison of a received `state` to the expected value.
 *
 * `received` is intentionally typed as `string` because it arrives from the
 * outside world (query string) and has not yet been validated. The expected
 * value is branded to force callers to pass the canonical reference.
 *
 * Length mismatch returns `false` without throwing (`timingSafeEqual`
 * requires equal-length buffers — length is not secret).
 */
export function verifyState(received: string, expected: StateParam): boolean {
  const a = Buffer.from(received, "base64url");
  const b = Buffer.from(expected, "base64url");
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}
