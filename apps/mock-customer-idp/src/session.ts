// HMAC-signed cookie session for the /authorize consent flow.
//
// Spec anchor: specs/authorization-server.md §4.5 ("hidden inputs carrying
// request params + a signed session cookie") and §8 (Cookie / Set-Cookie
// header values are redacted — see log.ts).
//
// The session secret is process-local: a fresh 32 random bytes generated at
// module import time. That means cookies issued by one process do not
// validate in another (intentional — the consent flow is single-process).
// For a multi-instance deployment, swap the module-level secret for a
// shared KMS-backed value.
//
// Format: `<base64url(JSON payload)>.<base64url(HMAC-SHA256(payload))>`.
// HMAC is computed over the raw base64url-encoded payload string (not the
// decoded JSON) so verification is byte-stable across JSON serialization
// idiosyncrasies.
//
// Production note: cookies set by this module DO NOT carry the `Secure`
// attribute because the demo runs on HTTP localhost. A real deployment MUST
// add `Secure` (the spec mandates it; see §4.5).

import { Buffer } from "node:buffer";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** Cookie name carrying the signed payload. Scoped to `/authorize`. */
export const SESSION_COOKIE_NAME = "as_consent_session";

/** Session lifetime in milliseconds (5 minutes per spec). */
export const SESSION_TTL_MS = 5 * 60 * 1000;

/**
 * Fresh per-process secret. Re-generated on every boot — there is no
 * persistent secret because consent sessions are inherently short-lived
 * (5 minutes) and never need to survive a restart.
 */
const SESSION_SECRET: Buffer = randomBytes(32);

/**
 * Payload shape persisted in the cookie. The consent POST handler reads
 * back exactly these fields and never trusts a value sourced from the form
 * for security-relevant decisions (form values are display-only).
 */
export interface ConsentSessionPayload {
  /** Canonical CIMD URL (the OAuth `client_id`). */
  clientId: string;
  /** Canonical `redirect_uri`. */
  redirectUri: string;
  /** Original `state` (echoed back on redirect). */
  state: string;
  /** PKCE `code_challenge` (S256). */
  codeChallenge: string;
  /** Always `S256` (only method this AS accepts). */
  codeChallengeMethod: "S256";
  /** Granted scopes (space-delimited). */
  scope: string;
  /** Canonical `resource` URI (RFC 8707). */
  resource: string;
  /** CSRF token tied to the form. */
  csrf: string;
  /** Issued-at epoch ms. Used for TTL enforcement. */
  iat: number;
}

function hmac(payloadB64: string): Buffer {
  return createHmac("sha256", SESSION_SECRET).update(payloadB64).digest();
}

/**
 * Serialize + sign a session payload. Returns the cookie value (no
 * `Set-Cookie` attributes — see `buildSetCookieHeader`).
 */
export function signSession(payload: ConsentSessionPayload): string {
  const json = JSON.stringify(payload);
  const payloadB64 = Buffer.from(json, "utf8").toString("base64url");
  const sig = hmac(payloadB64).toString("base64url");
  return `${payloadB64}.${sig}`;
}

/**
 * Reasons a session cookie can fail to validate. Surfaced so callers can
 * distinguish "no cookie at all" (re-render the form) from "tampered"
 * (refuse the request).
 */
export type SessionVerifyError =
  | { ok: false; reason: "missing" }
  | { ok: false; reason: "malformed" }
  | { ok: false; reason: "bad_signature" }
  | { ok: false; reason: "expired" }
  | { ok: false; reason: "invalid_payload" };

export type SessionVerifyResult = { ok: true; payload: ConsentSessionPayload } | SessionVerifyError;

/**
 * Verify + parse a session cookie value. HMAC compared in constant time.
 * Expired sessions (older than `SESSION_TTL_MS`) are rejected even with a
 * valid signature — `iat` is part of the signed payload so it cannot be
 * forged separately.
 *
 * `now` is injectable for tests so we can simulate expiry deterministically.
 */
export function verifySession(
  cookieValue: string | undefined,
  now: number = Date.now(),
): SessionVerifyResult {
  if (cookieValue === undefined || cookieValue.length === 0) {
    return { ok: false, reason: "missing" };
  }
  const dot = cookieValue.indexOf(".");
  if (dot === -1 || dot === 0 || dot === cookieValue.length - 1) {
    return { ok: false, reason: "malformed" };
  }
  const payloadB64 = cookieValue.slice(0, dot);
  const sigB64 = cookieValue.slice(dot + 1);

  const expectedSig = hmac(payloadB64);
  let presentedSig: Buffer;
  try {
    presentedSig = Buffer.from(sigB64, "base64url");
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (presentedSig.length !== expectedSig.length) {
    return { ok: false, reason: "bad_signature" };
  }
  if (!timingSafeEqual(presentedSig, expectedSig)) {
    return { ok: false, reason: "bad_signature" };
  }

  let parsed: unknown;
  try {
    const json = Buffer.from(payloadB64, "base64url").toString("utf8");
    parsed = JSON.parse(json);
  } catch {
    return { ok: false, reason: "malformed" };
  }

  if (!isPayload(parsed)) {
    return { ok: false, reason: "invalid_payload" };
  }
  if (now - parsed.iat > SESSION_TTL_MS) {
    return { ok: false, reason: "expired" };
  }
  return { ok: true, payload: parsed };
}

function isPayload(value: unknown): value is ConsentSessionPayload {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.clientId === "string" &&
    typeof v.redirectUri === "string" &&
    typeof v.state === "string" &&
    typeof v.codeChallenge === "string" &&
    v.codeChallengeMethod === "S256" &&
    typeof v.scope === "string" &&
    typeof v.resource === "string" &&
    typeof v.csrf === "string" &&
    typeof v.iat === "number" &&
    Number.isFinite(v.iat)
  );
}

/**
 * Build a `Set-Cookie` header value with the spec-mandated attributes:
 * `HttpOnly`, `SameSite=Lax`, `Path=/authorize`. Not `Secure` in dev
 * (HTTP localhost) — a production deployment MUST add `Secure`.
 *
 * `Max-Age` is in seconds (cookie convention) and matches `SESSION_TTL_MS`.
 */
export function buildSetCookieHeader(value: string): string {
  const maxAgeSec = Math.floor(SESSION_TTL_MS / 1000);
  return `${SESSION_COOKIE_NAME}=${value}; Path=/authorize; HttpOnly; SameSite=Lax; Max-Age=${String(maxAgeSec)}`;
}

/**
 * Generate a fresh CSRF token (32 random bytes, base64url) for embedding in
 * the consent form. The same value lives in the signed cookie so a forged
 * POST body cannot redirect the user.
 */
export function generateCsrfToken(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * Parse a request `Cookie` header for the consent session cookie. Returns
 * `undefined` if the header is absent or the cookie isn't present.
 *
 * We do not use a general-purpose cookie parser because the consent flow
 * only needs one specific cookie and a hand-rolled scan keeps the surface
 * area small.
 */
export function readSessionCookie(cookieHeader: string | undefined): string | undefined {
  if (cookieHeader === undefined || cookieHeader.length === 0) return undefined;
  const parts = cookieHeader.split(";");
  for (const part of parts) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const name = trimmed.slice(0, eq);
    if (name === SESSION_COOKIE_NAME) {
      return trimmed.slice(eq + 1);
    }
  }
  return undefined;
}
