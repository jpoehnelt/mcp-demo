// GET /authorize + POST /authorize/consent.
//
// Spec anchors:
//   - specs/authorization-server.md §4 (entire section)
//   - specs/architecture.md §4.4 (PKCE), §4.5 (single resource),
//     §4.9 (CIMD URL match), §4.10 (redirect_uri exact match),
//     §4.14 (state present + echoed)
//
// Error-handling contract:
//   - If we can't trust `redirect_uri` yet (parse failure or CIMD failure),
//     return 400 with a plain message.
//   - Once `redirect_uri` is validated against the CIMD, every subsequent
//     failure becomes a 302 to that URI with `error=...&state=...`
//     per OAuth 2.1 §4.1.2.1.

import { Buffer } from "node:buffer";
import { randomBytes, timingSafeEqual } from "node:crypto";
import type { CanonicalURI, ValidatedCIMDDocument } from "@poc/shared";
import {
  canonicalize,
  InvalidCanonicalURIError,
  InvalidCIMDError,
  InvalidContentTypeError,
  MaxBytesExceededError,
  SSRFBlockedError,
} from "@poc/shared";
import type { Context } from "hono";
import { type ZodError, z } from "zod";
import type { IdPApp, IdPVariables } from "../app.js";
import { fetchAndValidateCIMD } from "../cimd-cache.js";
import { renderConsentHtml } from "../consent.js";
import type { DB } from "../db.js";
import type { IdPEnv } from "../env.js";
import {
  buildSetCookieHeader,
  type ConsentSessionPayload,
  generateCsrfToken,
  readSessionCookie,
  signSession,
  verifySession,
} from "../session.js";

// Scopes the IdP advertises in `scopes_supported` (§3.1). The route layer
// is the only consumer of the actual list; we keep it inline so a typo in
// metadata doesn't silently desync from authorize validation.
const SCOPES_SUPPORTED = ["weather:read", "weather:premium"] as const;
type SupportedScope = (typeof SCOPES_SUPPORTED)[number];
const SUPPORTED_SCOPE_SET: ReadonlySet<string> = new Set(SCOPES_SUPPORTED);

/** Authorization code lifetime (§4.6). */
const AUTH_CODE_TTL_MS = 60_000;

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

/**
 * Per-parameter zod refinements. We accept loosely-typed input and produce
 * the canonical form for fields that need it. `client_id` is validated as a
 * URL but NOT canonicalized here — `fetchAndValidateCIMD` does the canonical
 * comparison itself.
 *
 * `resource` is special-cased at the query-parser layer: zod cannot detect
 * "this parameter appeared twice in the query string" because URLSearchParams
 * collapses duplicates into an array. We check for the array shape upstream.
 */
function buildAuthorizeSchema(env: IdPEnv) {
  return z.object({
    response_type: z.literal("code", {
      message: "response_type must be 'code'",
    }),
    client_id: z
      .string()
      .min(1, "client_id is required")
      .refine((v) => isValidClientIdShape(v, env.AS_DEV_ALLOW_INSECURE_CIMD), {
        message:
          "client_id must be an absolute https:// URL with a non-empty path (or http://127.0.0.1[:port] in dev)",
      }),
    redirect_uri: z.string().url("redirect_uri must be an absolute URL"),
    scope: z.string().min(1, "scope is required"),
    state: z.string().min(1, "state is required"),
    code_challenge: z.string().min(1, "code_challenge is required"),
    code_challenge_method: z.literal("S256", {
      message: "code_challenge_method must be S256",
    }),
    resource: z.string().url("resource must be an absolute URI"),
  });
}

function isValidClientIdShape(value: string, allowInsecure: boolean): boolean {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  const hasPath = parsed.pathname !== "" && parsed.pathname !== "/";
  if (!hasPath) return false;
  if (parsed.protocol === "https:") return true;
  if (parsed.protocol === "http:" && allowInsecure && parsed.hostname === "127.0.0.1") {
    return true;
  }
  return false;
}

type ParsedAuthorizeRequest = z.infer<ReturnType<typeof buildAuthorizeSchema>>;

interface ParseResult {
  ok: boolean;
  /** Populated on success. */
  request?: ParsedAuthorizeRequest;
  /** Populated on failure. Carries the OAuth error code + a short message. */
  error?: { code: string; description: string };
  /** True when `resource` appeared more than once (invariant §4.5). */
  multipleResource: boolean;
  /**
   * `state` and `redirect_uri` as they appeared in the query string,
   * regardless of whether the rest of the request validated. Used to drive
   * the OAuth 2.1 §4.1.2.1 redirect when we have a usable URI.
   */
  rawState?: string;
  rawRedirectUri?: string;
}

/**
 * Pull authorize-request params off a Hono request. Strict enough to honor
 * invariant §4.5 (exactly one `resource`); permissive enough to surface a
 * `state` echo even when other params are broken.
 */
function parseAuthorizeQuery(env: IdPEnv, url: URL): ParseResult {
  const params = url.searchParams;
  const resourceValues = params.getAll("resource");
  const multipleResource = resourceValues.length > 1;

  const rawState = params.get("state") ?? undefined;
  const rawRedirectUri = params.get("redirect_uri") ?? undefined;

  if (multipleResource) {
    return {
      ok: false,
      multipleResource: true,
      error: { code: "invalid_request", description: "exactly one resource parameter is required" },
      ...(rawState !== undefined ? { rawState } : {}),
      ...(rawRedirectUri !== undefined ? { rawRedirectUri } : {}),
    };
  }

  const raw = {
    response_type: params.get("response_type") ?? undefined,
    client_id: params.get("client_id") ?? undefined,
    redirect_uri: rawRedirectUri,
    scope: params.get("scope") ?? undefined,
    state: rawState,
    code_challenge: params.get("code_challenge") ?? undefined,
    code_challenge_method: params.get("code_challenge_method") ?? undefined,
    resource: resourceValues[0] ?? undefined,
  };

  const schema = buildAuthorizeSchema(env);
  const result = schema.safeParse(raw);
  if (!result.success) {
    // Map zod failures to an OAuth error code. `redirect_uri` / `client_id`
    // shape errors are `invalid_request`; everything else, too.
    return {
      ok: false,
      multipleResource: false,
      error: {
        code: errorCodeForZod(result.error),
        description: result.error.issues[0]?.message ?? "invalid request",
      },
      ...(rawState !== undefined ? { rawState } : {}),
      ...(rawRedirectUri !== undefined ? { rawRedirectUri } : {}),
    };
  }
  return {
    ok: true,
    request: result.data,
    multipleResource: false,
    ...(rawState !== undefined ? { rawState } : {}),
    ...(rawRedirectUri !== undefined ? { rawRedirectUri } : {}),
  };
}

/**
 * Map a zod failure to an OAuth error code. Per §4 and §4.1 the only codes
 * we'd ever return at parse time are `invalid_request` (most parameter
 * issues) and `unsupported_response_type` (response_type ≠ "code").
 */
function errorCodeForZod(err: ZodError): string {
  for (const issue of err.issues) {
    const path = issue.path.join(".");
    if (path === "response_type") return "unsupported_response_type";
    if (path === "code_challenge_method") return "invalid_request";
  }
  return "invalid_request";
}

// ---------------------------------------------------------------------------
// Redirect-back helpers
// ---------------------------------------------------------------------------

/** Build a redirect to `target` with OAuth error params appended. */
function buildErrorRedirect(target: string, code: string, state: string | undefined): string {
  const url = new URL(target);
  url.searchParams.set("error", code);
  if (state !== undefined) {
    url.searchParams.set("state", state);
  }
  return url.toString();
}

/** Build a redirect to `target` with `code` + `state`. */
function buildCodeRedirect(target: string, code: string, state: string): string {
  const url = new URL(target);
  url.searchParams.set("code", code);
  url.searchParams.set("state", state);
  return url.toString();
}

// ---------------------------------------------------------------------------
// Auth-code persistence (§4.6)
// ---------------------------------------------------------------------------

interface MintedCode {
  code: string;
  expiresAt: number;
}

function mintAndPersistAuthCode(
  db: DB,
  payload: {
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
    scope: string;
    resource: string;
    sub: string;
  },
  now: number,
): MintedCode {
  const code = randomBytes(32).toString("base64url");
  const expiresAt = now + AUTH_CODE_TTL_MS;
  db.prepare(
    "INSERT INTO auth_codes (code, client_id, redirect_uri, code_challenge, " +
      "code_challenge_method, scope, resource, sub, created_at, exp, used) " +
      "VALUES (?, ?, ?, ?, 'S256', ?, ?, ?, ?, ?, 0)",
  ).run(
    code,
    payload.clientId,
    payload.redirectUri,
    payload.codeChallenge,
    payload.scope,
    payload.resource,
    payload.sub,
    now,
    expiresAt,
  );
  return { code, expiresAt };
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

type AuthorizeContext = Context<{ Variables: IdPVariables }>;

/**
 * GET /authorize — request validation, CIMD resolution, then either
 * auto-approve (AS_AUTO_APPROVE=true) or render the consent form.
 */
async function handleAuthorize(c: AuthorizeContext): Promise<Response> {
  const env = c.var.env;
  const db = c.var.db;
  const log = c.var.log;

  // Hono's c.req.url is an absolute URL string by the time it reaches us.
  const url = new URL(c.req.url);
  const parsed = parseAuthorizeQuery(env, url);

  // --- parse failure handling ------------------------------------------------
  if (!parsed.ok) {
    // We can only redirect-back if we've been given a syntactically valid
    // redirect URI. Otherwise return 400 with a plain message.
    const rawRedirect = parsed.rawRedirectUri;
    if (
      rawRedirect !== undefined &&
      isWellFormedAbsoluteUrl(rawRedirect) &&
      parsed.error !== undefined
    ) {
      // OAuth 2.1 §4.1.2.1: redirect with error + state. We don't yet know
      // whether `rawRedirect` is registered against a CIMD, but for parse
      // errors that don't touch CIMD trust (e.g. multiple `resource`,
      // missing `state`) we still redirect — the spec requires it.
      const location = buildErrorRedirect(rawRedirect, parsed.error.code, parsed.rawState);
      log.info(
        { authorize_error: parsed.error.code, reason: parsed.error.description },
        "authorize parse failure (redirecting)",
      );
      return c.redirect(location, 302);
    }
    const description = parsed.error?.description ?? "invalid request";
    log.info({ authorize_error: parsed.error?.code, reason: description }, "authorize 400");
    return c.text(`authorize error: ${description}`, 400);
  }
  const request = parsed.request;
  if (request === undefined) {
    // Defensive — `ok: true` implies `request` is set; satisfies the
    // exact-optional checker without an `!`.
    return c.text("authorize error: parser bug", 500);
  }

  // --- CIMD resolution -------------------------------------------------------
  let cimd: ValidatedCIMDDocument;
  try {
    cimd = await fetchAndValidateCIMD(request.client_id, { env, db, log });
  } catch (err) {
    // We do NOT have a trusted redirect_uri yet — anything from CIMD
    // resolution becomes a 400, not a redirect. (Once we trust the URI we
    // could redirect, but failing to resolve the CIMD means we can't trust
    // it at all.)
    const errorCode = oauthCodeForCimdFailure(err);
    log.info({ authorize_error: errorCode, err }, "authorize cimd resolution failure");
    return c.text(`authorize error: ${errorCode}`, 400);
  }

  // --- redirect_uri exact-match against CIMD [INV-4.10] ----------------------
  let canonicalRedirect: CanonicalURI;
  try {
    canonicalRedirect = canonicalize(request.redirect_uri);
  } catch {
    return c.text("authorize error: invalid redirect_uri", 400);
  }
  const allowedRedirects = cimd.redirect_uris.map((u) => {
    try {
      return canonicalize(u);
    } catch {
      return undefined;
    }
  });
  const redirectMatches = allowedRedirects.some(
    (allowed) => allowed !== undefined && allowed === canonicalRedirect,
  );
  if (!redirectMatches) {
    log.info(
      { client_id: cimd.client_id, requested_redirect: canonicalRedirect },
      "redirect_uri not in CIMD redirect_uris",
    );
    // Spec §4.5 / OAuth 2.1 §4.1.2.1: NEVER redirect to an unverified URI.
    return c.text("authorize error: redirect_uri not registered", 400);
  }

  // --- scope subset check ----------------------------------------------------
  const scopes = request.scope.split(/\s+/).filter((s) => s.length > 0);
  const allScopesSupported = scopes.every((s): s is SupportedScope => SUPPORTED_SCOPE_SET.has(s));
  if (!allScopesSupported || scopes.length === 0) {
    const location = buildErrorRedirect(canonicalRedirect, "invalid_scope", request.state);
    log.info({ scopes, client_id: cimd.client_id }, "scope outside scopes_supported");
    return c.redirect(location, 302);
  }

  // --- canonicalize resource for storage ------------------------------------
  let canonicalResource: CanonicalURI;
  try {
    canonicalResource = canonicalize(request.resource);
  } catch {
    const location = buildErrorRedirect(canonicalRedirect, "invalid_target", request.state);
    return c.redirect(location, 302);
  }

  // --- auto-approve path -----------------------------------------------------
  if (env.AS_AUTO_APPROVE) {
    const minted = mintAndPersistAuthCode(
      db,
      {
        clientId: cimd.client_id,
        redirectUri: canonicalRedirect,
        codeChallenge: request.code_challenge,
        scope: scopes.join(" "),
        resource: canonicalResource,
        sub: env.AS_DEMO_USER_SUB,
      },
      Date.now(),
    );
    log.info(
      {
        client_id: cimd.client_id,
        sub: env.AS_DEMO_USER_SUB,
        scopes,
        exp: minted.expiresAt,
      },
      "auto-approve granted code",
    );
    return c.redirect(buildCodeRedirect(canonicalRedirect, minted.code, request.state), 302);
  }

  // --- interactive consent path ---------------------------------------------
  const csrfToken = generateCsrfToken();
  const payload: ConsentSessionPayload = {
    clientId: cimd.client_id,
    redirectUri: canonicalRedirect,
    state: request.state,
    codeChallenge: request.code_challenge,
    codeChallengeMethod: "S256",
    scope: scopes.join(" "),
    resource: canonicalResource,
    csrf: csrfToken,
    iat: Date.now(),
  };
  const cookieValue = signSession(payload);

  const html = renderConsentHtml({
    cimd,
    redirectUri: canonicalRedirect,
    scopes,
    csrfToken,
  });

  c.header("Set-Cookie", buildSetCookieHeader(cookieValue));
  c.header("Content-Type", "text/html; charset=utf-8");
  // Don't let the browser cache a page that carries a CSRF token.
  c.header("Cache-Control", "no-store");
  return c.body(html, 200);
}

/**
 * POST /authorize/consent — verifies the signed session cookie and the
 * CSRF token in the form body, then mints + persists an auth code (or
 * redirects with `error=access_denied`).
 */
async function handleConsent(c: AuthorizeContext): Promise<Response> {
  const log = c.var.log;
  const db = c.var.db;

  const cookieHeader = c.req.header("cookie");
  const cookieValue = readSessionCookie(cookieHeader);
  const verifyResult = verifySession(cookieValue);
  if (!verifyResult.ok) {
    log.info({ reason: verifyResult.reason }, "consent session verification failed");
    return c.text(`consent error: ${verifyResult.reason}`, 400);
  }
  const session = verifyResult.payload;

  // Read the form body. Hono uses URLSearchParams under the hood for
  // application/x-www-form-urlencoded.
  let body: FormData;
  try {
    body = await c.req.formData();
  } catch {
    return c.text("consent error: invalid form body", 400);
  }
  const action = body.get("action");
  const csrf = body.get("csrf");

  if (typeof csrf !== "string" || csrf.length === 0) {
    return c.text("consent error: missing csrf", 400);
  }
  // Constant-time compare on the CSRF token — defends against an attacker
  // who can guess the cookie session but not the matching csrf token (or
  // vice versa).
  if (!constantTimeStringEq(csrf, session.csrf)) {
    log.info({}, "consent csrf mismatch");
    return c.text("consent error: csrf mismatch", 400);
  }

  if (action === "deny") {
    log.info({ client_id: session.clientId }, "consent denied");
    return c.redirect(buildErrorRedirect(session.redirectUri, "access_denied", session.state), 302);
  }
  if (action !== "approve") {
    return c.text("consent error: unknown action", 400);
  }

  const env = c.var.env;
  const minted = mintAndPersistAuthCode(
    db,
    {
      clientId: session.clientId,
      redirectUri: session.redirectUri,
      codeChallenge: session.codeChallenge,
      scope: session.scope,
      resource: session.resource,
      sub: env.AS_DEMO_USER_SUB,
    },
    Date.now(),
  );
  log.info(
    {
      client_id: session.clientId,
      sub: env.AS_DEMO_USER_SUB,
      exp: minted.expiresAt,
    },
    "consent approved",
  );
  return c.redirect(buildCodeRedirect(session.redirectUri, minted.code, session.state), 302);
}

function constantTimeStringEq(a: string, b: string): boolean {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  // `timingSafeEqual` requires equal-length buffers — length is not secret.
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

function isWellFormedAbsoluteUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function oauthCodeForCimdFailure(err: unknown): string {
  if (err instanceof InvalidCIMDError) return "invalid_client";
  if (err instanceof SSRFBlockedError) return "invalid_client";
  if (err instanceof InvalidCanonicalURIError) return "invalid_client";
  if (err instanceof InvalidContentTypeError) return "invalid_client";
  if (err instanceof MaxBytesExceededError) return "invalid_client";
  // Anything else (timeout, socket error, etc) is operational; still surface
  // as invalid_client at this layer — the client can't proceed either way.
  return "invalid_client";
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/**
 * Mount /authorize and /authorize/consent on the IdP app. Deps are pulled
 * off `c.var` (set by the app-level middleware), so this function takes
 * only the app handle.
 */
export function registerAuthorizeRoutes(app: IdPApp): void {
  app.get("/authorize", (c) => handleAuthorize(c));
  app.post("/authorize/consent", (c) => handleConsent(c));
}
