// POST /token — authorization_code grant only (refresh_token redemption is
// out of scope for this slice — see prompts/09-idp-token.md).
//
// Spec anchors:
//   - specs/authorization-server.md §5.1 (auth-code grant steps)
//   - specs/authorization-server.md §5.2 (response shape)
//   - specs/authorization-server.md §5.4 (error responses)
//   - specs/architecture.md §4.4 (PKCE S256), §4.5 (single canonical resource)
//
// All DB work runs inside `db.transaction(...)` — better-sqlite3's transaction
// wrapper. The wrapper opens a BEGIN, runs the callback, and COMMITs on
// success / ROLLBACKs if the callback throws. We additionally use
// `db.exec("BEGIN IMMEDIATE")` semantics implicitly via the wrapper to
// serialize the code-lookup-and-mark-used pair (replay safety under
// concurrent requests).

import { Buffer } from "node:buffer";
import { timingSafeEqual } from "node:crypto";
import type {
  AccessTokenJWT,
  CanonicalURI,
  ClientId,
  RefreshTokenOpaque,
  ScopeString,
} from "@poc/shared";
import { canonicalize, InvalidCanonicalURIError, verifyPKCE } from "@poc/shared";
import type { Context } from "hono";
import { z } from "zod";
import type { IdPApp, IdPVariables } from "../app.js";
import type { DB } from "../db.js";
import type { IdPEnv } from "../env.js";
import { mintAccessToken } from "../jwt.js";
import type { SigningKeyset } from "../keys.js";
import type { Logger } from "../log.js";
import { issueRefreshToken } from "../refresh.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** OAuth 2.1 §4.1.3.1 error codes we emit on this endpoint. */
type TokenErrorCode =
  | "invalid_request"
  | "invalid_grant"
  | "invalid_client"
  | "unsupported_grant_type"
  | "invalid_target";

/**
 * Typed error thrown anywhere in the flow; the outer handler maps it to the
 * spec's JSON-body response. Carries the HTTP status because `invalid_client`
 * is 401 and everything else is 400 (§5.4).
 */
class TokenError extends Error {
  readonly code: TokenErrorCode;
  readonly status: 400 | 401;
  readonly description: string | undefined;

  constructor(code: TokenErrorCode, description?: string) {
    super(description ?? code);
    this.code = code;
    this.status = code === "invalid_client" ? 401 : 400;
    this.description = description;
  }
}

interface AuthCodeRow {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
  scope: string;
  resource: string;
  sub: string;
  exp: number;
  used: number;
}

interface TokenRequestBody {
  grantType: string;
  code: string;
  clientId: string;
  redirectUri: string;
  codeVerifier: string;
  resource: string;
}

interface TokenSuccessResponse {
  access_token: AccessTokenJWT;
  token_type: "Bearer";
  expires_in: number;
  scope: ScopeString;
  refresh_token: RefreshTokenOpaque;
}

type TokenContext = Context<{ Variables: IdPVariables }>;

// ---------------------------------------------------------------------------
// Content-Type + body parsing
// ---------------------------------------------------------------------------

/**
 * Require `application/x-www-form-urlencoded`. Per §5 the token endpoint
 * MUST NOT accept JSON; the body parser would otherwise tolerate either.
 * Parameters appearing in `application/x-www-form-urlencoded` are encoded
 * with optional whitespace; we ignore everything after the first `;`.
 */
function requireFormContentType(c: TokenContext): void {
  const raw = c.req.header("content-type") ?? "";
  const primary = raw.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  if (primary !== "application/x-www-form-urlencoded") {
    throw new TokenError(
      "invalid_request",
      "Content-Type must be application/x-www-form-urlencoded",
    );
  }
}

/**
 * Zod schema for the form body. Every external boundary parses with zod
 * (CLAUDE.md convention). Field naming matches the wire (snake_case); the
 * Output is remapped to the internal camelCase shape below.
 *
 * `resource` is required as a single non-empty string. The duplicate-
 * resource check (invariant §4.5) runs against `URLSearchParams.getAll`
 * BEFORE this schema, because `Object.fromEntries` collapses duplicates
 * silently. Order of error precedence:
 *   1. duplicate resource → invalid_request
 *   2. unsupported grant_type → unsupported_grant_type
 *   3. missing/empty required field → invalid_request (or invalid_target
 *      for resource specifically)
 */
const TokenRequestSchema = z.object({
  grant_type: z.literal("authorization_code"),
  code: z.string().min(1),
  client_id: z.string().min(1),
  redirect_uri: z.string().min(1),
  code_verifier: z.string().min(1),
  resource: z.string().min(1),
});

/**
 * Parse the form body. Runs the duplicate-`resource` pre-check then zod,
 * mapping the first zod failure to the appropriate OAuth error code.
 */
async function parseTokenBody(c: TokenContext): Promise<TokenRequestBody> {
  let rawText: string;
  try {
    rawText = await c.req.text();
  } catch {
    throw new TokenError("invalid_request", "Unable to read request body");
  }
  const params = new URLSearchParams(rawText);

  // [INV-4.5] — exactly one `resource`. Must run before zod, because the
  // schema sees only the first value after Object.fromEntries.
  if (params.getAll("resource").length > 1) {
    throw new TokenError("invalid_request", "exactly one resource parameter is required");
  }

  const raw = Object.fromEntries(params.entries());
  const result = TokenRequestSchema.safeParse(raw);
  if (!result.success) {
    throw mapTokenSchemaError(result.error, raw);
  }

  return {
    grantType: result.data.grant_type,
    code: result.data.code,
    clientId: result.data.client_id,
    redirectUri: result.data.redirect_uri,
    codeVerifier: result.data.code_verifier,
    resource: result.data.resource,
  };
}

/**
 * Map a zod failure on the token request schema to a typed `TokenError`.
 * Field-specific cases come first so the response error code matches the
 * spec table in §5.4 (e.g. missing `resource` → `invalid_target`, not
 * `invalid_request`).
 */
function mapTokenSchemaError(error: z.ZodError, raw: Record<string, string>): TokenError {
  const first = error.issues[0];
  if (first === undefined) {
    return new TokenError("invalid_request", "Invalid token request body");
  }
  const field = typeof first.path[0] === "string" ? first.path[0] : "";

  // grant_type literal mismatch → unsupported_grant_type.
  if (field === "grant_type") {
    const presented = raw.grant_type ?? "";
    if (presented === "") {
      return new TokenError("invalid_request", "grant_type is required");
    }
    return new TokenError("unsupported_grant_type", `grant_type "${presented}" is not supported`);
  }

  // Missing/empty resource → invalid_target per §5.4.
  if (field === "resource") {
    return new TokenError("invalid_target", "resource is required");
  }

  // All other field failures → invalid_request, naming the missing field.
  if (field !== "") {
    return new TokenError("invalid_request", `${field} is required`);
  }
  return new TokenError("invalid_request", "Invalid token request body");
}

// ---------------------------------------------------------------------------
// Auth-code lookup + mark-used (single transaction, replay-safe)
// ---------------------------------------------------------------------------

/**
 * Atomically look up the auth code, validate it is live, and mark it used.
 * Wrapping the SELECT + UPDATE in `db.transaction(...)` gives us the
 * BEGIN IMMEDIATE behaviour the spec asks for: under two concurrent
 * redemptions of the same code, exactly one transaction succeeds at the
 * SELECT-then-UPDATE pair, the other sees `used = 1` (or no row) and fails
 * `invalid_grant`.
 */
function consumeAuthCode(db: DB, code: string, nowMs: number): AuthCodeRow {
  const txn = db.transaction((codeArg: string): AuthCodeRow => {
    const row = db
      .prepare<[string], AuthCodeRow>(
        "SELECT code, client_id, redirect_uri, code_challenge, code_challenge_method, " +
          "scope, resource, sub, exp, used FROM auth_codes WHERE code = ?",
      )
      .get(codeArg);
    if (row === undefined) {
      throw new TokenError("invalid_grant", "code not found");
    }
    if (row.used === 1) {
      throw new TokenError("invalid_grant", "code already used");
    }
    if (row.exp < nowMs) {
      throw new TokenError("invalid_grant", "code expired");
    }
    db.prepare("UPDATE auth_codes SET used = 1 WHERE code = ?").run(codeArg);
    return row;
  });
  return txn(code);
}

// ---------------------------------------------------------------------------
// Per-field validation helpers
// ---------------------------------------------------------------------------

/** Constant-time canonical-URL equality. Throws `invalid_*` on mismatch. */
function assertCanonicalEq(
  requestValue: string,
  storedCanonical: string,
  onMismatch: TokenError,
): CanonicalURI {
  let requested: CanonicalURI;
  try {
    requested = canonicalize(requestValue);
  } catch (err) {
    if (err instanceof InvalidCanonicalURIError) {
      throw onMismatch;
    }
    throw err;
  }
  const a = Buffer.from(requested, "utf8");
  const b = Buffer.from(storedCanonical, "utf8");
  // Length is not secret; `timingSafeEqual` requires equal-length buffers.
  if (a.length !== b.length) {
    throw onMismatch;
  }
  if (!timingSafeEqual(a, b)) {
    throw onMismatch;
  }
  return requested;
}

/**
 * PKCE check per [INV-4.4]: `base64url(SHA-256(verifier)) == stored_challenge`.
 * The shared `verifyPKCE` runs the comparison on raw SHA-256 byte buffers in
 * constant time. Brands are minted locally because PKCE brand minting lives
 * in `@poc/shared`'s internal surface only — see brands.ts header.
 */
function verifyCodeVerifier(verifier: string, storedChallenge: string): void {
  // Both inputs are untrusted strings on entry; verifyPKCE wants branded
  // inputs but the brand here is structural — the runtime check is the
  // SHA-256 comparison. Cast through the brand types to satisfy the call
  // signature without re-exporting `unsafeBrand`.
  const ok = verifyPKCE(
    verifier as unknown as Parameters<typeof verifyPKCE>[0],
    storedChallenge as unknown as Parameters<typeof verifyPKCE>[1],
  );
  if (!ok) {
    throw new TokenError("invalid_grant", "PKCE verification failed");
  }
}

// ---------------------------------------------------------------------------
// Route handler
// ---------------------------------------------------------------------------

interface HandlerDeps {
  env: IdPEnv;
  db: DB;
  log: Logger;
  keys: SigningKeyset;
}

async function handleToken(c: TokenContext, deps: HandlerDeps): Promise<Response> {
  const { env, db, log, keys } = deps;

  let body: TokenRequestBody;
  try {
    requireFormContentType(c);
    body = await parseTokenBody(c);
  } catch (err) {
    return errorResponse(c, err, log);
  }

  let row: AuthCodeRow;
  try {
    row = consumeAuthCode(db, body.code, Date.now());
  } catch (err) {
    return errorResponse(c, err, log);
  }

  try {
    // §5.1 step 3 — redirect_uri canonical byte-equal.
    assertCanonicalEq(
      body.redirectUri,
      row.redirect_uri,
      new TokenError("invalid_grant", "redirect_uri mismatch"),
    );

    // §5.1 step 4 — client_id canonical byte-equal. §5.4 maps this to
    // `invalid_client` (401), distinct from the other code/PKCE mismatches.
    const clientId = assertCanonicalEq(
      body.clientId,
      row.client_id,
      new TokenError("invalid_client", "client_id mismatch"),
    );

    // §5.1 step 5 — resource canonical byte-equal; absent/different is
    // `invalid_target` per §5.4 / [INV-4.5]. Missing-resource is handled
    // at parse time; this guard catches the canonical-mismatch case.
    const resource = assertCanonicalEq(
      body.resource,
      row.resource,
      new TokenError("invalid_target", "resource mismatch"),
    );

    // §5.1 step 6 — PKCE.
    verifyCodeVerifier(body.codeVerifier, row.code_challenge);

    // §5.1 steps 7–8 — mint the JWT.
    const scope = row.scope as ScopeString;
    const { token, expiresIn } = await mintAccessToken({
      env,
      keys,
      sub: row.sub,
      clientId: clientId as ClientId,
      resource,
      scope,
    });

    // §5.1 step 9 — issue refresh token (no rotation in this slice).
    const refresh = issueRefreshToken({
      db,
      env,
      clientId: clientId as ClientId,
      resource,
      scope,
      sub: row.sub,
    });

    const responseBody: TokenSuccessResponse = {
      access_token: token,
      token_type: "Bearer",
      expires_in: expiresIn,
      scope,
      refresh_token: refresh.plaintext,
    };
    log.info(
      {
        client_id: clientId,
        sub: row.sub,
        family_id: refresh.familyId,
        expires_in: expiresIn,
      },
      "token issued",
    );
    // Token endpoint responses MUST NOT be cached (RFC 6749 §5.1, carried
    // forward by OAuth 2.1).
    c.header("Cache-Control", "no-store");
    c.header("Pragma", "no-cache");
    return c.json(responseBody, 200);
  } catch (err) {
    return errorResponse(c, err, log);
  }
}

/**
 * Render a §5.4 error response. JSON body, HTTP 400 (or 401 for
 * `invalid_client`). Unknown errors collapse to `invalid_request` 400 — we
 * never surface internal details to the client.
 */
function errorResponse(c: TokenContext, err: unknown, log: Logger): Response {
  let status: 400 | 401 = 400;
  let code: TokenErrorCode = "invalid_request";
  let description: string | undefined;
  if (err instanceof TokenError) {
    status = err.status;
    code = err.code;
    description = err.description;
  } else {
    log.error({ err }, "unhandled token endpoint error");
  }
  const body: { error: TokenErrorCode; error_description?: string } = { error: code };
  if (description !== undefined) {
    body.error_description = description;
  }
  log.info({ token_error: code, status }, "token endpoint error");
  c.header("Cache-Control", "no-store");
  c.header("Pragma", "no-cache");
  return c.json(body, status);
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/**
 * Mount POST /token. Deps are passed explicitly (rather than pulled off
 * `c.var`) to match the pattern in `registerMetadataRoutes` and keep the
 * registration helper a pure function of its inputs.
 */
export function registerTokenRoutes(app: IdPApp, deps: HandlerDeps): void {
  app.post("/token", (c) => handleToken(c, deps));
}
