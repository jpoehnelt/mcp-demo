// Refresh-token issuance.
//
// Spec anchors:
//   - specs/authorization-server.md §5.1 step 9 (issuance shape)
//   - specs/authorization-server.md §7 (refresh_tokens schema)
//   - specs/architecture.md §3.2 (opaque, 32 random bytes, stored as SHA-256)
//
// REDEMPTION (`grant_type=refresh_token`, §5.3) is OUT OF SCOPE for this
// slice — only issuance is implemented. The schema already supports the
// `parent_hash` + `family_id` columns rotation will use.
//
// On the wire: 32 random bytes → base64url (44 chars after stripping pad).
// In storage: SHA-256 hex of the wire form. The plaintext NEVER hits disk.

import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { CanonicalURI, ClientId, RefreshTokenOpaque, ScopeString } from "@poc/shared";
import type { DB } from "./db.js";
import type { IdPEnv } from "./env.js";

export interface IssueRefreshTokenArgs {
  db: DB;
  env: IdPEnv;
  clientId: ClientId;
  resource: CanonicalURI;
  scope: ScopeString;
  sub: string;
}

export interface IssuedRefreshToken {
  plaintext: RefreshTokenOpaque;
  familyId: string;
}

/**
 * Mint and persist a refresh token. Returns the plaintext (returned to the
 * client) and the family id (used by future rotations).
 *
 * The token is bound to `(client_id, resource, scope, sub)` — invariant
 * §3.2. `parent_hash` is NULL for first-issuance rows; rotation (§5.3, not
 * in this slice) will populate it with the SHA-256 hash of the redeemed
 * token, keeping the audit trail within the family.
 *
 * Synchronous: better-sqlite3 prepared statements run synchronously and we
 * want this whole call to compose cleanly inside the `db.transaction(...)`
 * wrapper from the token endpoint.
 */
export function issueRefreshToken(args: IssueRefreshTokenArgs): IssuedRefreshToken {
  const plaintext = randomBytes(32).toString("base64url");
  const tokenHash = createHash("sha256").update(plaintext).digest("hex");
  const familyId = randomUUID();
  const now = Date.now();
  const exp = now + args.env.AS_REFRESH_TOKEN_TTL_SEC * 1000;

  args.db
    .prepare(
      "INSERT INTO refresh_tokens (token_hash, family_id, parent_hash, client_id, " +
        "resource, scope, sub, created_at, exp, revoked) " +
        "VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, 0)",
    )
    .run(tokenHash, familyId, args.clientId, args.resource, args.scope, args.sub, now, exp);

  // Local brand application — see comment in jwt.ts for the same pattern.
  return {
    plaintext: plaintext as RefreshTokenOpaque,
    familyId,
  };
}
