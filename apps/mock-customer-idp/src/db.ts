// IdP SQLite bootstrap. Schema is the canonical one from
// specs/authorization-server.md §7. `applySchema` is idempotent so a fresh
// boot against an existing DB is a no-op (every table is `CREATE TABLE IF
// NOT EXISTS`).
//
// Future slices (7–9) will add prepared-statement helpers (insertAuthCode,
// getAuthCode, etc.) alongside this module — for this slice the schema is
// applied but no DML helpers are exposed yet.

import Database from "better-sqlite3";

export type DB = Database.Database;

/**
 * Open a SQLite database at `path`. `:memory:` is honoured for tests.
 * WAL mode is enabled to match production-ish behaviour (concurrent reads
 * during writes; required for the `BEGIN IMMEDIATE` transactions in §5.1).
 */
export function openDatabase(path: string): DB {
  const db = new Database(path);
  // WAL is per-DB and persisted, but setting it on every boot is cheap and
  // makes the in-memory test path explicit.
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  return db;
}

const SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS signing_keys (
    kid TEXT PRIMARY KEY,
    alg TEXT NOT NULL,
    private_jwk TEXT NOT NULL,
    public_jwk TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    retired_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS cimd_cache (
    url TEXT PRIMARY KEY,
    document TEXT NOT NULL,
    fetched_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS auth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    scope TEXT NOT NULL,
    resource TEXT NOT NULL,
    sub TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    exp INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_auth_codes_exp ON auth_codes(exp);

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    family_id TEXT NOT NULL,
    parent_hash TEXT,
    client_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    scope TEXT NOT NULL,
    sub TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    exp INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id);
`;

/**
 * Apply the full §7 schema. Idempotent (every statement uses `IF NOT EXISTS`),
 * so this runs on every boot.
 *
 * SQLite stores `private_jwk` / `public_jwk` / `document` as `TEXT` rather
 * than the spec's `JSON` type — SQLite's `JSON` is a constraint alias for
 * `TEXT` in better-sqlite3 and the values are JSON-stringified before insert.
 */
export function applySchema(db: DB): void {
  db.exec(SCHEMA_SQL);
}
