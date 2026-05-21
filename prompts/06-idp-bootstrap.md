# Step 6 — IdP Bootstrap

## Spec anchors

- [authorization-server.md §1](../specs/authorization-server.md) — Endpoints (just `/healthz` for this slice)
- [authorization-server.md §2](../specs/authorization-server.md) — Configuration env vars
- [authorization-server.md §6](../specs/authorization-server.md) — Key management
- [authorization-server.md §7](../specs/authorization-server.md) — Storage schema
- [authorization-server.md §8](../specs/authorization-server.md) — Logging redaction
- [apps/mock-customer-idp/.env.example](../apps/mock-customer-idp/.env.example) — canonical env var list

## Goal

Stand up the IdP as a runnable Hono app with env validation, SQLite bootstrap (full schema from §7), signing-key generation/persistence, pino logging with redaction, and a `/healthz` endpoint. No OAuth flow logic yet — that's slices 7–9.

## Deliverables

- `apps/mock-customer-idp/src/index.ts` — entry point, boot sequence
- `apps/mock-customer-idp/src/env.ts` — zod schema for `AS_*` env vars
- `apps/mock-customer-idp/src/db.ts` — better-sqlite3 setup + migration applying §7 schema
- `apps/mock-customer-idp/src/keys.ts` — signing-key load-or-generate per `AS_SIGNING_ALG`
- `apps/mock-customer-idp/src/log.ts` — pino logger with redaction per §8
- `apps/mock-customer-idp/src/app.ts` — Hono app factory (exported for tests + main)
- `apps/mock-customer-idp/src/routes/healthz.ts`
- `apps/mock-customer-idp/src/integration.test.ts` — in-process integration tests via `app.request()`
- Per-file unit tests where the logic is non-trivial (env validation, key gen, redaction)

## Public API (internal)

```ts
// app.ts
export function createIdPApp(deps: {
  env: IdPEnv;
  db: Database;
  log: Logger;
  keys: SigningKeyset;
}): Hono;

// env.ts
export interface IdPEnv {
  AS_ISSUER_URL: CanonicalURI;
  AS_PORT: number;
  AS_DB_PATH: string;
  AS_SIGNING_ALG: "RS256" | "ES256" | "EdDSA";
  AS_TOKEN_TTL_SEC: number;
  AS_REFRESH_TOKEN_TTL_SEC: number;
  AS_AUTO_APPROVE: boolean;
  AS_DEMO_USER_SUB: string;
  AS_DEV_ALLOW_INSECURE_CIMD: boolean;
}
export function parseEnv(raw: Record<string, string | undefined>): IdPEnv;

// keys.ts
export interface SigningKeyset {
  kid: string;
  alg: "RS256" | "ES256" | "EdDSA";
  publicJwk: JsonWebKey;
  privateKey: KeyLike;   // jose's KeyLike
}
export function loadOrGenerateKey(db: Database, alg: IdPEnv["AS_SIGNING_ALG"]): SigningKeyset;
```

## Acceptance criteria

### Boot sequence (in `index.ts`)

1. `parseEnv(process.env)` — zod-validate. Invalid → log error + `process.exit(1)`. No partial startup.
2. Open SQLite at `AS_DB_PATH`. Apply schema from §7 (idempotent — use `CREATE TABLE IF NOT EXISTS`).
3. `loadOrGenerateKey` — on empty `signing_keys` table, generate a keypair for `AS_SIGNING_ALG` and persist; otherwise load the active row.
4. Construct the Hono app via `createIdPApp(...)`.
5. `serve` via `@hono/node-server` on `AS_PORT`.
6. Log a single startup line: `idp listening on <AS_ISSUER_URL>`.
7. Graceful shutdown on SIGINT/SIGTERM: close DB, stop server, log.

### Env validation (`env.ts`)

- All `AS_*` vars from `.env.example` parsed via zod.
- Required without default: `AS_ISSUER_URL`. Anything else has a default per `.env.example`.
- `AS_ISSUER_URL` canonicalized via slice 1's `canonicalize`. Reject path-having URLs (PoC constraint per [authorization-server.md §2](../specs/authorization-server.md)).
- `AS_PORT`, `AS_TOKEN_TTL_SEC`, `AS_REFRESH_TOKEN_TTL_SEC`: `z.coerce.number().int().positive()`.
- `AS_AUTO_APPROVE`, `AS_DEV_ALLOW_INSECURE_CIMD`: `z.string().transform(v => v === "true")`.
- `AS_SIGNING_ALG`: `z.enum(["RS256", "ES256", "EdDSA"])`.

### DB (`db.ts`)

- All three tables from §7: `signing_keys`, `cimd_cache`, `auth_codes`, `refresh_tokens` + index `idx_auth_codes_exp` and `idx_refresh_tokens_family`.
- Use better-sqlite3's synchronous API. Enable WAL.
- Export prepared statement helpers later slices will need (`insertAuthCode`, `getAuthCode`, etc.) — at minimum a `Database` handle.

### Keys (`keys.ts`)

- RS256 → RSA 2048; ES256 → P-256; EdDSA → Ed25519. Use `jose.generateKeyPair`.
- `kid`: freshly generated UUID v4.
- Persist: `private_jwk` and `public_jwk` as JSON, `alg`, `created_at`, `retired_at: null`.
- On reload, return the row with `retired_at IS NULL` (the active key).
- Private key MUST NOT appear in any log line. Redaction in `log.ts` enforces this.

### Logging (`log.ts`)

Use pino with the redaction list from §8:

- Secret values: `token`, `access_token`, `refresh_token`, `code`, `code_verifier`, `private_jwk`, `client_secret`, `password`
- Headers: `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`
- Query strings and request bodies on `/token` and `/authorize/consent`

Use pino's `redact: { paths: [...], remove: true }`.

### `/healthz`

- `GET /healthz` returns `200` with `{ status: "ok" }`.
- Used by tests + future smoke script.

### Integration test (`integration.test.ts`)

```ts
const env = parseEnv({ AS_ISSUER_URL: "http://localhost:4444" });
const db = openInMemoryDB();
const keys = loadOrGenerateKey(db, env.AS_SIGNING_ALG);
const app = createIdPApp({ env, db, log, keys });

// test via app.request — no real port binding
const res = await app.request("/healthz");
expect(res.status).toBe(200);
```

Tests in this slice:

- `/healthz` returns 200 + correct JSON.
- Env: missing `AS_ISSUER_URL` → `parseEnv` throws `ZodError`.
- Env: `AS_ISSUER_URL=http://localhost:4444/tenant` (path) → reject.
- Keys: first call generates + persists; second call returns same `kid`.
- Logging: invoke a log call with a secret-shaped object; assert pino redacts it (use pino's destination redirection to a buffer for the assertion).
- Tag the secret-redaction test `[INV-4.12]`.

## Out of scope

- `/authorize`, `/token`, `/jwks.json`, metadata endpoints (slices 7–9)
- Consent UI
- CIMD fetch / cache logic (slice 8)

## Verification

```bash
test -f apps/mock-customer-idp/src/index.ts
test -f apps/mock-customer-idp/src/env.ts
test -f apps/mock-customer-idp/src/db.ts
test -f apps/mock-customer-idp/src/keys.ts
test -f apps/mock-customer-idp/src/log.ts
test -f apps/mock-customer-idp/src/app.ts
test -f apps/mock-customer-idp/src/routes/healthz.ts
test -f apps/mock-customer-idp/src/integration.test.ts

pnpm typecheck
pnpm lint
pnpm test

pnpm exec vitest run -t '[INV-4.12]' --reporter=verbose

# Independent AI review — address findings before commit
cr review --agent --type uncommitted -c CLAUDE.md -c specs/authorization-server.md
```

All gate commands must exit 0. CodeRabbit findings: address or explicitly acknowledge.

Optionally smoke: `cp apps/mock-customer-idp/.env.example apps/mock-customer-idp/.env && pnpm dev:idp` should print the startup line and respond 200 to `curl http://localhost:4444/healthz`.
