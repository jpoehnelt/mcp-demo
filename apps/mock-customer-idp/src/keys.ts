// Signing-key bootstrap. Spec anchor: specs/authorization-server.md §6.
//
// On first boot, generate a keypair sized to `AS_SIGNING_ALG`:
//   RS256 → RSA 2048
//   ES256 → P-256 (jose's default curve for ES256)
//   EdDSA → Ed25519 (the only EdDSA variant jose supports under that name)
//
// On every subsequent boot, return the row where `retired_at IS NULL`.
// Rotation is out of scope (specs/architecture.md §6 Non-Goals) but the
// schema already supports it — a future rotation slice can flip the active
// row and add a new one without migration.
//
// Private keys MUST stay in the DB and MUST NOT be logged. pino redaction
// in `log.ts` enforces that; the path `private_jwk` is listed there.

import { randomUUID } from "node:crypto";
import type { CryptoKey, JWK } from "jose";
import { exportJWK, generateKeyPair, importJWK } from "jose";
import type { DB } from "./db.js";
import type { IdPEnv } from "./env.js";

export interface SigningKeyset {
  kid: string;
  alg: IdPEnv["AS_SIGNING_ALG"];
  publicJwk: JWK;
  privateKey: CryptoKey;
}

interface SigningKeyRow {
  kid: string;
  alg: string;
  private_jwk: string;
  public_jwk: string;
}

// Map alg → jose `generateKeyPair` options.
// For RS256 we pin `modulusLength: 2048` (matches §6). ES256 and EdDSA use
// jose's default curve mapping (P-256 and Ed25519 respectively).
function generateOptionsFor(alg: IdPEnv["AS_SIGNING_ALG"]) {
  if (alg === "RS256") {
    return { extractable: true, modulusLength: 2048 } as const;
  }
  return { extractable: true } as const;
}

/**
 * Load the active signing key from the DB, or generate + persist one if
 * `signing_keys` is empty.
 *
 * Async because `jose.generateKeyPair` + `exportJWK` + `importJWK` are all
 * async (they use the WebCrypto API under the hood).
 */
export async function loadOrGenerateKey(
  db: DB,
  alg: IdPEnv["AS_SIGNING_ALG"],
): Promise<SigningKeyset> {
  const activeRow = db
    .prepare("SELECT kid, alg, private_jwk, public_jwk FROM signing_keys WHERE retired_at IS NULL")
    .get() as SigningKeyRow | undefined;

  if (activeRow !== undefined) {
    // Validate the stored alg matches the requested one. A mismatch would
    // mean someone changed `AS_SIGNING_ALG` against an existing DB; failing
    // loud is safer than silently signing with the wrong key.
    if (activeRow.alg !== alg) {
      throw new Error(
        `Active signing key alg (${activeRow.alg}) does not match AS_SIGNING_ALG (${alg}). ` +
          "Rotation is out of scope for this PoC — wipe AS_DB_PATH to re-bootstrap.",
      );
    }
    const publicJwk = JSON.parse(activeRow.public_jwk) as JWK;
    const privateJwk = JSON.parse(activeRow.private_jwk) as JWK;
    const privateKey = await importJWK(privateJwk, alg, { extractable: true });
    // `importJWK` returns `Uint8Array` for symmetric keys; ours are
    // asymmetric (RS256/ES256/EdDSA) so the result is a CryptoKey.
    if (privateKey instanceof Uint8Array) {
      throw new Error("Imported signing key is symmetric; expected asymmetric CryptoKey");
    }
    return { kid: activeRow.kid, alg, publicJwk, privateKey };
  }

  // Empty table — bootstrap a new keypair.
  const { privateKey, publicKey } = await generateKeyPair(alg, generateOptionsFor(alg));
  const publicJwk = await exportJWK(publicKey);
  const privateJwk = await exportJWK(privateKey);
  const kid = randomUUID();
  const now = Date.now();

  // Stamp `kid` + `alg` onto the public JWK so /jwks.json can serve it
  // directly in slice 7 without re-deriving the fields.
  publicJwk.kid = kid;
  publicJwk.alg = alg;
  publicJwk.use = "sig";

  db.prepare(
    "INSERT INTO signing_keys (kid, alg, private_jwk, public_jwk, created_at, retired_at) " +
      "VALUES (?, ?, ?, ?, ?, NULL)",
  ).run(kid, alg, JSON.stringify(privateJwk), JSON.stringify(publicJwk), now);

  return { kid, alg, publicJwk, privateKey };
}
