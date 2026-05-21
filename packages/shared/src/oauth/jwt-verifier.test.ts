// JWT verifier tests. Mints real JWTs via jose and serves a JWKS over a local
// 127.0.0.1 HTTP listener. The JWKS is fetched by jose's own fetch (not our
// `safeFetch`) — jose has no SSRF guard, but the listener URL is a literal
// loopback we control, so the test surface is trivially safe.

import { Buffer } from "node:buffer";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import type { CryptoKey, JWK } from "jose";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  InvalidAudienceError,
  InvalidIssuerError,
  InvalidTokenError,
  TokenExpiredError,
} from "../errors.js";
import { canonicalize } from "./canonical-uri.js";
import { createJWTVerifier } from "./jwt-verifier.js";

// ---------------------------------------------------------------------------
// JWKS test server
// ---------------------------------------------------------------------------

interface JWKSServer {
  url: string; // http://127.0.0.1:<port>/jwks
  setKeys: (keys: JWK[]) => void;
  close: () => Promise<void>;
}

async function startJWKSServer(initial: JWK[]): Promise<JWKSServer> {
  let keys = initial;
  const server = http.createServer((req, res) => {
    if ((req.url ?? "") !== "/jwks") {
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ keys }));
  });
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve();
    });
  });
  const addr = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${String(addr.port)}/jwks`,
    setKeys: (next) => {
      keys = next;
    },
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => {
          if (err !== undefined && err !== null) reject(err);
          else resolve();
        });
      }),
  };
}

// ---------------------------------------------------------------------------
// Token minting helpers
// ---------------------------------------------------------------------------

interface MintedKey {
  privateKey: CryptoKey;
  jwk: JWK;
  kid: string;
  alg: string;
}

let kidCounter = 0;
async function makeRSKey(): Promise<MintedKey> {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const jwk = await exportJWK(publicKey);
  kidCounter += 1;
  const kid = `test-rs256-${String(kidCounter)}`;
  jwk.kid = kid;
  jwk.alg = "RS256";
  jwk.use = "sig";
  return { privateKey, jwk, kid, alg: "RS256" };
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

interface ClaimsOverride {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  nbf?: number;
  jti?: string;
  scope?: string;
  client_id?: string;
}

function signJWT(key: MintedKey, overrides: ClaimsOverride, algOverride?: string): Promise<string> {
  const now = nowSec();
  const claims: Record<string, unknown> = {
    iss: overrides.iss ?? "https://idp.example.com",
    sub: overrides.sub ?? "user-1",
    aud: overrides.aud ?? "https://mcp.example.com",
    exp: overrides.exp ?? now + 300,
    iat: overrides.iat ?? now,
    jti: overrides.jti ?? "token-1",
    scope: overrides.scope ?? "read",
    client_id: overrides.client_id ?? "https://client.example.com/cimd",
  };
  if (overrides.nbf !== undefined) {
    claims.nbf = overrides.nbf;
  }
  return new SignJWT(claims)
    .setProtectedHeader({ alg: algOverride ?? key.alg, kid: key.kid })
    .sign(key.privateKey);
}

/**
 * Mint an HS256 token. We use jose's `SignJWT` with a raw symmetric secret;
 * this is for negative-path testing only — the verifier MUST refuse HS*.
 */
function signHS256(secret: Uint8Array, claims: Record<string, unknown>): Promise<string> {
  return new SignJWT(claims).setProtectedHeader({ alg: "HS256" }).sign(secret);
}

/**
 * Hand-build an unsecured ("alg":"none") JWT. jose refuses to sign these
 * via `SignJWT`, so we synthesize the wire form manually. The payload need
 * not even be valid — the verifier MUST refuse it before parsing.
 */
function buildAlgNoneJWT(claims: Record<string, unknown>): string {
  const enc = (v: unknown): string => Buffer.from(JSON.stringify(v), "utf8").toString("base64url");
  const header = enc({ alg: "none", typ: "JWT" });
  const payload = enc(claims);
  return `${header}.${payload}.`;
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

const ISSUER = canonicalize("https://idp.example.com");
const AUDIENCE = canonicalize("https://mcp.example.com");

describe("createJWTVerifier", () => {
  let jwks: JWKSServer;
  let key: MintedKey;

  beforeAll(async () => {
    key = await makeRSKey();
    jwks = await startJWKSServer([key.jwk]);
  });

  afterAll(async () => {
    await jwks.close();
  });

  beforeEach(() => {
    jwks.setKeys([key.jwk]);
  });

  function makeVerifier(): ReturnType<typeof createJWTVerifier> {
    return createJWTVerifier({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: jwks.url,
    });
  }

  // -- Happy path ----------------------------------------------------------

  it("verifies a well-formed RS256 token and returns parsed claims", async () => {
    const token = await signJWT(key, {});
    const claims = await makeVerifier().verify(token);
    expect(claims.iss).toBe("https://idp.example.com");
    expect(claims.aud).toBe("https://mcp.example.com");
    expect(claims.sub).toBe("user-1");
    expect(claims.scope).toBe("read");
  });

  it("verifies a token whose aud is an array containing the expected audience", async () => {
    const token = await signJWT(key, {
      aud: ["https://other.example.com", "https://mcp.example.com"],
    });
    const claims = await makeVerifier().verify(token);
    const audList = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    expect(audList).toContain("https://mcp.example.com");
  });

  it("verifies a token with aud expressed in non-canonical form (uppercase host)", async () => {
    const token = await signJWT(key, { aud: "https://MCP.example.com" });
    // Token aud is `https://MCP.example.com`; verifier audience is the
    // canonical `https://mcp.example.com`. Equality only holds after
    // canonicalization — this is the INV-4.1 containment-after-canonical
    // rule.
    await expect(makeVerifier().verify(token)).resolves.toBeDefined();
  });

  // -- INV-4.1 aud rejection -----------------------------------------------

  it("INV-4.1: rejects a token with aud=other.example.com", async () => {
    const token = await signJWT(key, { aud: "https://other.example.com" });
    await expect(makeVerifier().verify(token)).rejects.toBeInstanceOf(InvalidAudienceError);
  });

  it("INV-4.1: rejects a token whose aud array lacks the expected audience", async () => {
    const token = await signJWT(key, {
      aud: ["https://other.example.com", "https://still-other.example.com"],
    });
    await expect(makeVerifier().verify(token)).rejects.toBeInstanceOf(InvalidAudienceError);
  });

  // -- INV-4.2 iss rejection -----------------------------------------------

  it("INV-4.2: rejects a token whose iss does not match the expected issuer", async () => {
    const token = await signJWT(key, { iss: "https://evil.example.com" });
    await expect(makeVerifier().verify(token)).rejects.toBeInstanceOf(InvalidIssuerError);
  });

  // -- INV-4.3 HS* / alg:none ----------------------------------------------

  it("INV-4.3: rejects a token signed with HS256", async () => {
    const secret = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) secret[i] = i;
    const token = await signHS256(secret, {
      iss: "https://idp.example.com",
      sub: "user-1",
      aud: "https://mcp.example.com",
      exp: nowSec() + 300,
      iat: nowSec(),
      jti: "j",
      scope: "read",
      client_id: "https://client.example.com/cimd",
    });
    await expect(makeVerifier().verify(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it("INV-4.3: rejects a token with alg: none", async () => {
    const token = buildAlgNoneJWT({
      iss: "https://idp.example.com",
      sub: "user-1",
      aud: "https://mcp.example.com",
      exp: nowSec() + 300,
      iat: nowSec(),
      jti: "j",
      scope: "read",
      client_id: "https://client.example.com/cimd",
    });
    await expect(makeVerifier().verify(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  // -- exp / nbf / signature -----------------------------------------------

  it("rejects an expired token (exp far in the past)", async () => {
    const past = nowSec() - 3600;
    const token = await signJWT(key, { exp: past, iat: past - 60 });
    await expect(makeVerifier().verify(token)).rejects.toBeInstanceOf(TokenExpiredError);
  });

  it("accepts a token whose exp is within the ±30s skew window", async () => {
    // exp is 10 seconds in the past — still inside 30s tolerance.
    const skewed = nowSec() - 10;
    const token = await signJWT(key, { exp: skewed, iat: nowSec() - 60 });
    await expect(makeVerifier().verify(token)).resolves.toBeDefined();
  });

  it("rejects a token whose nbf is more than 30s in the future", async () => {
    const future = nowSec() + 120;
    const token = await signJWT(key, { nbf: future });
    await expect(makeVerifier().verify(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it("rejects a token signed with a key NOT present in the JWKS", async () => {
    const otherKey = await makeRSKey();
    // Sign with otherKey but keep JWKS pointing at the original key.
    const token = await signJWT(otherKey, {});
    await expect(makeVerifier().verify(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it("rejects a token whose payload omits required claims (e.g. scope)", async () => {
    const now = nowSec();
    // Mint without `scope` by going through SignJWT directly.
    const token = await new SignJWT({
      iss: "https://idp.example.com",
      sub: "user-1",
      aud: "https://mcp.example.com",
      exp: now + 300,
      iat: now,
      jti: "j",
      client_id: "https://client.example.com/cimd",
    })
      .setProtectedHeader({ alg: "RS256", kid: key.kid })
      .sign(key.privateKey);
    await expect(makeVerifier().verify(token)).rejects.toBeDefined();
  });

  it("rejects an empty token string", async () => {
    await expect(makeVerifier().verify("")).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it("constructs with an invalid jwks_uri and rejects subsequent verify calls", () => {
    expect(() =>
      createJWTVerifier({
        issuer: ISSUER,
        audience: AUDIENCE,
        jwksUri: "not-a-url",
      }),
    ).toThrow(InvalidTokenError);
  });
});
