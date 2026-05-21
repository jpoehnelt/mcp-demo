// In-process integration tests for the IdP. Tests build a real app via
// `createIdPApp` against an in-memory SQLite DB and drive it through
// `app.request()` — no real port binding, no `serve` invocation.
//
// Spec anchors:
//   - specs/authorization-server.md §2 (env), §6 (keys), §7 (schema),
//     §8 (logging redaction)
//   - specs/architecture.md invariant §4.12 (no-secret-logging)

import { Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import { ZodError } from "zod";
import { createIdPApp } from "./app.js";
import { applySchema, openDatabase } from "./db.js";
import { parseEnv } from "./env.js";
import { loadOrGenerateKey } from "./keys.js";
import { createLogger } from "./log.js";

function openInMemoryDB() {
  const db = openDatabase(":memory:");
  applySchema(db);
  return db;
}

async function buildApp() {
  const env = parseEnv({ AS_ISSUER_URL: "http://localhost:4444" });
  const db = openInMemoryDB();
  const keys = await loadOrGenerateKey(db, env.AS_SIGNING_ALG);
  const log = createLogger({ level: "silent" });
  const app = createIdPApp({ env, db, log, keys });
  return { app, env, db, keys };
}

describe("GET /healthz", () => {
  it("returns 200 with { status: 'ok' }", async () => {
    const { app } = await buildApp();
    const res = await app.request("/healthz");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body).toEqual({ status: "ok" });
  });
});

// Spec anchor: specs/authorization-server.md §3.1.
describe("GET /.well-known/oauth-authorization-server [§3.1]", () => {
  it("returns canonical issuer + endpoint URLs", async () => {
    const { app } = await buildApp();
    const res = await app.request("/.well-known/oauth-authorization-server");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toMatch(/^application\/json/);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.issuer).toBe("http://localhost:4444");
    expect(body.authorization_endpoint).toBe("http://localhost:4444/authorize");
    expect(body.token_endpoint).toBe("http://localhost:4444/token");
    expect(body.jwks_uri).toBe("http://localhost:4444/jwks.json");
    expect(body.response_types_supported).toEqual(["code"]);
    expect(body.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
    expect(body.code_challenge_methods_supported).toEqual(["S256"]);
    expect(body.token_endpoint_auth_methods_supported).toEqual(["none"]);
    expect(body.client_id_metadata_document_supported).toBe(true);
    // §3.1 closing note: neither `openid` nor `offline_access` is advertised.
    expect(body.scopes_supported).toEqual(["weather:read", "weather:premium"]);
  });

  it("sets Cache-Control: max-age=3600", async () => {
    const { app } = await buildApp();
    const res = await app.request("/.well-known/oauth-authorization-server");
    expect(res.headers.get("Cache-Control")).toBe("max-age=3600");
  });
});

// Spec anchor: specs/authorization-server.md §3.2.
describe("GET /.well-known/openid-configuration [§3.2]", () => {
  it("mirrors AS metadata and adds the OIDC fields", async () => {
    const { app, env } = await buildApp();
    const res = await app.request("/.well-known/openid-configuration");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toMatch(/^application\/json/);
    const body = (await res.json()) as Record<string, unknown>;
    // Mirror of §3.1 — spot-check the critical fields.
    expect(body.issuer).toBe("http://localhost:4444");
    expect(body.jwks_uri).toBe("http://localhost:4444/jwks.json");
    expect(body.scopes_supported).toEqual(["weather:read", "weather:premium"]);
    // OIDC-specific additions.
    expect(body.subject_types_supported).toEqual(["public"]);
    expect(body.id_token_signing_alg_values_supported).toEqual([env.AS_SIGNING_ALG]);
    expect(body.userinfo_endpoint).toBe("http://localhost:4444/userinfo");
  });

  it("sets Cache-Control: max-age=3600", async () => {
    const { app } = await buildApp();
    const res = await app.request("/.well-known/openid-configuration");
    expect(res.headers.get("Cache-Control")).toBe("max-age=3600");
  });

  it("id_token_signing_alg_values_supported reflects AS_SIGNING_ALG (ES256)", async () => {
    // Boot a second app with ES256 so we exercise the dynamic-alg path.
    // Hardcoded RS256 would pass the default-config test above; only this
    // case catches a regression to a literal "RS256" in the handler.
    const env = parseEnv({ AS_ISSUER_URL: "http://localhost:4444", AS_SIGNING_ALG: "ES256" });
    const db = openInMemoryDB();
    const keys = await loadOrGenerateKey(db, env.AS_SIGNING_ALG);
    const log = createLogger({ level: "silent" });
    const app = createIdPApp({ env, db, log, keys });

    const body = (await (await app.request("/.well-known/openid-configuration")).json()) as Record<
      string,
      unknown
    >;
    expect(body.id_token_signing_alg_values_supported).toEqual(["ES256"]);
  });
});

// Spec anchor: specs/authorization-server.md §3.3 + §6.
describe("GET /jwks.json [§3.3]", () => {
  it("returns the active key with matching kid, use, and alg", async () => {
    const { app, env, keys } = await buildApp();
    const res = await app.request("/jwks.json");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toMatch(/^application\/json/);
    const body = (await res.json()) as { keys: Array<Record<string, unknown>> };
    expect(body.keys).toHaveLength(1);
    const jwk = body.keys[0];
    if (jwk === undefined) {
      throw new Error("Expected jwks.keys[0] to be defined");
    }
    expect(jwk.kid).toBe(keys.kid);
    expect(jwk.use).toBe("sig");
    expect(jwk.alg).toBe(env.AS_SIGNING_ALG);
    // Public-only — the private key components (`d`, `p`, `q`, `dp`, `dq`,
    // `qi` for RSA; `d` for EC/OKP) MUST never appear in JWKS responses.
    expect(jwk.d).toBeUndefined();
    expect(jwk.p).toBeUndefined();
    expect(jwk.q).toBeUndefined();
  });

  it("sets Cache-Control: max-age=3600", async () => {
    const { app } = await buildApp();
    const res = await app.request("/jwks.json");
    expect(res.headers.get("Cache-Control")).toBe("max-age=3600");
  });

  it("returns alg=ES256 when AS_SIGNING_ALG=ES256", async () => {
    const env = parseEnv({ AS_ISSUER_URL: "http://localhost:4444", AS_SIGNING_ALG: "ES256" });
    const db = openInMemoryDB();
    const keys = await loadOrGenerateKey(db, env.AS_SIGNING_ALG);
    const log = createLogger({ level: "silent" });
    const app = createIdPApp({ env, db, log, keys });

    const body = (await (await app.request("/jwks.json")).json()) as {
      keys: Array<Record<string, unknown>>;
    };
    expect(body.keys[0]?.alg).toBe("ES256");
    expect(body.keys[0]?.kid).toBe(keys.kid);
  });
});

describe("GET /userinfo (stub for §3.2 advertisement)", () => {
  it("returns 200 with an empty object", async () => {
    const { app } = await buildApp();
    const res = await app.request("/userinfo");
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({});
  });
});

describe("parseEnv", () => {
  it("throws ZodError when AS_ISSUER_URL is missing", () => {
    expect(() => parseEnv({})).toThrow(ZodError);
  });

  it("rejects a path-having issuer URL (PoC constraint, §2)", () => {
    expect(() => parseEnv({ AS_ISSUER_URL: "http://localhost:4444/tenant" })).toThrow(ZodError);
  });

  it("canonicalizes the issuer URL (collapses trailing slash)", () => {
    const env = parseEnv({ AS_ISSUER_URL: "http://localhost:4444/" });
    expect(env.AS_ISSUER_URL).toBe("http://localhost:4444");
  });

  it("applies defaults for non-required vars", () => {
    const env = parseEnv({ AS_ISSUER_URL: "http://localhost:4444" });
    expect(env.AS_PORT).toBe(4444);
    expect(env.AS_DB_PATH).toBe("./as.db");
    expect(env.AS_SIGNING_ALG).toBe("RS256");
    expect(env.AS_TOKEN_TTL_SEC).toBe(300);
    expect(env.AS_REFRESH_TOKEN_TTL_SEC).toBe(86400);
    expect(env.AS_AUTO_APPROVE).toBe(false);
    expect(env.AS_DEMO_USER_SUB).toBe("demo-user");
    expect(env.AS_DEV_ALLOW_INSECURE_CIMD).toBe(false);
  });

  it("treats boolean env vars as true only for the literal 'true'", () => {
    const env = parseEnv({
      AS_ISSUER_URL: "http://localhost:4444",
      AS_AUTO_APPROVE: "true",
      AS_DEV_ALLOW_INSECURE_CIMD: "yes", // anything but "true" is false
    });
    expect(env.AS_AUTO_APPROVE).toBe(true);
    expect(env.AS_DEV_ALLOW_INSECURE_CIMD).toBe(false);
  });

  it("rejects an invalid AS_SIGNING_ALG", () => {
    expect(() =>
      parseEnv({
        AS_ISSUER_URL: "http://localhost:4444",
        AS_SIGNING_ALG: "HS256",
      }),
    ).toThrow(ZodError);
  });
});

describe("loadOrGenerateKey", () => {
  it("generates + persists on first call; returns the same kid on second call", async () => {
    const db = openInMemoryDB();
    const first = await loadOrGenerateKey(db, "RS256");
    expect(first.kid).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(first.alg).toBe("RS256");
    expect(first.publicJwk.kid).toBe(first.kid);
    expect(first.publicJwk.alg).toBe("RS256");
    expect(first.publicJwk.use).toBe("sig");

    const second = await loadOrGenerateKey(db, "RS256");
    expect(second.kid).toBe(first.kid);
    expect(second.publicJwk).toEqual(first.publicJwk);

    // Exactly one active row.
    const rows = db
      .prepare("SELECT COUNT(*) AS n FROM signing_keys WHERE retired_at IS NULL")
      .get() as { n: number };
    expect(rows.n).toBe(1);
  });

  it("supports ES256 (P-256)", async () => {
    const db = openInMemoryDB();
    const key = await loadOrGenerateKey(db, "ES256");
    expect(key.alg).toBe("ES256");
    expect(key.publicJwk.kty).toBe("EC");
    expect(key.publicJwk.crv).toBe("P-256");
  });

  it("supports EdDSA (Ed25519)", async () => {
    const db = openInMemoryDB();
    const key = await loadOrGenerateKey(db, "EdDSA");
    expect(key.alg).toBe("EdDSA");
    expect(key.publicJwk.kty).toBe("OKP");
    expect(key.publicJwk.crv).toBe("Ed25519");
  });

  it("throws when AS_SIGNING_ALG changes against an existing DB", async () => {
    const db = openInMemoryDB();
    await loadOrGenerateKey(db, "RS256");
    await expect(loadOrGenerateKey(db, "ES256")).rejects.toThrow(/does not match/);
  });
});

// Capture pino output into an in-memory buffer so we can assert on raw lines.
function makeLogCapture(): { lines: string[]; stream: Writable } {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, cb) {
      lines.push(chunk.toString("utf8"));
      cb();
    },
  });
  return { lines, stream };
}

describe("logging redaction [INV-4.12]", () => {
  it("removes secret-shaped fields from log output", () => {
    const { lines, stream } = makeLogCapture();
    const log = createLogger({ level: "info", destination: stream });

    // A synthetic record exercising every secret path from §8.
    log.info(
      {
        token: "tok-secret-AAA",
        access_token: "at-secret-BBB",
        refresh_token: "rt-secret-CCC",
        code: "code-secret-DDD",
        code_verifier: "cv-secret-EEE",
        private_jwk: { d: "private-secret-FFF" },
        client_secret: "cs-secret-GGG",
        password: "pw-secret-HHH",
        req: {
          headers: {
            Authorization: "Bearer secret-III",
            Cookie: "session=secret-JJJ",
            "set-cookie": "session=secret-KKK",
            "Proxy-Authorization": "Basic secret-LLL",
            "x-safe": "ok-MMM",
          },
          body: { password: "secret-NNN", token: "secret-OOO" },
          query: "code=secret-PPP&state=ok-QQQ",
        },
      },
      "synthetic request",
    );

    const combined = lines.join("");

    // Every secret value must be absent.
    const secretMarkers = [
      "tok-secret-AAA",
      "at-secret-BBB",
      "rt-secret-CCC",
      "code-secret-DDD",
      "cv-secret-EEE",
      "private-secret-FFF",
      "cs-secret-GGG",
      "pw-secret-HHH",
      "secret-III",
      "secret-JJJ",
      "secret-KKK",
      "secret-LLL",
      "secret-NNN",
      "secret-OOO",
      "secret-PPP",
    ];
    for (const marker of secretMarkers) {
      expect(combined).not.toContain(marker);
    }

    // The non-secret marker still survives (proves the log line was emitted
    // and we're not just looking at empty output).
    expect(combined).toContain("ok-MMM");
    expect(combined).toContain("synthetic request");
  });
});
