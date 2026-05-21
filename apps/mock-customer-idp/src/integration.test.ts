// In-process integration tests for the IdP. Tests build a real app via
// `createIdPApp` against an in-memory SQLite DB and drive it through
// `app.request()` — no real port binding, no `serve` invocation.
//
// Spec anchors:
//   - specs/authorization-server.md §2 (env), §6 (keys), §7 (schema),
//     §8 (logging redaction)
//   - specs/architecture.md invariant §4.12 (no-secret-logging)

import type { AddressInfo } from "node:net";
import { Writable } from "node:stream";
import { type ServerType, serve } from "@hono/node-server";
import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ZodError } from "zod";
import { createIdPApp } from "./app.js";
import { applySchema, openDatabase } from "./db.js";
import type { IdPEnv } from "./env.js";
import { parseEnv } from "./env.js";
import { loadOrGenerateKey } from "./keys.js";
import { createLogger } from "./log.js";
import {
  buildSetCookieHeader,
  type ConsentSessionPayload,
  SESSION_COOKIE_NAME,
  signSession,
} from "./session.js";

function openInMemoryDB() {
  const db = openDatabase(":memory:");
  applySchema(db);
  return db;
}

async function buildApp(envOverrides: Record<string, string> = {}) {
  const env: IdPEnv = parseEnv({
    AS_ISSUER_URL: "http://localhost:4444",
    ...envOverrides,
  });
  const db = openInMemoryDB();
  const keys = await loadOrGenerateKey(db, env.AS_SIGNING_ALG);
  const log = createLogger({ level: "silent" });
  const app = createIdPApp({ env, db, log, keys });
  return { app, env, db, keys };
}

// ---------------------------------------------------------------------------
// CIMD test-fixture HTTP server. Boots a Hono app on an ephemeral 127.0.0.1
// port. The handler is replaceable per-test so individual cases can serve
// canned documents (valid CIMD, mismatched client_id, 500, etc).
// ---------------------------------------------------------------------------

interface CIMDFixtureServer {
  port: number;
  url: string;
  origin: string;
  /** Replace the handler. Path is `/cimd/client.json` by default. */
  setHandler(handler: (path: string) => Response | Promise<Response>): void;
  close(): Promise<void>;
}

async function startCIMDServer(): Promise<CIMDFixtureServer> {
  let current: (path: string) => Response | Promise<Response> = () =>
    new Response("not configured", { status: 500 });
  const app = new Hono();
  app.all("*", (c) => {
    return Promise.resolve(current(c.req.path));
  });
  let server: ServerType | undefined;
  const port: number = await new Promise((resolve, reject) => {
    server = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" }, (info) => {
      resolve((info as AddressInfo).port);
    });
    server.on("error", reject);
  });
  const origin = `http://127.0.0.1:${String(port)}`;
  return {
    port,
    origin,
    url: `${origin}/cimd/client.json`,
    setHandler(h) {
      current = h;
    },
    close() {
      return new Promise((resolve, reject) => {
        if (server === undefined) {
          resolve();
          return;
        }
        server.close((err) => (err !== undefined ? reject(err) : resolve()));
      });
    },
  };
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

/** Build a baseline CIMD document for `clientId` with the demo redirect. */
function buildCIMD(clientId: string, redirectUris: string[]) {
  return {
    client_id: clientId,
    client_name: "Demo CLI",
    client_uri: "https://example.com/demo",
    redirect_uris: redirectUris,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  };
}

function buildAuthorizeQuery(overrides: Partial<Record<string, string>> = {}): string {
  const base: Record<string, string> = {
    response_type: "code",
    client_id: "https://example.invalid/c",
    redirect_uri: "https://app.example.com/cb",
    scope: "weather:read",
    state: "s-12345",
    code_challenge: "abc123-challenge",
    code_challenge_method: "S256",
    resource: "https://mcp.example.com",
  };
  const merged = { ...base, ...overrides };
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(merged)) {
    if (v !== undefined) params.append(k, v);
  }
  return params.toString();
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

// ---------------------------------------------------------------------------
// /authorize and /authorize/consent. Spec anchor: §4 (all subsections).
// Each describe boots the IdP app in-process + a CIMD fixture server, then
// drives the flow via `app.request()`.
// ---------------------------------------------------------------------------

describe("GET /authorize [§4]", () => {
  let cimdServer: CIMDFixtureServer;
  beforeEach(async () => {
    cimdServer = await startCIMDServer();
  });
  afterEach(async () => {
    await cimdServer.close();
  });

  it("happy path with AS_AUTO_APPROVE → 302 with code + state", async () => {
    const { app, db } = await buildApp({
      AS_AUTO_APPROVE: "true",
      AS_DEV_ALLOW_INSECURE_CIMD: "true",
    });
    cimdServer.setHandler((path) => {
      if (path === "/cimd/client.json") {
        return jsonResponse(buildCIMD(cimdServer.url, ["https://app.example.com/cb"]));
      }
      return new Response("not found", { status: 404 });
    });
    const query = buildAuthorizeQuery({ client_id: cimdServer.url });
    const res = await app.request(`/authorize?${query}`);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location");
    expect(location).not.toBeNull();
    const u = new URL(location ?? "");
    expect(u.origin + u.pathname).toBe("https://app.example.com/cb");
    expect(u.searchParams.get("state")).toBe("s-12345");
    const code = u.searchParams.get("code");
    expect(code).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(code?.length ?? 0).toBeGreaterThanOrEqual(40); // 32 bytes base64url

    // The auth_codes row was persisted with the right fields.
    const row = db
      .prepare(
        "SELECT client_id, redirect_uri, code_challenge, code_challenge_method, scope, resource, sub, used FROM auth_codes WHERE code = ?",
      )
      .get(code) as Record<string, unknown> | undefined;
    expect(row).toBeDefined();
    expect(row?.client_id).toBe(cimdServer.url);
    expect(row?.redirect_uri).toBe("https://app.example.com/cb");
    expect(row?.code_challenge_method).toBe("S256");
    expect(row?.scope).toBe("weather:read");
    expect(row?.resource).toBe("https://mcp.example.com");
    expect(row?.sub).toBe("demo-user");
    expect(row?.used).toBe(0);
  });

  it("[INV-4.5] rejects multiple resource params", async () => {
    const { app } = await buildApp({ AS_DEV_ALLOW_INSECURE_CIMD: "true" });
    const params = new URLSearchParams(buildAuthorizeQuery({ client_id: cimdServer.url }));
    params.append("resource", "https://other.example.com");
    const res = await app.request(`/authorize?${params.toString()}`);
    // Two resource values → invalid_request. redirect_uri parsed OK, so
    // OAuth 2.1 §4.1.2.1 says redirect-with-error.
    expect(res.status).toBe(302);
    const location = res.headers.get("Location") ?? "";
    expect(location).toContain("error=invalid_request");
    expect(location).toContain("state=s-12345");
  });

  it("[INV-4.10] rejects redirect_uri not in CIMD redirect_uris", async () => {
    const { app } = await buildApp({ AS_DEV_ALLOW_INSECURE_CIMD: "true" });
    cimdServer.setHandler(() =>
      jsonResponse(buildCIMD(cimdServer.url, ["https://app.example.com/cb"])),
    );
    const query = buildAuthorizeQuery({
      client_id: cimdServer.url,
      redirect_uri: "https://attacker.example.com/cb",
    });
    const res = await app.request(`/authorize?${query}`);
    expect(res.status).toBe(400);
    // Body MUST NOT redirect — defending against open-redirect.
    expect(res.headers.get("Location")).toBeNull();
  });

  it("[INV-4.9] rejects CIMD whose client_id ≠ fetch URL", async () => {
    const { app } = await buildApp({ AS_DEV_ALLOW_INSECURE_CIMD: "true" });
    cimdServer.setHandler(() =>
      jsonResponse(buildCIMD("https://different.example.com/c", ["https://app.example.com/cb"])),
    );
    const query = buildAuthorizeQuery({ client_id: cimdServer.url });
    const res = await app.request(`/authorize?${query}`);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("invalid_client");
  });

  it("rejects CIMD fetched from a connection-refused loopback port (SSRF-adjacent)", async () => {
    // With AS_DEV_ALLOW_INSECURE_CIMD=true, http://127.0.0.1 passes the
    // surface zod shape check and safeFetch attempts a real connection.
    // Pointing at a port we know is closed exercises the operational-error
    // → invalid_client mapping at the route layer (the same mapping that
    // a true SSRFBlockedError would take). The deep dns.lookup test seam
    // isn't exported through @poc/shared, so this is the cleanest way to
    // hit the catch arm without coupling to internal modules.
    const { app } = await buildApp({ AS_DEV_ALLOW_INSECURE_CIMD: "true" });
    const closedUrl = "http://127.0.0.1:1/cimd/client.json";
    const query = buildAuthorizeQuery({ client_id: closedUrl });
    const res = await app.request(`/authorize?${query}`);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("invalid_client");
  });

  it("rejects code_challenge_method=plain", async () => {
    const { app } = await buildApp({ AS_DEV_ALLOW_INSECURE_CIMD: "true" });
    const query = buildAuthorizeQuery({
      client_id: cimdServer.url,
      code_challenge_method: "plain",
    });
    const res = await app.request(`/authorize?${query}`);
    // redirect_uri parsed OK → spec says redirect-with-error.
    expect(res.status).toBe(302);
    const location = res.headers.get("Location") ?? "";
    expect(location).toContain("error=invalid_request");
  });

  it("rejects response_type ≠ code", async () => {
    const { app } = await buildApp({ AS_DEV_ALLOW_INSECURE_CIMD: "true" });
    const query = buildAuthorizeQuery({
      client_id: cimdServer.url,
      response_type: "token",
    });
    const res = await app.request(`/authorize?${query}`);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location") ?? "").toContain("error=unsupported_response_type");
  });

  it("rejects non-URL client_id", async () => {
    const { app } = await buildApp({ AS_DEV_ALLOW_INSECURE_CIMD: "true" });
    const query = buildAuthorizeQuery({ client_id: "not-a-url" });
    const res = await app.request(`/authorize?${query}`);
    // redirect_uri parses, so we redirect with error.
    expect(res.status).toBe(302);
    expect(res.headers.get("Location") ?? "").toContain("error=");
  });

  it("returns 400 when redirect_uri is missing (cannot safely redirect)", async () => {
    const { app } = await buildApp({ AS_DEV_ALLOW_INSECURE_CIMD: "true" });
    const params = new URLSearchParams(buildAuthorizeQuery({ client_id: cimdServer.url }));
    params.delete("redirect_uri");
    const res = await app.request(`/authorize?${params.toString()}`);
    expect(res.status).toBe(400);
    expect(res.headers.get("Location")).toBeNull();
  });

  it("rejects scope outside scopes_supported with invalid_scope redirect", async () => {
    const { app } = await buildApp({ AS_DEV_ALLOW_INSECURE_CIMD: "true" });
    cimdServer.setHandler(() =>
      jsonResponse(buildCIMD(cimdServer.url, ["https://app.example.com/cb"])),
    );
    const query = buildAuthorizeQuery({
      client_id: cimdServer.url,
      scope: "weather:read admin:everything",
    });
    const res = await app.request(`/authorize?${query}`);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location") ?? "";
    expect(location).toContain("error=invalid_scope");
    expect(location).toContain("state=s-12345");
  });

  it("renders consent HTML when AS_AUTO_APPROVE=false", async () => {
    const { app } = await buildApp({ AS_DEV_ALLOW_INSECURE_CIMD: "true" });
    cimdServer.setHandler(() =>
      jsonResponse(buildCIMD(cimdServer.url, ["https://app.example.com/cb"])),
    );
    const query = buildAuthorizeQuery({ client_id: cimdServer.url });
    const res = await app.request(`/authorize?${query}`);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type") ?? "").toMatch(/^text\/html/);
    const setCookie = res.headers.get("Set-Cookie") ?? "";
    expect(setCookie).toContain(SESSION_COOKIE_NAME);
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("Path=/authorize");
    expect(setCookie).toContain("SameSite=Lax");
    const html = await res.text();
    expect(html).toContain("Demo CLI"); // client_name from CIMD
    expect(html).toContain("weather:read"); // scope listed
    expect(html).toContain("/authorize/consent"); // form action
  });

  it("renders a loopback warning when redirect_uri is 127.0.0.1", async () => {
    const { app } = await buildApp({ AS_DEV_ALLOW_INSECURE_CIMD: "true" });
    cimdServer.setHandler(() =>
      jsonResponse(buildCIMD(cimdServer.url, ["http://127.0.0.1:8765/cb"])),
    );
    const query = buildAuthorizeQuery({
      client_id: cimdServer.url,
      redirect_uri: "http://127.0.0.1:8765/cb",
    });
    const res = await app.request(`/authorize?${query}`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toMatch(/Warning.*loopback/i);
  });

  it("treats a 500 from the CIMD server as invalid_client", async () => {
    const { app } = await buildApp({ AS_DEV_ALLOW_INSECURE_CIMD: "true" });
    cimdServer.setHandler(() => new Response("boom", { status: 500 }));
    const query = buildAuthorizeQuery({ client_id: cimdServer.url });
    const res = await app.request(`/authorize?${query}`);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("invalid_client");
  });
});

describe("POST /authorize/consent [§4.5]", () => {
  /** Build a valid signed-session cookie for the consent endpoint. */
  function makeSession(overrides: Partial<ConsentSessionPayload> = {}): {
    cookie: string;
    payload: ConsentSessionPayload;
  } {
    const payload: ConsentSessionPayload = {
      clientId: "http://127.0.0.1:9000/cimd/client.json",
      redirectUri: "https://app.example.com/cb",
      state: "s-12345",
      codeChallenge: "abc123-challenge",
      codeChallengeMethod: "S256",
      scope: "weather:read",
      resource: "https://mcp.example.com",
      csrf: "csrf-token-value",
      iat: Date.now(),
      ...overrides,
    };
    const cookie = signSession(payload);
    return { cookie, payload };
  }

  it("approve → persists auth_code row and redirects with code", async () => {
    const { app, db } = await buildApp();
    const { cookie, payload } = makeSession();
    const setCookie = buildSetCookieHeader(cookie);
    const form = new URLSearchParams({ action: "approve", csrf: payload.csrf });
    const res = await app.request("/authorize/consent", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie: `${SESSION_COOKIE_NAME}=${cookie}`,
      },
      body: form.toString(),
    });
    expect(setCookie).toContain("HttpOnly"); // sanity on helper
    expect(res.status).toBe(302);
    const location = res.headers.get("Location") ?? "";
    const u = new URL(location);
    expect(u.origin + u.pathname).toBe("https://app.example.com/cb");
    expect(u.searchParams.get("state")).toBe(payload.state);
    const code = u.searchParams.get("code");
    expect(code).toMatch(/^[A-Za-z0-9_-]+$/);

    const row = db
      .prepare(
        "SELECT client_id, redirect_uri, scope, resource, sub, used, exp FROM auth_codes WHERE code = ?",
      )
      .get(code) as Record<string, unknown> | undefined;
    expect(row).toBeDefined();
    expect(row?.client_id).toBe(payload.clientId);
    expect(row?.scope).toBe(payload.scope);
    expect(row?.used).toBe(0);
    // exp ≈ now + 60s
    const exp = row?.exp as number;
    expect(exp - Date.now()).toBeGreaterThan(50_000);
    expect(exp - Date.now()).toBeLessThanOrEqual(60_000);
  });

  it("deny → redirect with error=access_denied + state", async () => {
    const { app } = await buildApp();
    const { cookie, payload } = makeSession();
    const form = new URLSearchParams({ action: "deny", csrf: payload.csrf });
    const res = await app.request("/authorize/consent", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie: `${SESSION_COOKIE_NAME}=${cookie}`,
      },
      body: form.toString(),
    });
    expect(res.status).toBe(302);
    const location = res.headers.get("Location") ?? "";
    expect(location).toContain("error=access_denied");
    expect(location).toContain(`state=${payload.state}`);
  });

  it("forged session cookie → reject (400)", async () => {
    const { app } = await buildApp();
    const { payload } = makeSession();
    // Take the legitimate JSON payload but sign it with the wrong key
    // (HMAC with all zeros). The verifier MUST reject.
    const json = JSON.stringify(payload);
    const payloadB64 = Buffer.from(json, "utf8").toString("base64url");
    const fakeSig = Buffer.alloc(32).toString("base64url");
    const forged = `${payloadB64}.${fakeSig}`;
    const form = new URLSearchParams({ action: "approve", csrf: payload.csrf });
    const res = await app.request("/authorize/consent", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie: `${SESSION_COOKIE_NAME}=${forged}`,
      },
      body: form.toString(),
    });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("bad_signature");
  });

  it("missing session cookie → reject (400)", async () => {
    const { app } = await buildApp();
    const form = new URLSearchParams({ action: "approve", csrf: "anything" });
    const res = await app.request("/authorize/consent", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("missing");
  });

  it("CSRF token mismatch → reject (400)", async () => {
    const { app } = await buildApp();
    const { cookie } = makeSession();
    const form = new URLSearchParams({ action: "approve", csrf: "wrong-csrf" });
    const res = await app.request("/authorize/consent", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie: `${SESSION_COOKIE_NAME}=${cookie}`,
      },
      body: form.toString(),
    });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("csrf");
  });

  it("expired session cookie → reject (400)", async () => {
    const { app } = await buildApp();
    // iat 10 minutes ago, TTL is 5 minutes.
    const { cookie, payload } = makeSession({ iat: Date.now() - 10 * 60 * 1000 });
    const form = new URLSearchParams({ action: "approve", csrf: payload.csrf });
    const res = await app.request("/authorize/consent", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie: `${SESSION_COOKIE_NAME}=${cookie}`,
      },
      body: form.toString(),
    });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("expired");
  });

  it("unknown action → reject (400)", async () => {
    const { app } = await buildApp();
    const { cookie, payload } = makeSession();
    const form = new URLSearchParams({ action: "explode", csrf: payload.csrf });
    const res = await app.request("/authorize/consent", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie: `${SESSION_COOKIE_NAME}=${cookie}`,
      },
      body: form.toString(),
    });
    expect(res.status).toBe(400);
  });
});

describe("cimd-cache", () => {
  let cimdServer: CIMDFixtureServer;
  beforeEach(async () => {
    cimdServer = await startCIMDServer();
  });
  afterEach(async () => {
    await cimdServer.close();
  });

  it("caches a fetched CIMD and reuses it on second request", async () => {
    const { app, db } = await buildApp({
      AS_AUTO_APPROVE: "true",
      AS_DEV_ALLOW_INSECURE_CIMD: "true",
    });
    let fetchCount = 0;
    cimdServer.setHandler((path) => {
      if (path === "/cimd/client.json") {
        fetchCount += 1;
        return jsonResponse(buildCIMD(cimdServer.url, ["https://app.example.com/cb"]));
      }
      return new Response("not found", { status: 404 });
    });
    const query = buildAuthorizeQuery({ client_id: cimdServer.url });

    const r1 = await app.request(`/authorize?${query}`);
    expect(r1.status).toBe(302);
    const r2 = await app.request(`/authorize?${query}`);
    expect(r2.status).toBe(302);
    // Two authorize calls, one network fetch — second was a cache hit.
    expect(fetchCount).toBe(1);

    const row = db.prepare("SELECT COUNT(*) AS n FROM cimd_cache").get() as { n: number };
    expect(row.n).toBe(1);
  });
});
