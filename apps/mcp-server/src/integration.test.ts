// In-process integration tests for the MCP resource server.
//
// Pattern (per slice 10 prompt):
//   1. Stand up a real in-process IdP (slice 6+) on an ephemeral 127.0.0.1
//      port. The MCP server's RFC 8414 metadata discovery and the shared
//      `jose.createRemoteJWKSet` JWKS fetcher both do real HTTP, so we need
//      an actual listener — `app.request()` is not enough.
//   2. The shared `discoverASMetadata` runs through `safeFetch`, which
//      blocks plaintext `http://` unless `allowInsecure=true`. The fetcher
//      module's `__setFetcherForTests` seam lets us swap in a permissive
//      fetcher just for the test process. The verifier's `jose` JWKS fetch
//      goes directly through Node's `http` (not through `safeFetch`), so it
//      works against `http://127.0.0.1:<port>/jwks.json` out of the box.
//   3. Mint real tokens via the IdP's /authorize + /token flow so the
//      happy-path tokens carry the right `iss`/`aud`/`alg`/`kid` for the
//      MCP server's verifier to accept.
//
// Spec anchors:
//   - specs/resource-server.md §3 (PRM), §4.1 (middleware behavior)
//   - specs/architecture.md invariants §4.1 (aud), §4.3 (alg allowlist),
//     §4.7 (WWW-Authenticate), §4.13 (no token in URI)

import { createHash, randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import { type ServerType, serve } from "@hono/node-server";
import { type CanonicalURI, canonicalize } from "@poc/shared";
import { Hono } from "hono";
import { SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ZodError } from "zod";
// Direct internal import of the discovery test seam. The barrel doesn't
// re-export `__setFetcherForTests` because it's intentionally a test-only
// hook; vitest's @poc/shared alias points at the package src root, so this
// relative import resolves through the same TypeScript composite project.
import {
  __setFetcherForTests,
  type SafeFetchOptions,
} from "../../../packages/shared/src/oauth/discovery.js";
import { createIdPApp } from "../../mock-customer-idp/src/app.js";
import { applySchema, openDatabase } from "../../mock-customer-idp/src/db.js";
import { parseEnv as parseIdPEnv } from "../../mock-customer-idp/src/env.js";
import { loadOrGenerateKey } from "../../mock-customer-idp/src/keys.js";
import { createLogger as createIdPLogger } from "../../mock-customer-idp/src/log.js";
import type { MCPServerApp } from "./app.js";
import { createMCPServerApp } from "./app.js";
import { parseEnv } from "./env.js";
import { createLogger } from "./log.js";

// ---------------------------------------------------------------------------
// In-process IdP listener
// ---------------------------------------------------------------------------

interface IdPHandle {
  origin: string;
  app: ReturnType<typeof createIdPApp>;
  keys: Awaited<ReturnType<typeof loadOrGenerateKey>>;
  close: () => Promise<void>;
}

async function startIdP(): Promise<IdPHandle> {
  // 1. Bind on an ephemeral port to learn the URL before constructing the
  //    IdP env (the issuer URL must match the listening port byte-for-byte).
  const db = openDatabase(":memory:");
  applySchema(db);
  const keys = await loadOrGenerateKey(db, "RS256");
  const log = createIdPLogger({ level: "silent" });

  // First we need to know the port, but the IdP env needs the URL up front
  // (it's baked into AS metadata). Strategy: bind a placeholder Hono app on
  // port 0 to discover the port, close it, then start the real IdP on that
  // port. Race-y in principle, fine in practice for tests.
  const probe = new Hono();
  probe.get("/_probe", (c) => c.text("probe"));
  let probeServer: ServerType | undefined;
  const port: number = await new Promise((resolve, reject) => {
    probeServer = serve({ fetch: probe.fetch, port: 0, hostname: "127.0.0.1" }, (info) => {
      resolve((info as AddressInfo).port);
    });
    probeServer.on("error", reject);
  });
  await new Promise<void>((resolve, reject) => {
    probeServer?.close((err) => (err !== undefined ? reject(err) : resolve()));
  });

  const origin = `http://127.0.0.1:${String(port)}`;
  const env = parseIdPEnv({
    AS_ISSUER_URL: origin,
    AS_AUTO_APPROVE: "true",
    AS_DEV_ALLOW_INSECURE_CIMD: "true",
  });

  const app = createIdPApp({ env, db, log, keys });

  let server: ServerType | undefined;
  await new Promise<void>((resolve, reject) => {
    server = serve({ fetch: app.fetch, port, hostname: "127.0.0.1" }, () => {
      resolve();
    });
    server.on("error", reject);
  });

  return {
    origin,
    app,
    keys,
    close: () =>
      new Promise<void>((resolve, reject) => {
        if (server === undefined) {
          resolve();
          return;
        }
        server.close((err) => (err !== undefined ? reject(err) : resolve()));
      }),
  };
}

// ---------------------------------------------------------------------------
// CIMD fixture server — needed by /authorize to fetch the client's CIMD.
// ---------------------------------------------------------------------------

interface CIMDFixture {
  origin: string;
  url: string;
  close: () => Promise<void>;
}

async function startCIMDFixture(redirectUris: string[]): Promise<CIMDFixture> {
  const app = new Hono();
  // `client_id` must be a self-pointer that matches the fetch URL.
  let selfUrl = "";
  app.get("/cimd/client.json", (c) =>
    c.json({
      client_id: selfUrl,
      client_name: "Test Client",
      client_uri: "http://example.invalid",
      redirect_uris: redirectUris,
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }),
  );
  let server: ServerType | undefined;
  const port: number = await new Promise((resolve, reject) => {
    server = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" }, (info) => {
      resolve((info as AddressInfo).port);
    });
    server.on("error", reject);
  });
  const origin = `http://127.0.0.1:${String(port)}`;
  selfUrl = `${origin}/cimd/client.json`;
  return {
    origin,
    url: selfUrl,
    close: () =>
      new Promise<void>((resolve, reject) => {
        if (server === undefined) {
          resolve();
          return;
        }
        server.close((err) => (err !== undefined ? reject(err) : resolve()));
      }),
  };
}

// ---------------------------------------------------------------------------
// Permissive fetcher for tests. Mirrors `safeFetch`'s return shape but
// makes real HTTP calls via the built-in `fetch`. We swap it in for the
// duration of the test file so `discoverASMetadata` can reach the in-process
// IdP at `http://127.0.0.1:<port>`.
// ---------------------------------------------------------------------------

async function permissiveFetcher(
  url: string,
  _opts: SafeFetchOptions,
): Promise<{ status: number; body: string; headers: Headers }> {
  const res = await fetch(url);
  const body = await res.text();
  return { status: res.status, body, headers: res.headers };
}

// ---------------------------------------------------------------------------
// /authorize → /token helper. Drives the in-process IdP to mint a real
// signed access token for `(resource, scope)`.
// ---------------------------------------------------------------------------

async function mintTokenViaIdP(
  idp: IdPHandle,
  cimd: CIMDFixture,
  resource: string,
  scope = "weather:read",
): Promise<string> {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const redirectUri = "https://app.example.com/cb";

  const authQuery = new URLSearchParams({
    response_type: "code",
    client_id: cimd.url,
    redirect_uri: redirectUri,
    scope,
    state: "s-1",
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource,
  });
  const authRes = await fetch(`${idp.origin}/authorize?${authQuery.toString()}`, {
    redirect: "manual",
  });
  if (authRes.status !== 302) {
    throw new Error(`expected 302 from /authorize, got ${String(authRes.status)}`);
  }
  const location = authRes.headers.get("location");
  if (location === null) throw new Error("missing Location from /authorize");
  const code = new URL(location).searchParams.get("code");
  if (code === null) throw new Error("missing code from /authorize redirect");

  const tokenBody = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: cimd.url,
    redirect_uri: redirectUri,
    code_verifier: verifier,
    resource,
  });
  const tokenRes = await fetch(`${idp.origin}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: tokenBody.toString(),
  });
  if (tokenRes.status !== 200) {
    throw new Error(`expected 200 from /token, got ${String(tokenRes.status)}`);
  }
  const tokenJson = (await tokenRes.json()) as { access_token: string };
  return tokenJson.access_token;
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe("MCP server integration", () => {
  let idp: IdPHandle;
  let cimd: CIMDFixture;
  let mcp: MCPServerApp;
  let mcpAudience: string;
  let restoreFetcher: ReturnType<typeof __setFetcherForTests>;

  beforeAll(async () => {
    // Bring up the IdP first so its origin can flow into MCP env config.
    idp = await startIdP();
    cimd = await startCIMDFixture(["https://app.example.com/cb"]);

    // Swap in the permissive fetcher for the duration of this test file —
    // production discovery refuses `http://`, but the in-process IdP is on
    // loopback HTTP.
    restoreFetcher = __setFetcherForTests(permissiveFetcher);

    mcpAudience = "http://localhost:3333";
    const mcpEnv = parseEnv({
      MCP_OIDC_ISSUER_URL: idp.origin,
      MCP_AUDIENCE: mcpAudience,
      MCP_PRM_AUTH_SERVERS: idp.origin,
    });
    const log = createLogger({ level: "silent" });
    mcp = await createMCPServerApp({ env: mcpEnv, log });
  });

  afterAll(async () => {
    __setFetcherForTests(restoreFetcher);
    await cimd.close();
    await idp.close();
  });

  // -------------------------------------------------------------------------
  // /healthz
  // -------------------------------------------------------------------------

  it("/healthz returns 200", async () => {
    const res = await mcp.request("/healthz");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body).toEqual({ status: "ok" });
  });

  // -------------------------------------------------------------------------
  // PRM
  // -------------------------------------------------------------------------

  it("PRM returns canonical resource + authorization_servers + scopes_supported", async () => {
    const res = await mcp.request("/.well-known/oauth-protected-resource");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type") ?? "").toMatch(/^application\/json/);
    expect(res.headers.get("Cache-Control")).toBe("max-age=3600");
    const body = (await res.json()) as {
      resource: string;
      authorization_servers: string[];
      scopes_supported: string[];
      bearer_methods_supported: string[];
    };
    expect(body.resource).toBe(mcpAudience);
    expect(body.authorization_servers).toEqual([idp.origin]);
    // §3.1: PRM only advertises the minimum scope; premium surfaces via
    // 403 step-up.
    expect(body.scopes_supported).toEqual(["weather:read"]);
    expect(body.bearer_methods_supported).toEqual(["header"]);
  });

  // -------------------------------------------------------------------------
  // Auth middleware — failure paths
  // -------------------------------------------------------------------------

  it("[INV-4.7] /mcp without auth → 401 + WWW-Authenticate", async () => {
    const res = await mcp.request("/mcp", { method: "POST" });
    expect(res.status).toBe(401);
    const h = res.headers.get("WWW-Authenticate");
    expect(h).not.toBeNull();
    expect(h).toContain("Bearer");
    expect(h).toContain(`realm="${mcpAudience}"`);
    expect(h).toContain(`resource_metadata="${mcpAudience}/.well-known/oauth-protected-resource"`);
    expect(h).toContain('scope="weather:read"');
  });

  it("/mcp with non-Bearer scheme → 401", async () => {
    const res = await mcp.request("/mcp", {
      method: "POST",
      headers: { authorization: "Basic dXNlcjpwYXNz" },
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toContain("Bearer");
  });

  it("[INV-4.1] /mcp with wrong-aud token → 401", async () => {
    // Mint a token whose `aud` is some other resource; the MCP server's
    // verifier MUST reject on canonical-aud mismatch.
    const otherAudience = "http://other.example.com";
    const token = await mintTokenViaIdP(idp, cimd, otherAudience);
    const res = await mcp.request("/mcp", {
      method: "POST",
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toContain("Bearer");
  });

  it("[INV-4.3] /mcp with HS256 forged token → 401", async () => {
    // Hand-forge an HS256 token. Even though the secret is bogus, the
    // verifier MUST reject on the alg before considering the signature.
    const secret = new TextEncoder().encode("not-the-real-key");
    const nowSec = Math.floor(Date.now() / 1000);
    const forged = await new SignJWT({
      scope: "weather:read",
      client_id: cimd.url,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer(idp.origin)
      .setAudience(mcpAudience)
      .setSubject("demo-user")
      .setIssuedAt(nowSec)
      .setExpirationTime(nowSec + 300)
      .setJti("forged-jti")
      .sign(secret);

    const res = await mcp.request("/mcp", {
      method: "POST",
      headers: { authorization: `Bearer ${forged}` },
    });
    expect(res.status).toBe(401);
  });

  it("[INV-4.13] /mcp with token in query string → 401", async () => {
    const res = await mcp.request("/mcp?access_token=eyJhbGciOiJSUzI1NiI.fake.fake", {
      method: "POST",
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toContain("Bearer");
  });

  it("/mcp with malformed (non-JWT) token → 401", async () => {
    const res = await mcp.request("/mcp", {
      method: "POST",
      headers: { authorization: "Bearer not-a-jwt" },
    });
    expect(res.status).toBe(401);
  });

  // -------------------------------------------------------------------------
  // Auth middleware — success path
  // -------------------------------------------------------------------------

  it("/mcp with valid token → 200 stub", async () => {
    const token = await mintTokenViaIdP(idp, cimd, mcpAudience);
    const res = await mcp.request("/mcp", {
      method: "POST",
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean };
    expect(body.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// parseEnv — pure unit tests (no IdP needed)
// ---------------------------------------------------------------------------

describe("parseEnv", () => {
  const VALID = {
    MCP_OIDC_ISSUER_URL: "http://localhost:4444",
    MCP_AUDIENCE: "http://localhost:3333",
    MCP_PRM_AUTH_SERVERS: "http://localhost:4444",
  };

  it("parses the canonical happy path", () => {
    const env = parseEnv(VALID);
    expect(env.MCP_OIDC_ISSUER_URL).toBe("http://localhost:4444");
    expect(env.MCP_AUDIENCE).toBe("http://localhost:3333");
    expect(env.MCP_PRM_AUTH_SERVERS).toEqual(["http://localhost:4444"]);
    expect(env.MCP_PORT).toBe(3333);
  });

  it("canonicalizes each URL (drops trailing slash)", () => {
    const env = parseEnv({
      MCP_OIDC_ISSUER_URL: "http://localhost:4444/",
      MCP_AUDIENCE: "http://localhost:3333/",
      MCP_PRM_AUTH_SERVERS: "http://localhost:4444/, http://localhost:5555/",
    });
    expect(env.MCP_OIDC_ISSUER_URL).toBe("http://localhost:4444");
    expect(env.MCP_AUDIENCE).toBe("http://localhost:3333");
    expect(env.MCP_PRM_AUTH_SERVERS).toEqual(["http://localhost:4444", "http://localhost:5555"]);
  });

  it("parses MCP_PRM_AUTH_SERVERS as comma-separated, preserving order", () => {
    const env = parseEnv({
      ...VALID,
      MCP_PRM_AUTH_SERVERS: "http://a.example.com,http://b.example.com,http://c.example.com",
    });
    expect(env.MCP_PRM_AUTH_SERVERS).toEqual([
      "http://a.example.com",
      "http://b.example.com",
      "http://c.example.com",
    ]);
  });

  it("rejects an empty MCP_PRM_AUTH_SERVERS list (only commas/whitespace)", () => {
    expect(() => parseEnv({ ...VALID, MCP_PRM_AUTH_SERVERS: " , , " })).toThrow(ZodError);
  });

  it("rejects malformed URL in MCP_PRM_AUTH_SERVERS", () => {
    expect(() =>
      parseEnv({ ...VALID, MCP_PRM_AUTH_SERVERS: "http://ok.example.com,not-a-url" }),
    ).toThrow(ZodError);
  });

  it("throws ZodError when MCP_OIDC_ISSUER_URL is missing", () => {
    expect(() => parseEnv({ MCP_AUDIENCE: "http://x", MCP_PRM_AUTH_SERVERS: "http://y" })).toThrow(
      ZodError,
    );
  });

  it("coerces MCP_PORT from string", () => {
    const env = parseEnv({ ...VALID, MCP_PORT: "9999" });
    expect(env.MCP_PORT).toBe(9999);
  });

  it("rejects non-positive MCP_PORT", () => {
    expect(() => parseEnv({ ...VALID, MCP_PORT: "0" })).toThrow(ZodError);
    expect(() => parseEnv({ ...VALID, MCP_PORT: "-1" })).toThrow(ZodError);
  });

  it("MCP_AUDIENCE round-trips through canonicalize", () => {
    const env = parseEnv({ ...VALID, MCP_AUDIENCE: "HTTP://LOCALHOST:3333/" });
    expect(env.MCP_AUDIENCE).toBe(canonicalize("http://localhost:3333" as CanonicalURI));
  });
});
