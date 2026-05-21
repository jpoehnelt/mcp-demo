// Cross-app integration test — boots the IdP + MCP server in-process on real
// loopback ports, drives the client's `runFlow` against them, and asserts
// the full end-to-end handshake (including step-up).
//
// Why in-process + real ports:
//   - The client's `runFlow` does real HTTP discovery + token exchange + tool
//     call. `app.request()` (the Hono in-memory invoker) doesn't help us —
//     we'd have to teach `flow.ts` to use it, which would defeat the test's
//     purpose of exercising the production code path.
//   - Test-only seam: `discoverASMetadata` (used by both MCP server boot AND
//     the client) refuses `http://` via `safeFetch`. We swap in a permissive
//     fetcher via the same `__setFetcherForTests` hook the MCP server tests
//     already use.
//
// Spec anchors:
//   - architecture.md §4.1 (audience), §4.5 (resource), §4.7 (WWW-Authenticate),
//     §4.13 (no token in URI), §4.14 (state echo)
//   - client.md §3 (whole section), §4 (security)

import type { AddressInfo } from "node:net";
import { type ServerType, serve } from "@hono/node-server";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runFlow } from "../../apps/mcp-client/src/flow.js";
import { createLogger as createClientLogger } from "../../apps/mcp-client/src/log.js";
import { callMCPTool } from "../../apps/mcp-client/src/mcp-call.js";
import { createMCPServerApp } from "../../apps/mcp-server/src/app.js";
import { parseEnv as parseMCPEnv } from "../../apps/mcp-server/src/env.js";
import { createLogger as createMCPLogger } from "../../apps/mcp-server/src/log.js";
import { createIdPApp } from "../../apps/mock-customer-idp/src/app.js";
import { applySchema, openDatabase } from "../../apps/mock-customer-idp/src/db.js";
import { parseEnv as parseIdPEnv } from "../../apps/mock-customer-idp/src/env.js";
import { loadOrGenerateKey } from "../../apps/mock-customer-idp/src/keys.js";
import { createLogger as createIdPLogger } from "../../apps/mock-customer-idp/src/log.js";
import {
  __setFetcherForTests,
  type SafeFetchOptions,
} from "../../packages/shared/src/oauth/discovery.js";

// ---------------------------------------------------------------------------
// Test fixture: bring up the IdP on a known 127.0.0.1 port.
// ---------------------------------------------------------------------------

interface IdPHandle {
  origin: string;
  close: () => Promise<void>;
}

async function startIdP(): Promise<IdPHandle> {
  const db = openDatabase(":memory:");
  applySchema(db);
  const keys = await loadOrGenerateKey(db, "RS256");
  const log = createIdPLogger({ level: "silent" });

  // Probe-then-rebind: get a free port, free it, reuse the number for the
  // real listener so we can bake the issuer URL into the env before bind.
  const probe = new Hono();
  probe.get("/_probe", (c) => c.text("ok"));
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
    server = serve({ fetch: app.fetch, port, hostname: "127.0.0.1" }, () => resolve());
    server.on("error", reject);
  });

  return {
    origin,
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
// MCP server fixture on a real port.
// ---------------------------------------------------------------------------

interface MCPHandle {
  origin: string;
  close: () => Promise<void>;
}

async function startMCP(idpOrigin: string): Promise<MCPHandle> {
  // Probe for a free port.
  const probe = new Hono();
  probe.get("/_probe", (c) => c.text("ok"));
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
  const env = parseMCPEnv({
    MCP_OIDC_ISSUER_URL: idpOrigin,
    MCP_AUDIENCE: origin,
    MCP_PRM_AUTH_SERVERS: idpOrigin,
  });
  const log = createMCPLogger({ level: "silent" });
  const app = await createMCPServerApp({ env, log });

  let server: ServerType | undefined;
  await new Promise<void>((resolve, reject) => {
    server = serve({ fetch: app.fetch, port, hostname: "127.0.0.1" }, () => resolve());
    server.on("error", reject);
  });

  return {
    origin,
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
// Permissive fetcher for discovery — production refuses http://.
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
// Reporter that captures lines (no stdout writes in tests).
// ---------------------------------------------------------------------------

function makeCapturingReporter(): {
  steps: string[];
  results: string[];
  reporter: { step(line: string): void; result(line: string): void };
} {
  const steps: string[] = [];
  const results: string[] = [];
  return {
    steps,
    results,
    reporter: {
      step(line) {
        steps.push(line);
      },
      result(line) {
        results.push(line);
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe("end-to-end auth flow (in-process)", () => {
  let idp: IdPHandle;
  let mcp: MCPHandle;
  let restoreFetcher: ReturnType<typeof __setFetcherForTests>;

  beforeAll(async () => {
    restoreFetcher = __setFetcherForTests(permissiveFetcher);
    idp = await startIdP();
    mcp = await startMCP(idp.origin);
  }, 20_000);

  afterAll(async () => {
    __setFetcherForTests(restoreFetcher);
    await mcp.close();
    await idp.close();
  });

  // -------------------------------------------------------------------------

  it("happy path: get_weather with weather:read succeeds end-to-end", async () => {
    const { steps, results, reporter } = makeCapturingReporter();
    const log = createClientLogger({ level: "silent" });
    const result = await runFlow(
      {
        server: mcp.origin,
        tool: "get_weather",
        args: { city: "Denver" },
        scope: undefined,
        cimdPort: 0,
        autoOpen: false,
        headless: true,
        verbose: false,
      },
      { log, reporter },
    );
    // Tool succeeded.
    expect(result.stepUpsPerformed).toBe(0);
    const payload = JSON.parse(result.resultText) as {
      city: string;
      tempF: number;
      conditions: string;
    };
    expect(payload.city).toBe("Denver");
    expect(typeof payload.tempF).toBe("number");
    expect(payload.conditions).toBe("sunny");

    // Reporter captured the headline events.
    expect(steps.some((s) => s.includes("Local CIMD server"))).toBe(true);
    expect(steps.some((s) => s.includes("authorization server"))).toBe(true);
    expect(steps.some((s) => s.includes("Authorization code received"))).toBe(true);
    expect(steps.some((s) => s.includes("Token issued"))).toBe(true);
    // result() called exactly once for the happy path.
    expect(results.length).toBe(0); // runFlow doesn't call reporter.result; index.ts does
  }, 15_000);

  // -------------------------------------------------------------------------

  it("[INV-4.1] mid-flow: token minted for a different audience is rejected", async () => {
    // Drive the IdP directly to mint a token whose `aud` is some other URL.
    // The MCP server's verifier MUST reject on canonical-aud mismatch.
    const otherAudience = "http://other.example.com";

    // Run the unauthenticated probe first to capture the 401 challenge so
    // we know the PRM/AS pair to drive (so this test exercises the same
    // discovery path as the happy path).
    const probe = await callMCPTool({
      mcpServerUrl: mcp.origin,
      tool: "get_weather",
      args: { city: "Denver" },
      accessToken: undefined,
    });
    expect(probe.ok).toBe(false);
    if (probe.ok) return;
    expect(probe.kind).toBe("unauthorized");

    // Mint a token via the IdP's authorize+token flow with a bad audience.
    const { token } = await mintTokenForResource(idp.origin, otherAudience, "weather:read");

    // Use the bad-audience token against the MCP server.
    const callRes = await callMCPTool({
      mcpServerUrl: mcp.origin,
      tool: "get_weather",
      args: { city: "Denver" },
      accessToken: token,
    });
    expect(callRes.ok).toBe(false);
    if (callRes.ok) return;
    expect(callRes.kind).toBe("unauthorized");
    expect(callRes.status).toBe(401);
  }, 15_000);

  // -------------------------------------------------------------------------

  it("step-up: get_premium_forecast triggers step-up and succeeds", async () => {
    const log = createClientLogger({ level: "silent" });
    const { steps, reporter } = makeCapturingReporter();
    const result = await runFlow(
      {
        server: mcp.origin,
        tool: "get_premium_forecast",
        args: { city: "Denver" },
        // Force the initial token to lack `weather:premium` — that scope is
        // NOT in PRM.scopes_supported (only weather:read is), so the initial
        // authorize round picks just weather:read. The MCP server returns
        // 403 insufficient_scope, the client re-authorizes with
        // weather:premium added (union), and succeeds on the retry.
        scope: undefined,
        cimdPort: 0,
        autoOpen: false,
        headless: true,
        verbose: false,
      },
      { log, reporter },
    );
    expect(result.stepUpsPerformed).toBeGreaterThanOrEqual(1);
    expect(result.finalScope.split(/\s+/)).toContain("weather:premium");
    const payload = JSON.parse(result.resultText) as {
      city: string;
      forecast: { day: number; tempF: number; conditions: string }[];
    };
    expect(payload.city).toBe("Denver");
    expect(payload.forecast).toHaveLength(14);
    expect(steps.some((s) => s.toLowerCase().includes("step-up"))).toBe(true);
  }, 20_000);
});

// ---------------------------------------------------------------------------
// Helper: mint a token via the IdP's authorize+token endpoints for an
// arbitrary (resource, scope). Mirrors the helper in the MCP server's
// integration tests; lifted in-line so this file stays self-contained.
// ---------------------------------------------------------------------------

async function mintTokenForResource(
  idpOrigin: string,
  resource: string,
  scope: string,
): Promise<{ token: string; refreshToken: string | undefined }> {
  // The IdP requires a CIMD URL that resolves; reuse a tiny inline fixture.
  // We need to bring up a one-shot CIMD server because the IdP fetches the
  // doc on /authorize.
  const cimd = await startCIMDFixture();
  try {
    const { createHash, randomBytes } = await import("node:crypto");
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
    const authRes = await fetch(`${idpOrigin}/authorize?${authQuery.toString()}`, {
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
    const tokenRes = await fetch(`${idpOrigin}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: tokenBody.toString(),
    });
    if (tokenRes.status !== 200) {
      throw new Error(`expected 200 from /token, got ${String(tokenRes.status)}`);
    }
    const json = (await tokenRes.json()) as { access_token: string; refresh_token?: string };
    return { token: json.access_token, refreshToken: json.refresh_token };
  } finally {
    await cimd.close();
  }
}

interface CIMDFixture {
  url: string;
  close: () => Promise<void>;
}

async function startCIMDFixture(): Promise<CIMDFixture> {
  const app = new Hono();
  let selfUrl = "";
  app.get("/cimd/client.json", (c) =>
    c.json({
      client_id: selfUrl,
      client_name: "Test Client",
      client_uri: "http://example.invalid",
      redirect_uris: ["https://app.example.com/cb"],
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
  selfUrl = `http://127.0.0.1:${String(port)}/cimd/client.json`;
  return {
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
