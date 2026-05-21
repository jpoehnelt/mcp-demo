import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { InvalidTokenError, SSRFBlockedError } from "../errors.js";
import type { SafeFetchOptions } from "../http/ssrf.js";
import { canonicalize } from "./canonical-uri.js";
import { __setFetcherForTests, discoverASMetadata, fetchPRM, resolvePRMUrl } from "./discovery.js";

// ---------------------------------------------------------------------------
// resolvePRMUrl — pure function, table-driven.
// ---------------------------------------------------------------------------

describe("resolvePRMUrl", () => {
  const cases: Array<[string, string, string]> = [
    [
      "bare domain (no path)",
      "https://example.com",
      "https://example.com/.well-known/oauth-protected-resource",
    ],
    [
      "single-segment path",
      "https://example.com/mcp",
      "https://example.com/.well-known/oauth-protected-resource/mcp",
    ],
    [
      "multi-segment path",
      "https://example.com/public/mcp",
      "https://example.com/.well-known/oauth-protected-resource/public/mcp",
    ],
    [
      "non-default port preserved",
      "https://example.com:8443/mcp",
      "https://example.com:8443/.well-known/oauth-protected-resource/mcp",
    ],
  ];

  it.each(cases)("resolves %s", (_label, input, expected) => {
    expect(resolvePRMUrl(canonicalize(input))).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// Test fetcher harness
// ---------------------------------------------------------------------------

type FetcherFn = (
  url: string,
  opts: SafeFetchOptions,
) => Promise<{ status: number; body: string; headers: Headers }>;

interface CallLog {
  calls: string[];
}

function buildFetcherTable(
  table: Record<string, { status: number; body: string; contentType?: string }>,
  log?: CallLog,
): FetcherFn {
  return (url: string, _opts: SafeFetchOptions) => {
    if (log !== undefined) log.calls.push(url);
    const entry = table[url];
    if (entry === undefined) {
      // Mimic safeFetch's behaviour for a 404 — return the 404 (caller
      // schema-parse will fail; discovery treats that as a soft miss).
      const headers404 = new Headers();
      headers404.set("content-type", "application/json");
      return Promise.resolve({
        status: 404,
        body: '{"error":"not_found"}',
        headers: headers404,
      });
    }
    const headers = new Headers();
    headers.set("content-type", entry.contentType ?? "application/json");
    return Promise.resolve({ status: entry.status, body: entry.body, headers });
  };
}

const validASMetadata = {
  issuer: "https://idp.example.com/tenant1",
  authorization_endpoint: "https://idp.example.com/tenant1/authorize",
  token_endpoint: "https://idp.example.com/tenant1/token",
  jwks_uri: "https://idp.example.com/tenant1/jwks.json",
  response_types_supported: ["code"],
  code_challenge_methods_supported: ["S256"],
};

// ---------------------------------------------------------------------------
// discoverASMetadata cascade
// ---------------------------------------------------------------------------

describe("discoverASMetadata cascade", () => {
  let restoreFetcher: FetcherFn | null = null;

  afterEach(() => {
    if (restoreFetcher !== null) {
      __setFetcherForTests(restoreFetcher);
      restoreFetcher = null;
    }
  });

  it("step 1: returns metadata from path-inserted oauth-authorization-server", async () => {
    const log: CallLog = { calls: [] };
    restoreFetcher = __setFetcherForTests(
      buildFetcherTable(
        {
          "https://idp.example.com/.well-known/oauth-authorization-server/tenant1": {
            status: 200,
            body: JSON.stringify(validASMetadata),
          },
        },
        log,
      ),
    );
    const metadata = await discoverASMetadata(canonicalize("https://idp.example.com/tenant1"));
    expect(metadata.issuer).toBe("https://idp.example.com/tenant1");
    // Only one fetch attempted — step 1 hit.
    expect(log.calls).toEqual([
      "https://idp.example.com/.well-known/oauth-authorization-server/tenant1",
    ]);
  });

  it("step 2: falls back to path-inserted openid-configuration when step 1 misses", async () => {
    const log: CallLog = { calls: [] };
    restoreFetcher = __setFetcherForTests(
      buildFetcherTable(
        {
          "https://idp.example.com/.well-known/openid-configuration/tenant1": {
            status: 200,
            body: JSON.stringify(validASMetadata),
          },
        },
        log,
      ),
    );
    const metadata = await discoverASMetadata(canonicalize("https://idp.example.com/tenant1"));
    expect(metadata.token_endpoint).toBe("https://idp.example.com/tenant1/token");
    expect(log.calls).toEqual([
      "https://idp.example.com/.well-known/oauth-authorization-server/tenant1",
      "https://idp.example.com/.well-known/openid-configuration/tenant1",
    ]);
  });

  it("step 3: falls back to path-APPENDED openid-configuration (OIDC legacy)", async () => {
    const log: CallLog = { calls: [] };
    restoreFetcher = __setFetcherForTests(
      buildFetcherTable(
        {
          "https://idp.example.com/tenant1/.well-known/openid-configuration": {
            status: 200,
            body: JSON.stringify(validASMetadata),
          },
        },
        log,
      ),
    );
    const metadata = await discoverASMetadata(canonicalize("https://idp.example.com/tenant1"));
    expect(metadata.jwks_uri).toBe("https://idp.example.com/tenant1/jwks.json");
    expect(log.calls).toEqual([
      "https://idp.example.com/.well-known/oauth-authorization-server/tenant1",
      "https://idp.example.com/.well-known/openid-configuration/tenant1",
      "https://idp.example.com/tenant1/.well-known/openid-configuration",
    ]);
  });

  it("exhausts the cascade and throws when no step succeeds", async () => {
    const log: CallLog = { calls: [] };
    restoreFetcher = __setFetcherForTests(buildFetcherTable({}, log));
    await expect(
      discoverASMetadata(canonicalize("https://idp.example.com/tenant1")),
    ).rejects.toBeInstanceOf(InvalidTokenError);
    // Confirm all three URLs were attempted in order.
    expect(log.calls).toEqual([
      "https://idp.example.com/.well-known/oauth-authorization-server/tenant1",
      "https://idp.example.com/.well-known/openid-configuration/tenant1",
      "https://idp.example.com/tenant1/.well-known/openid-configuration",
    ]);
  });

  it("hard-fails when metadata lacks S256 in code_challenge_methods_supported", async () => {
    restoreFetcher = __setFetcherForTests(
      buildFetcherTable({
        "https://idp.example.com/.well-known/oauth-authorization-server/tenant1": {
          status: 200,
          body: JSON.stringify({
            ...validASMetadata,
            code_challenge_methods_supported: ["plain"],
          }),
        },
      }),
    );
    await expect(
      discoverASMetadata(canonicalize("https://idp.example.com/tenant1")),
    ).rejects.toThrow(/S256/);
  });

  it("treats safeFetch errors as soft misses (continues cascade)", async () => {
    const log: CallLog = { calls: [] };
    let stepCount = 0;
    restoreFetcher = __setFetcherForTests((url: string) => {
      log.calls.push(url);
      stepCount += 1;
      if (stepCount < 3) {
        return Promise.reject(new SSRFBlockedError(`simulated network error on ${url}`));
      }
      const headers = new Headers();
      headers.set("content-type", "application/json");
      return Promise.resolve({
        status: 200,
        body: JSON.stringify(validASMetadata),
        headers,
      });
    });
    const metadata = await discoverASMetadata(canonicalize("https://idp.example.com/tenant1"));
    expect(metadata.issuer).toBe("https://idp.example.com/tenant1");
    expect(log.calls).toHaveLength(3);
  });

  it("path-insertion is correct for bare-domain issuer (no path)", async () => {
    const log: CallLog = { calls: [] };
    restoreFetcher = __setFetcherForTests(
      buildFetcherTable(
        {
          "https://idp.example.com/.well-known/oauth-authorization-server": {
            status: 200,
            body: JSON.stringify({
              ...validASMetadata,
              issuer: "https://idp.example.com",
              authorization_endpoint: "https://idp.example.com/authorize",
              token_endpoint: "https://idp.example.com/token",
              jwks_uri: "https://idp.example.com/jwks.json",
            }),
          },
        },
        log,
      ),
    );
    const metadata = await discoverASMetadata(canonicalize("https://idp.example.com"));
    expect(metadata.issuer).toBe("https://idp.example.com");
    expect(log.calls[0]).toBe("https://idp.example.com/.well-known/oauth-authorization-server");
  });

  it("treats malformed JSON body as a soft miss and falls through", async () => {
    const log: CallLog = { calls: [] };
    restoreFetcher = __setFetcherForTests(
      buildFetcherTable(
        {
          "https://idp.example.com/.well-known/oauth-authorization-server/tenant1": {
            status: 200,
            body: "this is not json",
          },
          "https://idp.example.com/tenant1/.well-known/openid-configuration": {
            status: 200,
            body: JSON.stringify(validASMetadata),
          },
        },
        log,
      ),
    );
    const metadata = await discoverASMetadata(canonicalize("https://idp.example.com/tenant1"));
    expect(metadata.issuer).toBe("https://idp.example.com/tenant1");
    expect(log.calls).toHaveLength(3);
  });
});

// ---------------------------------------------------------------------------
// fetchPRM
// ---------------------------------------------------------------------------

describe("fetchPRM", () => {
  let restoreFetcher: FetcherFn | null = null;

  beforeEach(() => {
    // no-op; per-test wiring.
  });

  afterEach(() => {
    if (restoreFetcher !== null) {
      __setFetcherForTests(restoreFetcher);
      restoreFetcher = null;
    }
  });

  it("parses a valid PRM document", async () => {
    restoreFetcher = __setFetcherForTests(
      buildFetcherTable({
        "https://example.com/.well-known/oauth-protected-resource/mcp": {
          status: 200,
          body: JSON.stringify({
            resource: "https://example.com/mcp",
            authorization_servers: ["https://idp.example.com"],
            scopes_supported: ["read", "write"],
          }),
        },
      }),
    );
    const prm = await fetchPRM("https://example.com/.well-known/oauth-protected-resource/mcp");
    expect(prm.resource).toBe("https://example.com/mcp");
    expect(prm.authorization_servers).toEqual(["https://idp.example.com"]);
    // Default applied:
    expect(prm.bearer_methods_supported).toEqual(["header"]);
  });

  it("throws InvalidTokenError on malformed JSON", async () => {
    restoreFetcher = __setFetcherForTests(
      buildFetcherTable({
        "https://example.com/.well-known/oauth-protected-resource/mcp": {
          status: 200,
          body: "not json",
        },
      }),
    );
    await expect(
      fetchPRM("https://example.com/.well-known/oauth-protected-resource/mcp"),
    ).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it("propagates fetcher errors (e.g. SSRF block)", async () => {
    restoreFetcher = __setFetcherForTests((url: string) => {
      return Promise.reject(new SSRFBlockedError(`blocked ${url}`));
    });
    await expect(
      fetchPRM("https://example.com/.well-known/oauth-protected-resource"),
    ).rejects.toBeInstanceOf(SSRFBlockedError);
  });
});
