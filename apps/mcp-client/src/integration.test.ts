// In-process integration tests for the MCP client's local CIMD + callback
// server and the CLI argument parser.
//
// Cross-app tests that boot a real IdP + MCP server live in
// test/integration/auth-flow.test.ts.

import { Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import { startCIMDServer } from "./cimd-server.js";
import { parseOptions } from "./cli.js";
import { unionScopes } from "./flow.js";
import { _redactPathsForTest, createLogger } from "./log.js";

// ---------------------------------------------------------------------------
// startCIMDServer
// ---------------------------------------------------------------------------

describe("startCIMDServer — local CIMD + callback server", () => {
  it("GET /client.json returns the expected CIMD shape; binds to 127.0.0.1", async () => {
    const handle = await startCIMDServer({ port: 0 });
    try {
      // We MUST be able to reach the server at 127.0.0.1 literally; if it
      // had bound to ::1 (localhost on some macOS configs) this would fail.
      const res = await fetch(`http://127.0.0.1:${String(handle.port)}/client.json`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as Record<string, unknown>;

      expect(body.client_id).toBe(`http://127.0.0.1:${String(handle.port)}/client.json`);
      expect(body.redirect_uris).toEqual([`http://127.0.0.1:${String(handle.port)}/callback`]);
      expect(body.client_name).toBe("MCP Demo Client");
      expect(body.grant_types).toEqual(["authorization_code", "refresh_token"]);
      expect(body.response_types).toEqual(["code"]);
      expect(body.token_endpoint_auth_method).toBe("none");
      // client_id MUST canonically equal the URL the document is served at
      // (spec §2.1) — sanity-check the textual equality here; the IdP
      // performs the canonical comparison itself.
      expect(body.client_id).toBe(handle.clientIdUrl);
    } finally {
      await handle.close();
    }
  });

  it("GET /callback captures code+state and responds 200", async () => {
    const handle = await startCIMDServer({ port: 0 });
    try {
      const captured = handle.waitForCallback();
      const res = await fetch(
        `http://127.0.0.1:${String(handle.port)}/callback?code=abc&state=xyz`,
      );
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toMatch(/Authorization complete/i);

      const payload = await captured;
      expect(payload.code).toBe("abc");
      expect(payload.state).toBe("xyz");
      expect(payload.error).toBeUndefined();
    } finally {
      await handle.close();
    }
  });

  it("GET /callback with error short-circuits (no code, error present)", async () => {
    const handle = await startCIMDServer({ port: 0 });
    try {
      const captured = handle.waitForCallback();
      const res = await fetch(
        `http://127.0.0.1:${String(handle.port)}/callback?error=access_denied&error_description=user+said+no&state=xyz`,
      );
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toMatch(/Authorization failed/i);

      const payload = await captured;
      expect(payload.code).toBeUndefined();
      expect(payload.error).toBe("access_denied");
      expect(payload.errorDescription).toBe("user said no");
      expect(payload.state).toBe("xyz");
    } finally {
      await handle.close();
    }
  });

  it("close() is idempotent", async () => {
    const handle = await startCIMDServer({ port: 0 });
    await handle.close();
    await expect(handle.close()).resolves.toBeUndefined();
  });

  it("404 for unknown paths", async () => {
    const handle = await startCIMDServer({ port: 0 });
    try {
      const res = await fetch(`http://127.0.0.1:${String(handle.port)}/admin`);
      expect(res.status).toBe(404);
    } finally {
      await handle.close();
    }
  });
});

// ---------------------------------------------------------------------------
// parseOptions
// ---------------------------------------------------------------------------

describe("parseOptions", () => {
  it("applies defaults when nothing is provided", () => {
    const opts = parseOptions({});
    expect(opts.server).toBe("http://localhost:3333");
    expect(opts.tool).toBe("get_weather");
    expect(opts.args).toEqual({ city: "Denver" });
    expect(opts.cimdPort).toBe(7777);
    expect(opts.headless).toBe(false);
    expect(opts.verbose).toBe(false);
    expect(opts.scope).toBeUndefined();
  });

  it("parses --args JSON objects", () => {
    const opts = parseOptions({ args: '{"city":"Seattle","unit":"C"}' });
    expect(opts.args).toEqual({ city: "Seattle", unit: "C" });
  });

  it("rejects non-object --args (arrays, scalars)", () => {
    expect(() => parseOptions({ args: '["denver"]' })).toThrow(/JSON object/);
    expect(() => parseOptions({ args: '"denver"' })).toThrow(/JSON object/);
  });

  it("rejects malformed --args JSON", () => {
    expect(() => parseOptions({ args: "{not json" })).toThrow(/valid JSON/);
  });

  it("coerces --cimd-port from string", () => {
    const opts = parseOptions({ cimdPort: "5555" });
    expect(opts.cimdPort).toBe(5555);
  });

  it("rejects out-of-range ports", () => {
    expect(() => parseOptions({ cimdPort: "0" })).toThrow();
    expect(() => parseOptions({ cimdPort: "99999" })).toThrow();
  });

  it("auto-open defaults to false when --headless is set", () => {
    const opts = parseOptions({ headless: true });
    expect(opts.headless).toBe(true);
    expect(opts.autoOpen).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// log redaction [INV-4.12]
// ---------------------------------------------------------------------------

describe("logging redaction [INV-4.12]", () => {
  it("redacts tokens, codes, code_verifier from log output", () => {
    const lines: string[] = [];
    const stream = new Writable({
      write(chunk, _enc, cb) {
        lines.push(chunk.toString("utf8"));
        cb();
      },
    });
    const log = createLogger({ level: "info", destination: stream });

    log.info(
      {
        access_token: "at-secret-AAA",
        refresh_token: "rt-secret-BBB",
        code: "code-secret-CCC",
        code_verifier: "cv-secret-DDD",
        token: "tok-secret-EEE",
        headers: {
          authorization: "Bearer at-secret-FFF",
          Authorization: "Bearer at-secret-GGG",
        },
      },
      "synthetic record",
    );

    const combined = lines.join("");
    const markers = [
      "at-secret-AAA",
      "rt-secret-BBB",
      "code-secret-CCC",
      "cv-secret-DDD",
      "tok-secret-EEE",
      "at-secret-FFF",
      "at-secret-GGG",
    ];
    for (const m of markers) {
      expect(combined).not.toContain(m);
    }
    expect(combined).toContain("synthetic record");
  });

  it("redact path list includes every secret field", () => {
    for (const field of ["token", "access_token", "refresh_token", "code", "code_verifier"]) {
      expect(_redactPathsForTest).toContain(field);
    }
  });
});

// ---------------------------------------------------------------------------
// unionScopes
// ---------------------------------------------------------------------------

describe("unionScopes", () => {
  it("merges and de-duplicates while preserving first-seen order", () => {
    expect(unionScopes("weather:read", "weather:premium")).toBe("weather:read weather:premium");
    expect(unionScopes("weather:read", "weather:read")).toBe("weather:read");
    expect(unionScopes("a b c", "b d")).toBe("a b c d");
  });

  it("ignores empty inputs", () => {
    expect(unionScopes("", "weather:read")).toBe("weather:read");
    expect(unionScopes("weather:read", "")).toBe("weather:read");
    expect(unionScopes("", "")).toBe("");
  });
});
