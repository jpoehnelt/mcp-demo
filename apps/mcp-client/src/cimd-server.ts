// Local CIMD + OAuth callback server.
//
// Spec anchors:
//   - specs/client.md §2 (routes + binding)
//   - specs/client.md §2.1 (CIMD document shape)
//   - specs/client.md §4 (security: unbind after capture)
//
// Binds to `127.0.0.1` LITERALLY (not `localhost`) so the IdP's SSRF check
// has a deterministic IP to match. Serves two routes:
//
//   * GET /client.json — the runtime-generated CIMD document. Each `start()`
//     uses a fresh port so `client_id` and `redirect_uris[0]` are baked
//     against the actual listening URL.
//   * GET /callback    — captures the OAuth `code`+`state` (or `error`)
//     query, responds to the browser with a friendly message, then unbinds
//     the listener (security §4 — listener MUST NOT remain open across the
//     rest of the flow).

import type { AddressInfo } from "node:net";
import { type ServerType, serve } from "@hono/node-server";
import { Hono } from "hono";

/**
 * Static fields of the CIMD document. `client_id` and `redirect_uris` are
 * filled in at boot once the actual listening port is known.
 */
const CIMD_STATIC = {
  client_name: "MCP Demo Client",
  client_uri: "https://github.com/jpoehnelt/mcp-demo",
  grant_types: ["authorization_code", "refresh_token"] as const,
  response_types: ["code"] as const,
  token_endpoint_auth_method: "none",
} as const;

export interface CIMDDocument {
  client_id: string;
  client_name: string;
  client_uri: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: "none";
}

/**
 * Raw callback query — captured verbatim from the browser redirect. The flow
 * is responsible for shape-validating these (state echo, error short-circuit).
 */
export interface CallbackPayload {
  code?: string;
  state?: string;
  error?: string;
  errorDescription?: string;
}

export interface CIMDServerHandle {
  /** Actual bound port (matches `desiredPort` if it was free; otherwise OS-assigned). */
  port: number;
  /** CIMD document URL — same value as `cimd.client_id`. */
  clientIdUrl: string;
  /** Callback URL — same value as `cimd.redirect_uris[0]`. */
  redirectUri: string;
  /** Frozen CIMD document the server returns from GET /client.json. */
  cimd: Readonly<CIMDDocument>;
  /**
   * Resolves on the next callback hit. Each `start()` produces one
   * `waitForCallback` promise. Calling it twice returns the same promise.
   */
  waitForCallback(): Promise<CallbackPayload>;
  /** Idempotent. Unbinds the port. */
  close(): Promise<void>;
}

interface StartOptions {
  /** Desired CIMD port (per `--cimd-port`). Use `0` for OS-assigned. */
  port: number;
}

/**
 * Bring up the local CIMD + callback server. Binds to `127.0.0.1` LITERALLY.
 *
 * The handle's `waitForCallback()` resolves the FIRST time `/callback` is
 * hit; subsequent calls return the same payload. On callback receipt we
 * respond to the browser with a friendly HTML page and immediately schedule
 * `close()` so the listener doesn't outlive the flow (spec §4).
 */
export async function startCIMDServer(opts: StartOptions): Promise<CIMDServerHandle> {
  const app = new Hono();

  // Resolved when the first /callback hits; deferred so closures below can
  // both `resolve` it and `await` it via `waitForCallback()`.
  let resolveCallback: (payload: CallbackPayload) => void = () => undefined;
  const callbackPromise = new Promise<CallbackPayload>((resolve) => {
    resolveCallback = resolve;
  });
  let callbackFired = false;

  // The CIMD doc and routes both need the listening port, but we don't know
  // it until `serve()` returns. Use a forward-ref pattern: routes read off a
  // closure that gets populated after bind.
  let clientIdUrl = "";
  let redirectUri = "";
  let cimd: CIMDDocument | undefined;

  app.get("/client.json", (c) => {
    if (cimd === undefined) {
      // Should be impossible — routes only mount after the address is known.
      return c.json({ error: "server_not_ready" }, 500);
    }
    return c.json(cimd);
  });

  app.get("/callback", (c) => {
    const url = new URL(c.req.url);
    const payload: CallbackPayload = {};
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const error = url.searchParams.get("error");
    const errorDescription = url.searchParams.get("error_description");
    if (code !== null) payload.code = code;
    if (state !== null) payload.state = state;
    if (error !== null) payload.error = error;
    if (errorDescription !== null) payload.errorDescription = errorDescription;

    if (!callbackFired) {
      callbackFired = true;
      resolveCallback(payload);
    }

    const message =
      payload.error !== undefined
        ? `Authorization failed: ${payload.error}`
        : "Authorization complete, you may close this window.";
    return c.html(
      `<!doctype html><html><head><meta charset="utf-8"><title>MCP Demo Client</title></head><body><h1>${message}</h1></body></html>`,
    );
  });

  // 404 for anything else — keep the surface area minimal so a stray /admin
  // probe doesn't accidentally hit our static handler.
  app.notFound((c) => c.text("not found", 404));

  let server: ServerType | undefined;
  // Bind on 127.0.0.1 LITERALLY (spec §2 + IdP SSRF expectation).
  const port: number = await new Promise<number>((resolve, reject) => {
    server = serve({ fetch: app.fetch, port: opts.port, hostname: "127.0.0.1" }, (info) => {
      resolve((info as AddressInfo).port);
    });
    server.on("error", reject);
  });

  clientIdUrl = `http://127.0.0.1:${String(port)}/client.json`;
  redirectUri = `http://127.0.0.1:${String(port)}/callback`;
  cimd = Object.freeze({
    client_id: clientIdUrl,
    client_name: CIMD_STATIC.client_name,
    client_uri: CIMD_STATIC.client_uri,
    redirect_uris: [redirectUri],
    grant_types: [...CIMD_STATIC.grant_types],
    response_types: [...CIMD_STATIC.response_types],
    token_endpoint_auth_method: CIMD_STATIC.token_endpoint_auth_method,
  });

  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    await new Promise<void>((resolve, reject) => {
      if (server === undefined) {
        resolve();
        return;
      }
      server.close((err) => (err !== undefined && err !== null ? reject(err) : resolve()));
    });
  };

  return {
    port,
    clientIdUrl,
    redirectUri,
    cimd,
    waitForCallback: () => callbackPromise,
    close,
  };
}
