// `POST /mcp` wiring. Bridges Hono's request/response surface to the MCP
// SDK's `WebStandardStreamableHTTPServerTransport` (Web-Standard-Request/
// -Response shape — works directly with `c.req.raw` and lets us return the
// SDK's `Response` straight back to Hono).
//
// Design notes:
//
// 1. One fresh `McpServer` + transport per request. The MCP SDK's tool
//    handler `extra.authInfo` only carries `{ token, clientId, scopes[] }` —
//    strictly less than the `TokenClaims` shape `requireScope` consumes.
//    Rather than convert in both directions, we capture `claims` in a
//    closure that `mcp/tools.ts` reads from. The per-request overhead (one
//    schema lookup + a couple of allocations) is negligible for a PoC.
//
// 2. Scope enforcement happens BEFORE the SDK dispatches the call. The SDK's
//    high-level `McpServer` wraps any thrown error inside the tool handler
//    in a JSON-RPC tool-error result (`isError: true`, HTTP 200). That's the
//    wrong shape for `InsufficientScopeError` — architecture invariant §4.8
//    mandates an HTTP 403 with a `WWW-Authenticate: ..., error="insufficient_scope"`
//    header on the outer HTTP envelope so the client can drive the step-up
//    flow. We therefore peek at the JSON-RPC body, run `requireScope` on
//    `tools/call` requests for tools whose row in §6 names a scope, then
//    hand the already-parsed body to the transport via `parsedBody`. The
//    body is consumed only once.
//
// 3. `enableJsonResponse: true` keeps responses synchronous JSON — the demo
//    doesn't need SSE streams and JSON is easier to assert in tests.
//
// Spec anchors:
//   - resource-server.md §6 (tool table + scope mapping)
//   - architecture.md §4.8 (403 + WWW-Authenticate on insufficient scope)
//   - resource-server.md §4.3 (no token forwarding — tools compute locally)

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import type { TokenClaims } from "@poc/shared";
import type { Context } from "hono";
import type { MCPServerApp } from "../app.js";
import type { MCPServerEnv } from "../env.js";
import type { Logger } from "../log.js";
import { requireScope } from "../middleware/require-scope.js";
import { registerTools } from "./tools.js";

interface CreateMCPTransportDeps {
  env: MCPServerEnv;
  log: Logger;
}

const SERVER_INFO = {
  name: "mcp-demo-weather",
  version: "0.0.0",
} as const;

// Tools whose row in resource-server.md §6 names a required scope. Kept
// alongside the transport so the pre-flight check stays close to the
// declared invariant; `mcp/tools.ts` still calls `requireScope` itself,
// which is defense-in-depth in case a future code path bypasses the
// pre-flight (e.g. an internal `request()` invocation that skips the
// transport).
const TOOL_SCOPE: Record<string, string> = {
  get_weather: "weather:read",
  get_premium_forecast: "weather:premium",
  // list_cities intentionally absent — no scope required (§6).
};

// Minimal shape of a JSON-RPC `tools/call` request — just enough to identify
// the tool name. Other fields (id, arguments) pass through unchanged.
function extractToolCallName(body: unknown): string | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const rec = body as Record<string, unknown>;
  if (rec.method !== "tools/call") return undefined;
  const params = rec.params;
  if (typeof params !== "object" || params === null) return undefined;
  const name = (params as Record<string, unknown>).name;
  return typeof name === "string" ? name : undefined;
}

async function handleMCPRequest(c: Context, claims: TokenClaims, log: Logger): Promise<Response> {
  // Read the body ONCE. The transport accepts a `parsedBody` option so we
  // don't double-consume the stream. `c.req.raw` is a Web-Standard `Request`;
  // calling `.json()` here drains the body, which is why we pass it back
  // through `parsedBody` below.
  let parsedBody: unknown;
  try {
    parsedBody = await c.req.raw.clone().json();
  } catch {
    // Malformed JSON — let the transport produce the proper JSON-RPC parse
    // error. Pass `undefined` so it falls back to reading the body itself
    // (which will fail with a JSON-RPC -32700, HTTP 400).
    parsedBody = undefined;
  }

  // Pre-flight scope check (§6 + §4.8). Runs only on `tools/call`; other
  // methods (`initialize`, `tools/list`, etc.) need no scope beyond auth.
  const toolName = extractToolCallName(parsedBody);
  if (toolName !== undefined) {
    const requiredScope = TOOL_SCOPE[toolName];
    if (requiredScope !== undefined) {
      // Throws InsufficientScopeError → onError → 403 + WWW-Authenticate.
      requireScope(claims, requiredScope);
    }
  }

  const server = new McpServer(SERVER_INFO);
  registerTools(server, claims);

  // Stateless mode: no session ID generator, no session validation. The
  // PoC client always reconnects fresh; we don't need cross-request state.
  // Omit `sessionIdGenerator` entirely (rather than passing `undefined`) so
  // we satisfy `exactOptionalPropertyTypes` — the SDK treats absence as
  // stateless mode.
  const transport = new WebStandardStreamableHTTPServerTransport({
    enableJsonResponse: true,
  });

  try {
    await server.connect(transport);
    return await transport.handleRequest(c.req.raw, { parsedBody });
  } catch (err) {
    log.error({ err }, "mcp transport error");
    throw err;
  } finally {
    // Release SDK resources tied to this request. `transport.close()` is
    // idempotent and safe to call after `handleRequest` resolves.
    await transport.close().catch(() => {
      /* swallow close errors; we already have the response */
    });
    await server.close().catch(() => {
      /* swallow close errors */
    });
  }
}

/**
 * Mount `POST /mcp` on the given Hono app. Caller must have already
 * installed the §4.1 auth middleware (so `c.var.claims` is populated) and
 * registered `attachInsufficientScopeHandler` (so a thrown
 * `InsufficientScopeError` becomes the spec-mandated 403 with
 * `WWW-Authenticate`).
 */
export function createMCPTransport(app: MCPServerApp, deps: CreateMCPTransportDeps): void {
  app.post("/mcp", async (c) => handleMCPRequest(c, c.var.claims, deps.log));
}
