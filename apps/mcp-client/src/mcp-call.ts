// MCP tool invocation.
//
// Spec: specs/client.md §3.4 (tool call), §4 (security: Bearer header only,
// invariant §4.13).
//
// We issue a JSON-RPC `tools/call` envelope to `POST <server>/mcp` with the
// streamable-HTTP-friendly accept set. The bearer token MUST travel only in
// the `Authorization` header — never in URI, query, or body — per §4.13.
//
// The PoC uses a hand-rolled POST instead of the MCP SDK's high-level
// `Client` + transport classes. Rationale:
//
//   1. The full SDK client requires an `initialize` handshake + capability
//      negotiation that adds two round-trips to a one-shot CLI. The MCP
//      server's own integration tests issue the same hand-rolled envelope.
//   2. The SDK's transport doesn't expose the underlying HTTP response
//      headers — and we need `WWW-Authenticate` from a 403 to drive step-up.
//      A direct fetch makes the header available without prying at internals.
//   3. Treating the token as opaque (just-a-string) keeps the §4.3 / §4.13
//      surface tiny — no parsing path inside this module.

import { type ParsedAuthChallenge, parseAuthChallenge } from "./www-authenticate.js";

/** Successful JSON-RPC tool result envelope. */
export interface MCPToolSuccess {
  ok: true;
  /** Raw text content (`result.content[0].text`) — the tool's payload. */
  text: string;
  /** Full JSON-RPC body for verbose logging. */
  rawBody: unknown;
}

/** Insufficient-scope failure — drives step-up in `flow.ts`. */
export interface MCPToolInsufficientScope {
  ok: false;
  kind: "insufficient_scope";
  status: 403;
  challenge: ParsedAuthChallenge;
  rawBody: unknown;
}

/** Auth failure (401: bad/missing/expired token). */
export interface MCPToolUnauthorized {
  ok: false;
  kind: "unauthorized";
  status: 401;
  challenge: ParsedAuthChallenge | undefined;
  rawBody: unknown;
}

/** Any other failure — network or non-OAuth HTTP error. */
export interface MCPToolError {
  ok: false;
  kind: "error";
  status: number;
  message: string;
  rawBody: unknown;
}

export type MCPToolOutcome =
  | MCPToolSuccess
  | MCPToolInsufficientScope
  | MCPToolUnauthorized
  | MCPToolError;

export interface CallMCPToolInput {
  mcpServerUrl: string;
  tool: string;
  args: Record<string, unknown>;
  /**
   * Bearer token. Pass `undefined` to deliberately send an unauthenticated
   * request (e.g. to capture the initial 401 + WWW-Authenticate during the
   * pre-discovery probe).
   */
  accessToken: string | undefined;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number;
  result?: {
    content?: { type: string; text: string }[];
    isError?: boolean;
  };
  error?: {
    code: number;
    message: string;
  };
}

/**
 * POST a JSON-RPC `tools/call` envelope to `<mcpServerUrl>/mcp`.
 *
 * Returns a tagged-union outcome — the caller (`flow.ts`) dispatches on
 * `kind` to drive step-up vs. happy-path vs. fatal failures.
 */
export async function callMCPTool(input: CallMCPToolInput): Promise<MCPToolOutcome> {
  const headers: Record<string, string> = {
    accept: "application/json, text/event-stream",
    "content-type": "application/json",
  };
  if (input.accessToken !== undefined) {
    // INV-4.13: bearer only in Authorization, never in URI.
    headers.authorization = `Bearer ${input.accessToken}`;
  }
  const url = `${input.mcpServerUrl}/mcp`;
  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: input.tool, arguments: input.args },
    }),
  });

  const text = await res.text();
  let body: unknown;
  try {
    body = text.length === 0 ? undefined : JSON.parse(text);
  } catch {
    body = text;
  }

  if (res.status === 401) {
    const challenge = parseAuthChallenge(res.headers.get("www-authenticate"));
    return {
      ok: false,
      kind: "unauthorized",
      status: 401,
      challenge,
      rawBody: body,
    };
  }
  if (res.status === 403) {
    const challenge = parseAuthChallenge(res.headers.get("www-authenticate"));
    if (challenge === undefined) {
      return {
        ok: false,
        kind: "error",
        status: 403,
        message: "403 from /mcp without WWW-Authenticate header (cannot drive step-up)",
        rawBody: body,
      };
    }
    return {
      ok: false,
      kind: "insufficient_scope",
      status: 403,
      challenge,
      rawBody: body,
    };
  }
  if (res.status !== 200) {
    return {
      ok: false,
      kind: "error",
      status: res.status,
      message: `MCP server returned HTTP ${String(res.status)}`,
      rawBody: body,
    };
  }

  // 200 OK from the transport. Inspect the JSON-RPC envelope.
  const rpc = body as JsonRpcResponse | undefined;
  if (rpc === undefined || typeof rpc !== "object") {
    return {
      ok: false,
      kind: "error",
      status: 200,
      message: "MCP response was not valid JSON-RPC",
      rawBody: body,
    };
  }
  if (rpc.error !== undefined) {
    return {
      ok: false,
      kind: "error",
      status: 200,
      message: `MCP tool error: ${rpc.error.message}`,
      rawBody: body,
    };
  }
  if (rpc.result?.isError === true) {
    const errText = rpc.result.content?.[0]?.text ?? "(no message)";
    return {
      ok: false,
      kind: "error",
      status: 200,
      message: `MCP tool returned error: ${errText}`,
      rawBody: body,
    };
  }
  const first = rpc.result?.content?.[0];
  return {
    ok: true,
    text: first?.text ?? "",
    rawBody: body,
  };
}
