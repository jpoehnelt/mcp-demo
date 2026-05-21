// End-to-end flow orchestration.
//
// Spec: specs/client.md §3 (whole section).
//
// Stages:
//   1. Boot local CIMD + callback server (one per `runFlow()` invocation).
//   2. Probe MCP server unauthenticated → expect 401, parse challenge.
//   3. Run PRM + AS metadata discovery (`discovery.ts`).
//   4. Generate PKCE pair + state.
//   5. Build authorize URL; drive the user-agent step.
//   6. Verify the captured state, exchange code for token.
//   7. Call the MCP tool; on 403 insufficient_scope, loop to (4) with the
//      union of granted + newly-required scopes. Cap at 2 retries.
//
// All output for the user goes through the injected `Reporter` so tests can
// capture it; structured pino lines go to the `Logger`.

import { generatePKCE, generateState, verifyState } from "@poc/shared";
import { buildAuthorizeUrl, driveAuthorize } from "./authorize.js";
import { type CIMDServerHandle, startCIMDServer } from "./cimd-server.js";
import type { ClientOptions } from "./cli.js";
import { runDiscovery } from "./discovery.js";
import type { Logger } from "./log.js";
import { callMCPTool, type MCPToolOutcome } from "./mcp-call.js";
import { exchangeCodeForToken } from "./token.js";

const MAX_STEPUP_RETRIES = 2;

/**
 * User-facing reporter — `index.ts` wires a stdout-writing implementation;
 * tests pass an array-collecting one.
 */
export interface Reporter {
  step(line: string): void;
  result(line: string): void;
}

export interface FlowDeps {
  log: Logger;
  reporter: Reporter;
}

export interface FlowResult {
  /** Tool result text (the `result.content[0].text` payload). */
  resultText: string;
  /** Final scope granted on the token used to invoke the tool. */
  finalScope: string;
  /** Number of step-up retries performed (0 = first call succeeded). */
  stepUpsPerformed: number;
  /**
   * Populated only when `options.printToken` is set; the access token from
   * the token endpoint, NOT redacted. The caller is responsible for handling
   * it carefully (do not log, do not persist).
   */
  accessToken?: string;
}

/**
 * Authorize once + call the tool. Returns the tool's outcome and the scope
 * that the AS actually granted (echoed in the token response).
 *
 * Extracted so the step-up loop in `runFlow` can re-enter §3.2 with a wider
 * scope without duplicating the body.
 */
async function authorizeAndCall(args: {
  options: ClientOptions;
  discovery: Awaited<ReturnType<typeof runDiscovery>>;
  cimd: CIMDServerHandle;
  scope: string;
  deps: FlowDeps;
}): Promise<{ outcome: MCPToolOutcome; grantedScope: string; accessToken?: string }> {
  const { options, discovery, cimd, scope, deps } = args;

  // (4) PKCE + state.
  const pkce = generatePKCE();
  const state = generateState();
  deps.reporter.step(`PKCE pair generated (S256)`);

  // (5) Authorize URL + drive user-agent.
  const authorizeUrl = buildAuthorizeUrl({
    asMetadata: discovery.asMetadata,
    clientId: cimd.clientIdUrl,
    redirectUri: cimd.redirectUri,
    scope,
    resource: discovery.resource,
    codeChallenge: pkce.challenge,
    state,
  });
  deps.reporter.step(
    options.headless ? "Driving headless consent..." : "Opening browser to authorize...",
  );
  const callback = await driveAuthorize({
    authorizeUrl,
    loopbackBaseUrl: `http://127.0.0.1:${String(cimd.port)}`,
    waitForCallback: cimd.waitForCallback,
    mode: options.headless ? "headless" : "interactive",
    log: deps.log,
  });

  // (6a) Validate state — INV-4.14. Verify ALWAYS (even on the error path)
  // so a CSRF-attacker who forces a denial cannot bypass the check.
  if (callback.state === undefined || !verifyState(callback.state, state)) {
    throw new Error("state mismatch on /callback [INV-4.14]");
  }

  // (6b) Error short-circuit.
  if (callback.error !== undefined) {
    const friendly =
      callback.error === "access_denied"
        ? "User denied consent"
        : `Authorization failed: ${callback.error}${
            callback.errorDescription !== undefined ? ` (${callback.errorDescription})` : ""
          }`;
    throw new Error(friendly);
  }
  if (callback.code === undefined) {
    throw new Error("callback missing both `code` and `error` query params");
  }
  deps.reporter.step("Authorization code received");

  // (6c) Exchange.
  const tokenRes = await exchangeCodeForToken({
    asMetadata: discovery.asMetadata,
    code: callback.code,
    clientId: cimd.clientIdUrl,
    redirectUri: cimd.redirectUri,
    codeVerifier: pkce.verifier,
    resource: discovery.resource,
  });
  const grantedScope = tokenRes.scope ?? scope;
  deps.reporter.step(
    `Token issued (aud: ${discovery.resource}, scope: ${grantedScope}${
      tokenRes.expires_in !== undefined ? `, exp: ${formatTtl(tokenRes.expires_in)}` : ""
    })`,
  );

  // `--print-token` short-circuit: skip the tool call and surface the token
  // back to runFlow so the CLI can print it. Caller is responsible for not
  // logging it. This exists as a dev-only escape hatch for MCP Inspector,
  // whose OAuth flow defaults to DCR (RFC 7591) — incompatible with our
  // CIMD-only IdP (see architecture.md §6 non-goals).
  if (options.printToken) {
    return {
      outcome: { ok: true, text: "", rawBody: null },
      grantedScope,
      accessToken: tokenRes.access_token,
    };
  }

  // (7) Call the tool.
  deps.reporter.step(`Tool call: ${options.tool}(${JSON.stringify(options.args)})`);
  const outcome = await callMCPTool({
    mcpServerUrl: options.server,
    tool: options.tool,
    args: options.args,
    accessToken: tokenRes.access_token,
  });
  return { outcome, grantedScope };
}

/**
 * Drive the full flow end-to-end. Returns the final `FlowResult` on success
 * or throws a descriptive error on permanent failure.
 *
 * The local CIMD server is created once and re-used across step-up retries —
 * the IdP's CIMD cache is keyed on the CIMD URL, so re-using the URL skips a
 * fresh fetch on the second authorize round-trip.
 *
 * NB: a fresh CIMD server is needed PER authorize because the callback
 * resolves only once. So we start a new one before each authorize round-trip
 * inside the retry loop (the previous one already closed itself on capture).
 */
export async function runFlow(options: ClientOptions, deps: FlowDeps): Promise<FlowResult> {
  // ---- (1) Probe MCP server for the initial 401 challenge. -----------------
  const probe = await callMCPTool({
    mcpServerUrl: options.server,
    tool: options.tool,
    args: options.args,
    accessToken: undefined,
  });
  if (probe.ok || probe.kind !== "unauthorized") {
    throw new Error(
      `expected 401 from unauthenticated /mcp probe, got ${
        probe.ok ? "200" : `${String(probe.status)} (${probe.kind})`
      }`,
    );
  }
  const initialChallenge = probe.challenge;
  if (initialChallenge?.resourceMetadata === undefined) {
    throw new Error("401 WWW-Authenticate missing `resource_metadata` parameter");
  }
  deps.reporter.step(`Discovered MCP server (audience: ${options.server})`);

  // ---- (2) Discovery: PRM + AS metadata. -----------------------------------
  const discovery = await runDiscovery({
    prmUrl: initialChallenge.resourceMetadata,
    log: deps.log,
  });
  deps.reporter.step(`Discovered authorization server at ${discovery.authorizationServer}`);

  // ---- (3) Initial scope. --------------------------------------------------
  // §3.6 Scope Selection Strategy: prefer --scope, then 401-advertised scope,
  // then PRM scopes_supported, then omit.
  let scope: string =
    options.scope ?? initialChallenge.scope ?? (discovery.prm.scopes_supported ?? []).join(" ");
  if (scope.length === 0) {
    // PRM had no scopes_supported AND the 401 didn't advertise one; fall back
    // to the demo's minimum.
    scope = "weather:read";
  }

  // ---- (4–7) Authorize + tool call, with step-up retries. ------------------
  let stepUps = 0;
  let cimd = await startCIMDServer({ port: options.cimdPort });
  deps.reporter.step(`Local CIMD server at http://127.0.0.1:${String(cimd.port)}/client.json`);

  try {
    while (true) {
      const { outcome, grantedScope, accessToken } = await authorizeAndCall({
        options,
        discovery,
        cimd,
        scope,
        deps,
      });

      if (outcome.ok) {
        return {
          resultText: outcome.text,
          finalScope: grantedScope,
          stepUpsPerformed: stepUps,
          ...(accessToken === undefined ? {} : { accessToken }),
        };
      }

      if (outcome.kind === "insufficient_scope") {
        if (stepUps >= MAX_STEPUP_RETRIES) {
          throw new Error(
            `step-up retry cap reached (${String(MAX_STEPUP_RETRIES)}); still 403 insufficient_scope`,
          );
        }
        stepUps += 1;
        // Union of previously-granted + newly-required scopes. Never narrow
        // (§3.5) — a regression to a smaller set may regress to a 403 for a
        // different missing scope.
        const required = outcome.challenge.scope ?? "";
        scope = unionScopes(grantedScope, required);
        deps.reporter.step(
          `Step-up: re-authorizing with scope=${JSON.stringify(scope)} (attempt ${String(stepUps)}/${String(MAX_STEPUP_RETRIES)})`,
        );
        // Need a fresh callback server for the next authorize round.
        await cimd.close();
        cimd = await startCIMDServer({ port: options.cimdPort });
        continue;
      }

      if (outcome.kind === "unauthorized") {
        // Mid-flow 401 (e.g. token expired between issuance and tool call) —
        // surface as a fatal error; refresh-token redemption is out of scope
        // per spec §"Out of scope".
        throw new Error(
          `MCP server returned 401 for an authenticated request — token likely expired (${
            outcome.challenge?.error ?? "no error code"
          })`,
        );
      }

      throw new Error(outcome.message);
    }
  } finally {
    await cimd.close().catch((err: unknown) => {
      deps.log.warn({ err }, "error closing local CIMD server");
    });
  }
}

/**
 * Set-union of two whitespace-separated scope strings, preserving the order
 * of the first occurrence.
 */
export function unionScopes(a: string, b: string): string {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of `${a} ${b}`.split(/\s+/)) {
    if (part.length === 0) continue;
    if (seen.has(part)) continue;
    seen.add(part);
    out.push(part);
  }
  return out.join(" ");
}

/** Pretty-print a TTL in seconds as e.g. `4m 59s`. */
function formatTtl(seconds: number): string {
  if (seconds < 60) return `${String(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return s === 0 ? `${String(m)}m` : `${String(m)}m ${String(s)}s`;
}
