// Authorization request orchestration.
//
// Spec: specs/client.md §3.2 (authorize request params), §3.3 (callback +
// state verification), §3.4 (headless drive).
//
// Two modes:
//
//   * Interactive (`autoOpen=true`): build the authorize URL, hand it to the
//     `open` package, wait for the browser → IdP → loopback callback to fire.
//
//   * Headless (`headless=true`): with `AS_AUTO_APPROVE=true` the IdP skips
//     the consent UI on GET /authorize and 302s straight to our callback. We
//     fetch the authorize URL with `redirect: "manual"`, extract the
//     Location header, then issue a GET against that loopback URL ourselves
//     so the regular `/callback` capture path still fires (same code path
//     as the interactive flow — keeps the assertions identical).

import type { ASMetadata, PKCEChallenge, StateParam } from "@poc/shared";
import open from "open";
import type { CallbackPayload } from "./cimd-server.js";
import type { Logger } from "./log.js";

export interface BuildAuthorizeUrlInput {
  asMetadata: ASMetadata;
  clientId: string;
  redirectUri: string;
  scope: string;
  resource: string;
  codeChallenge: PKCEChallenge;
  state: StateParam;
}

/**
 * Build the authorize URL per spec §3.2 parameter table. All values are
 * URL-encoded by `URLSearchParams`; we never concatenate raw strings.
 */
export function buildAuthorizeUrl(input: BuildAuthorizeUrlInput): string {
  const params = new URLSearchParams();
  params.set("response_type", "code");
  params.set("client_id", input.clientId);
  params.set("redirect_uri", input.redirectUri);
  params.set("scope", input.scope);
  params.set("resource", input.resource);
  params.set("code_challenge", input.codeChallenge);
  params.set("code_challenge_method", "S256");
  params.set("state", input.state);
  return `${input.asMetadata.authorization_endpoint}?${params.toString()}`;
}

export interface DriveAuthorizeOpts {
  authorizeUrl: string;
  loopbackBaseUrl: string;
  waitForCallback: () => Promise<CallbackPayload>;
  mode: "interactive" | "headless";
  log: Logger;
}

/**
 * Trigger the user-agent step of the authorization request and resolve when
 * the local `/callback` route has captured `code`+`state` (or `error`).
 *
 * Interactive mode shells out to `open`; headless mode drives the IdP's
 * auto-approve path directly via fetch and re-routes the response back into
 * our `/callback` handler so the capture path is identical.
 */
export async function driveAuthorize(opts: DriveAuthorizeOpts): Promise<CallbackPayload> {
  if (opts.mode === "interactive") {
    // The `open` package returns a `ChildProcess`; we don't await its exit
    // (the browser tab may live long after the callback fires).
    await open(opts.authorizeUrl);
    return opts.waitForCallback();
  }

  // Headless: hit the IdP's /authorize with `redirect: "manual"`. With
  // AS_AUTO_APPROVE=true the IdP returns 302 with `Location` pointing at our
  // loopback callback. We then GET that loopback URL to fire our /callback
  // handler. This keeps the capture path identical between modes.
  const authRes = await fetch(opts.authorizeUrl, { redirect: "manual" });
  if (authRes.status !== 302) {
    const body = await authRes.text();
    opts.log.error(
      { status: authRes.status, body: body.slice(0, 200) },
      "headless authorize: expected 302",
    );
    throw new Error(
      `headless authorize: expected 302 from IdP, got HTTP ${String(authRes.status)}`,
    );
  }
  const location = authRes.headers.get("location");
  if (location === null || location.length === 0) {
    throw new Error("headless authorize: 302 response missing Location header");
  }

  // The IdP's Location should already point at our loopback callback. Fire
  // the request that triggers our /callback handler, then resolve on the
  // captured payload.
  const callbackUrl = new URL(location, opts.loopbackBaseUrl).toString();
  // Don't await — the callback handler's response races with
  // `waitForCallback()` resolving from inside the handler.
  void fetch(callbackUrl).catch((err: unknown) => {
    opts.log.warn({ err }, "headless callback fetch failed");
  });
  return opts.waitForCallback();
}
