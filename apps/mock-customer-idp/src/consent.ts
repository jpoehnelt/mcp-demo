// HTML rendering helpers for the consent UI.
//
// Spec anchor: specs/authorization-server.md §4.5 (Consent UI). The form
// MUST display: client_name, client_uri, logo_uri, requested scopes, and
// the redirect URI hostname. A warning MUST appear if any redirect_uri is
// loopback (MCP localhost-risks reference).
//
// The HTML is intentionally minimal — single self-contained page, no
// external CSS or JS, no framework. The form posts to
// `/authorize/consent` with hidden inputs replaying the request params
// (display-only on the server side; the signed cookie is the source of
// truth) plus the CSRF token and an `action` field carrying "approve"
// or "deny".

import type { ValidatedCIMDDocument } from "@poc/shared";

/**
 * Inputs the renderer needs. Most of these come from the resolved CIMD
 * document; `redirectUri` comes from the request because the CIMD may
 * advertise multiple and we render the one the client actually requested.
 */
export interface ConsentRenderInput {
  cimd: ValidatedCIMDDocument;
  redirectUri: string;
  /** Requested scopes (already validated as a subset of scopes_supported). */
  scopes: readonly string[];
  /** CSRF token; same value lives in the signed session cookie. */
  csrfToken: string;
}

/**
 * Lightweight HTML entity escape. The consent form interpolates several
 * fields sourced from the CIMD (client_name, client_uri, logo_uri); a
 * malicious CIMD could embed `<script>` tags otherwise.
 *
 * Covers the five characters that matter inside HTML element content and
 * `"`-delimited attribute values. We never interpolate into `'`-delimited
 * attributes or unquoted attributes.
 */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

/**
 * Returns `true` if the parsed `redirect_uri` host is a loopback literal.
 * Per spec §4.5 we warn (never block) when this is the case. The CIMD
 * schema already rejects `http://localhost` so the only loopback we ever
 * see is `127.0.0.1` (IPv4) or `[::1]` (IPv6).
 */
export function isLoopbackRedirect(redirectUri: string): boolean {
  try {
    const u = new URL(redirectUri);
    return u.hostname === "127.0.0.1" || u.hostname === "[::1]" || u.hostname === "::1";
  } catch {
    return false;
  }
}

/**
 * Render the consent page HTML. Returns a complete HTML document (no
 * surrounding template). Caller is responsible for setting
 * `Content-Type: text/html; charset=utf-8`.
 */
export function renderConsentHtml(input: ConsentRenderInput): string {
  const { cimd, redirectUri, scopes, csrfToken } = input;

  // Pull display fields off the CIMD. `client_uri` and `logo_uri` are
  // optional — render only when present.
  const clientName = escapeHtml(cimd.client_name);
  const clientUri = cimd.client_uri !== undefined ? escapeHtml(cimd.client_uri) : undefined;
  const logoUri = cimd.logo_uri !== undefined ? escapeHtml(cimd.logo_uri) : undefined;

  let redirectHost: string;
  try {
    redirectHost = new URL(redirectUri).host;
  } catch {
    // Should be unreachable — the redirect_uri was validated by zod and the
    // CIMD before we got here. Defensive fallback.
    redirectHost = redirectUri;
  }
  const escapedHost = escapeHtml(redirectHost);
  const escapedRedirect = escapeHtml(redirectUri);
  const escapedCsrf = escapeHtml(csrfToken);

  const loopbackWarning = isLoopbackRedirect(redirectUri)
    ? `<p class="warning" role="alert"><strong>Warning:</strong> the redirect URI is a loopback address (${escapedHost}). Any process on this machine can listen on a loopback port — only proceed if you started this flow yourself.</p>`
    : "";

  const logoBlock = logoUri !== undefined ? `<img src="${logoUri}" alt="" class="logo" />` : "";

  const clientLinkBlock =
    clientUri !== undefined
      ? `<p><a href="${clientUri}" rel="noopener noreferrer">${clientUri}</a></p>`
      : "";

  const scopeItems = scopes.map((s) => `<li><code>${escapeHtml(s)}</code></li>`).join("");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Authorize ${clientName}</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 32rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
  .logo { max-width: 4rem; max-height: 4rem; vertical-align: middle; }
  .warning { background: #fff4e5; border-left: 4px solid #b45309; padding: 0.75rem 1rem; }
  ul { padding-left: 1.25rem; }
  .actions { margin-top: 1.5rem; display: flex; gap: 0.75rem; }
  button { padding: 0.5rem 1rem; font-size: 1rem; cursor: pointer; }
  .approve { background: #0a7f3f; color: white; border: 1px solid #0a7f3f; }
  .deny { background: #f4f4f5; border: 1px solid #ccc; }
</style>
</head>
<body>
<h1>${logoBlock} Authorize ${clientName}</h1>
${clientLinkBlock}
<p><strong>${clientName}</strong> is requesting access to your account at <code>${escapedHost}</code>.</p>
${loopbackWarning}
<p>It will be granted the following scopes:</p>
<ul>${scopeItems}</ul>
<p>You will be returned to <code>${escapedRedirect}</code> after you choose.</p>
<form method="POST" action="/authorize/consent">
  <input type="hidden" name="csrf" value="${escapedCsrf}" />
  <div class="actions">
    <button type="submit" name="action" value="approve" class="approve">Approve</button>
    <button type="submit" name="action" value="deny" class="deny">Deny</button>
  </div>
</form>
</body>
</html>`;
}
