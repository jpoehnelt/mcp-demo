// WWW-Authenticate header helpers. See specs/shared-library.md §3.1.
//
// RFC 7235 §2.1 quoted-string syntax: backslash-escape `"` and `\` inside the
// quoted value; other characters are literal. We build headers with all values
// quoted (RFC allows token-or-quoted; quoted is always safe).

/**
 * Escape a string for use as a quoted-string value per RFC 7235 §2.1.
 * Escapes `\` first to avoid double-escaping the escapes for `"`.
 */
function escapeQuotedString(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

/**
 * Unescape a quoted-string body per RFC 7235 §2.1. Any `\X` is replaced with
 * `X` literally; bare characters pass through.
 */
function unescapeQuotedString(value: string): string {
  let out = "";
  let i = 0;
  while (i < value.length) {
    const ch = value[i];
    if (ch === "\\" && i + 1 < value.length) {
      const next = value[i + 1];
      if (next !== undefined) {
        out += next;
        i += 2;
        continue;
      }
    }
    out += ch;
    i += 1;
  }
  return out;
}

function paramPair(key: string, value: string): string {
  return `${key}="${escapeQuotedString(value)}"`;
}

/**
 * Build a `Bearer realm="...", resource_metadata="...", scope="..."` header
 * for an unauthenticated 401 response.
 */
export function buildUnauthorizedHeader(opts: {
  realm: string;
  resourceMetadata: string;
  scope: string;
}): string {
  const params = [
    paramPair("realm", opts.realm),
    paramPair("resource_metadata", opts.resourceMetadata),
    paramPair("scope", opts.scope),
  ];
  return `Bearer ${params.join(", ")}`;
}

/**
 * Build a `Bearer ..., error="insufficient_scope", ...` header for a 403
 * response where the token is valid but lacks the required scope.
 */
export function buildInsufficientScopeHeader(opts: {
  realm: string;
  scope: string;
  resourceMetadata: string;
  errorDescription?: string;
}): string {
  const params = [
    paramPair("realm", opts.realm),
    paramPair("error", "insufficient_scope"),
    paramPair("scope", opts.scope),
    paramPair("resource_metadata", opts.resourceMetadata),
  ];
  if (opts.errorDescription !== undefined) {
    params.push(paramPair("error_description", opts.errorDescription));
  }
  return `Bearer ${params.join(", ")}`;
}

/**
 * Parse a syntactically valid `Bearer key="value", ...` header into its
 * scheme and key/value pairs.
 *
 * Tolerates extra whitespace around commas and `=`. Quoted-string values are
 * unescaped per RFC 7235 §2.1. Token (unquoted) values are accepted too —
 * they're returned verbatim.
 *
 * Throws `Error` on a malformed header; this is a library bug if it happens
 * on output of `buildUnauthorizedHeader` / `buildInsufficientScopeHeader`.
 */
export function parseWWWAuthenticate(header: string): {
  scheme: string;
  params: Record<string, string>;
} {
  if (typeof header !== "string" || header.length === 0) {
    throw new Error("WWW-Authenticate header is empty");
  }

  // Split scheme from the rest at the first run of whitespace.
  const schemeMatch = /^(\S+)\s*(.*)$/.exec(header);
  if (schemeMatch === null) {
    throw new Error(`Malformed WWW-Authenticate header: ${header}`);
  }
  const scheme = schemeMatch[1] ?? "";
  const rest = schemeMatch[2] ?? "";

  const params: Record<string, string> = {};
  let i = 0;
  const len = rest.length;

  // Skip leading whitespace.
  const skipWs = (): void => {
    while (i < len && (rest[i] === " " || rest[i] === "\t")) i += 1;
  };

  while (i < len) {
    skipWs();
    if (i >= len) break;

    // Read key (token: 1*tchar). We accept any non-ws/non-`=` run.
    const keyStart = i;
    while (i < len && rest[i] !== "=" && rest[i] !== " " && rest[i] !== "\t" && rest[i] !== ",") {
      i += 1;
    }
    const key = rest.slice(keyStart, i);
    if (key.length === 0) {
      throw new Error(`Malformed WWW-Authenticate header (empty key) at offset ${String(i)}`);
    }
    skipWs();
    if (rest[i] !== "=") {
      throw new Error(`Missing "=" after key "${key}" at offset ${String(i)}`);
    }
    i += 1; // consume "="
    skipWs();

    let value: string;
    if (rest[i] === '"') {
      // Quoted-string.
      i += 1;
      const valStart = i;
      while (i < len) {
        const ch = rest[i];
        if (ch === "\\") {
          i += 2;
          continue;
        }
        if (ch === '"') break;
        i += 1;
      }
      if (rest[i] !== '"') {
        throw new Error(`Unterminated quoted-string for key "${key}"`);
      }
      const rawValue = rest.slice(valStart, i);
      value = unescapeQuotedString(rawValue);
      i += 1; // consume closing quote
    } else {
      // Token value (no whitespace, no comma).
      const valStart = i;
      while (i < len && rest[i] !== "," && rest[i] !== " " && rest[i] !== "\t") {
        i += 1;
      }
      value = rest.slice(valStart, i);
      if (value.length === 0) {
        throw new Error(`Empty token value for key "${key}"`);
      }
    }

    params[key] = value;

    skipWs();
    if (i < len) {
      if (rest[i] !== ",") {
        throw new Error(`Expected "," between params at offset ${String(i)}`);
      }
      i += 1; // consume ","
    }
  }

  return { scheme, params };
}
