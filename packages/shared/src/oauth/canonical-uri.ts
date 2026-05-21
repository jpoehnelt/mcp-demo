// Canonical URI handling per architecture §4.11 and shared-library §2.1.
//
// Rules:
//   * lowercase scheme + host
//   * strip default port (`:80` for http, `:443` for https)
//   * remove fragment
//   * remove trailing slash; a path of `/` collapses to empty
//   * normalize percent-encoding per RFC 3986 §6.2.2
//     (uppercase hex digits; decode unreserved set)
//   * reject non-absolute URLs
//
// Canonical form is what every audience, issuer, PRM `resource`, and CIMD
// `client_id` comparison runs through, so subtle bugs here break invariants
// §4.1 (audience), §4.2 (issuer), §4.9 (CIMD URL), and §4.10 (redirect URI).

import { Buffer } from "node:buffer";
import { timingSafeEqual } from "node:crypto";
import { InvalidCanonicalURIError } from "../errors.js";
import type { CanonicalURI } from "../types/brands.js";
import { unsafeBrand } from "../types/brands.js";

const DEFAULT_PORTS: Readonly<Record<string, string>> = Object.freeze({
  "http:": "80",
  "https:": "443",
});

// RFC 3986 §2.3 unreserved set.
function isUnreservedByte(byte: number): boolean {
  // ALPHA
  if ((byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a)) return true;
  // DIGIT
  if (byte >= 0x30 && byte <= 0x39) return true;
  // "-" / "." / "_" / "~"
  return byte === 0x2d || byte === 0x2e || byte === 0x5f || byte === 0x7e;
}

function isHexDigit(ch: string): boolean {
  return (ch >= "0" && ch <= "9") || (ch >= "A" && ch <= "F") || (ch >= "a" && ch <= "f");
}

/**
 * Normalize percent-encoded triplets per RFC 3986 §6.2.2:
 *   1. Uppercase hex digits in `%HH`.
 *   2. Decode percent-encoded bytes that fall in the unreserved set.
 * Untouched bytes (reserved/delimiters) pass through.
 *
 * The input is the already-parsed component (path / query). We operate on the
 * raw component as written by `URL`, which preserves percent-triplets verbatim.
 */
function normalizePercentEncoding(component: string): string {
  let out = "";
  let i = 0;
  while (i < component.length) {
    const ch = component[i];
    if (ch === "%" && i + 2 < component.length) {
      const h1 = component[i + 1];
      const h2 = component[i + 2];
      if (h1 !== undefined && h2 !== undefined && isHexDigit(h1) && isHexDigit(h2)) {
        const upper = `${h1}${h2}`.toUpperCase();
        const byte = Number.parseInt(upper, 16);
        if (isUnreservedByte(byte)) {
          out += String.fromCharCode(byte);
        } else {
          out += `%${upper}`;
        }
        i += 3;
        continue;
      }
      // A `%` not followed by two hex digits is malformed per RFC 3986 §2.1.
      throw new InvalidCanonicalURIError(
        `Malformed percent-encoding at offset ${String(i)} in component "${component}"`,
      );
    }
    out += ch;
    i += 1;
  }
  return out;
}

/**
 * Returns the canonical form of an absolute URL.
 *
 * Throws `InvalidCanonicalURIError` if:
 *   * input is not a string,
 *   * input is empty / not an absolute URL,
 *   * percent-encoding is malformed.
 */
export function canonicalize(url: string): CanonicalURI {
  if (typeof url !== "string" || url.length === 0) {
    throw new InvalidCanonicalURIError("Canonical URI must be a non-empty string");
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (cause) {
    throw new InvalidCanonicalURIError(`Not an absolute URL: "${url}"`, { cause });
  }

  // `new URL("/foo", undefined)` would have thrown above, but guard anyway: a
  // URL with an empty protocol is not absolute by our definition.
  if (parsed.protocol === "" || parsed.host === "") {
    throw new InvalidCanonicalURIError(`Not an absolute URL: "${url}"`);
  }

  // 1. Scheme: WHATWG `URL` already lowercases the protocol.
  const scheme = parsed.protocol.toLowerCase();

  // 2. Host: WHATWG `URL` lowercases ASCII host labels and IDNA-encodes
  //    non-ASCII labels; force lowercase for defense-in-depth.
  const host = parsed.hostname.toLowerCase();

  // 3. Port: strip the default port for the scheme.
  let portSegment = "";
  if (parsed.port !== "" && DEFAULT_PORTS[scheme] !== parsed.port) {
    portSegment = `:${parsed.port}`;
  }

  // 4. Path: collapse `/` to empty; otherwise strip a single trailing slash.
  //    Percent-encoding is normalized.
  let path = parsed.pathname;
  if (path === "/") {
    path = "";
  } else if (path.length > 1 && path.endsWith("/")) {
    path = path.slice(0, -1);
  }
  path = normalizePercentEncoding(path);

  // 5. Query: preserved but percent-encoding normalized. (The MCP canonical
  //    server URI rules don't strip query, and downstream code only canonicalizes
  //    URIs that have no query in practice; we still normalize for safety.)
  const query = parsed.search === "" ? "" : normalizePercentEncoding(parsed.search);

  // 6. Fragment: dropped.

  // 7. Userinfo is intentionally dropped — canonical OAuth identifiers never
  //    carry userinfo, and silently keeping it would let two visually-distinct
  //    strings collide.
  const canonical = `${scheme}//${host}${portSegment}${path}${query}`;
  return unsafeBrand<string, "CanonicalURI">(canonical);
}

/**
 * Constant-time equality on the canonical form of two URLs.
 *
 * Both inputs MUST canonicalize successfully — a malformed URI throws the
 * same `InvalidCanonicalURIError` as `canonicalize` would, since silently
 * returning `false` would hide bugs at call sites that already validated.
 *
 * Length-mismatched inputs return `false` immediately (length is not secret
 * and `timingSafeEqual` requires equal-length buffers).
 */
export function equalsCanonical(a: string, b: string): boolean {
  const ca = canonicalize(a);
  const cb = canonicalize(b);
  const ba = Buffer.from(ca, "utf8");
  const bb = Buffer.from(cb, "utf8");
  if (ba.length !== bb.length) {
    return false;
  }
  return timingSafeEqual(ba, bb);
}
