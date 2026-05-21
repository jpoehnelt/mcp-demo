// SSRF-safe HTTP fetch. See specs/shared-library.md §3.2 and
// specs/authorization-server.md §4.3 for the denylist table, and
// specs/architecture.md §4.9 for the invariant this enforces.
//
// Defense in depth:
//   1. Parse URL, resolve ALL A + AAAA records.
//   2. If ANY resolved address is in a denylisted range, refuse the request.
//      (An attacker who controls DNS can mix one public IP with one private
//       IP — we lose if we try other addresses, so we just bail.)
//   3. Pin the connection to a pre-approved address by overriding the
//      `lookup` option of node:http / node:https. The fetch cannot do a
//      fresh DNS query mid-flight (defeats DNS rebinding — invariant §4.9).
//   4. AbortController timeout + maxRedirects=0 + byte-cap streamed body +
//      content-type validation.

import { Buffer } from "node:buffer";
import * as dns from "node:dns";
import * as http from "node:http";
import * as https from "node:https";
import { InvalidContentTypeError, MaxBytesExceededError, SSRFBlockedError } from "../errors.js";

// ---------------------------------------------------------------------------
// IP address classification
// ---------------------------------------------------------------------------

/** Parse a dotted-quad IPv4 string to a 32-bit unsigned integer, or null. */
function parseIPv4(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (part.length === 0 || part.length > 3) return null;
    if (!/^\d+$/.test(part)) return null;
    const n = Number.parseInt(part, 10);
    if (n < 0 || n > 255) return null;
    value = value * 256 + n;
  }
  // Ensure unsigned 32-bit representation.
  return value >>> 0;
}

/**
 * Returns true if `ipv4Int` (a 32-bit unsigned int) is in `cidr` (e.g. "10.0.0.0/8").
 * Internal helper; assumes `cidr` is well-formed.
 */
function ipv4InCidr(ipv4Int: number, cidr: string): boolean {
  const [base, prefixStr] = cidr.split("/");
  if (base === undefined || prefixStr === undefined) return false;
  const prefix = Number.parseInt(prefixStr, 10);
  const baseInt = parseIPv4(base);
  if (baseInt === null) return false;
  if (prefix === 0) return true;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (ipv4Int & mask) === (baseInt & mask);
}

/**
 * Parse an IPv6 address string to a Uint8Array of 16 bytes, or null.
 * Handles `::` compression and embedded IPv4 (e.g. `::ffff:192.0.2.1`).
 */
function parseIPv6(ip: string): Uint8Array | null {
  // Strip zone index (e.g. "fe80::1%eth0").
  const noZone = ip.split("%", 1)[0] ?? ip;

  // Detect embedded IPv4 suffix.
  let head = noZone;
  let tailV4: Uint8Array | null = null;
  const lastColon = noZone.lastIndexOf(":");
  if (lastColon >= 0 && noZone.includes(".", lastColon)) {
    const v4 = noZone.slice(lastColon + 1);
    const v4Int = parseIPv4(v4);
    if (v4Int === null) return null;
    tailV4 = new Uint8Array([
      (v4Int >>> 24) & 0xff,
      (v4Int >>> 16) & 0xff,
      (v4Int >>> 8) & 0xff,
      v4Int & 0xff,
    ]);
    head = noZone.slice(0, lastColon);
  }

  // Split by `::` (at most once).
  const doubleColonIdx = head.indexOf("::");
  let leftGroups: string[];
  let rightGroups: string[];
  if (doubleColonIdx === -1) {
    leftGroups = head === "" ? [] : head.split(":");
    rightGroups = [];
  } else {
    const leftStr = head.slice(0, doubleColonIdx);
    const rightStr = head.slice(doubleColonIdx + 2);
    leftGroups = leftStr === "" ? [] : leftStr.split(":");
    rightGroups = rightStr === "" ? [] : rightStr.split(":");
    if (head.indexOf("::", doubleColonIdx + 1) !== -1) return null;
  }

  const expectedGroups = tailV4 === null ? 8 : 6;
  const explicitGroups = leftGroups.length + rightGroups.length;
  if (explicitGroups > expectedGroups) return null;
  if (doubleColonIdx === -1 && explicitGroups !== expectedGroups) return null;

  const fillZeros = expectedGroups - explicitGroups;
  const allGroups = [
    ...leftGroups,
    ...Array.from({ length: fillZeros }, () => "0"),
    ...rightGroups,
  ];

  const bytes = new Uint8Array(16);
  for (let i = 0; i < allGroups.length; i += 1) {
    const g = allGroups[i];
    if (g === undefined || g.length === 0 || g.length > 4) return null;
    if (!/^[0-9a-fA-F]+$/.test(g)) return null;
    const v = Number.parseInt(g, 16);
    bytes[i * 2] = (v >>> 8) & 0xff;
    bytes[i * 2 + 1] = v & 0xff;
  }
  if (tailV4 !== null) {
    bytes.set(tailV4, 12);
  }
  return bytes;
}

const IPV4_DENY_CIDRS_BASE = Object.freeze([
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "169.254.0.0/16",
  "100.64.0.0/10",
  "224.0.0.0/4",
  "255.255.255.255/32",
  "0.0.0.0/8",
]);
const IPV4_LOOPBACK_CIDR = "127.0.0.0/8";

/**
 * Returns true if `ip` is a denylisted address per shared-library §3.2.
 *
 * `opts.allowLoopback`:
 *   * `false` — IPv4 `127.0.0.0/8` is denied along with every other family.
 *   * `true`  — IPv4 `127.0.0.0/8` is allowed; ALL other families (including
 *     IPv6 `::1`, link-local, ULA, multicast, etc.) remain denied.
 *
 * IPv4-mapped IPv6 (`::ffff:0:0/96`) recursively re-checks the embedded IPv4.
 *
 * Throws on syntactically invalid input — callers should already have
 * `dns.lookup` results which are always well-formed.
 */
export function isDeniedAddress(ip: string, opts: { allowLoopback: boolean }): boolean {
  if (typeof ip !== "string" || ip.length === 0) {
    throw new SSRFBlockedError(`Cannot classify empty IP address`);
  }

  // IPv4 fast path.
  const v4 = parseIPv4(ip);
  if (v4 !== null) {
    for (const cidr of IPV4_DENY_CIDRS_BASE) {
      if (ipv4InCidr(v4, cidr)) return true;
    }
    if (!opts.allowLoopback && ipv4InCidr(v4, IPV4_LOOPBACK_CIDR)) return true;
    return false;
  }

  const v6 = parseIPv6(ip);
  if (v6 === null) {
    throw new SSRFBlockedError(`Unparseable IP address: ${ip}`);
  }

  // IPv4-mapped (::ffff:0:0/96): bytes 0..9 == 0, bytes 10..11 == 0xff.
  let isV4Mapped = true;
  for (let i = 0; i < 10; i += 1) {
    if (v6[i] !== 0) {
      isV4Mapped = false;
      break;
    }
  }
  if (isV4Mapped && v6[10] === 0xff && v6[11] === 0xff) {
    const embeddedInt =
      ((v6[12] ?? 0) << 24) | ((v6[13] ?? 0) << 16) | ((v6[14] ?? 0) << 8) | (v6[15] ?? 0);
    const embedded = `${String(v6[12])}.${String(v6[13])}.${String(v6[14])}.${String(v6[15])}`;
    // Recurse-ish: re-check the embedded IPv4 against the IPv4 rules.
    const embeddedUnsigned = embeddedInt >>> 0;
    for (const cidr of IPV4_DENY_CIDRS_BASE) {
      if (ipv4InCidr(embeddedUnsigned, cidr)) return true;
    }
    if (!opts.allowLoopback && ipv4InCidr(embeddedUnsigned, IPV4_LOOPBACK_CIDR)) return true;
    // Verify the textual form parses identically (defensive).
    if (parseIPv4(embedded) !== embeddedUnsigned) {
      throw new SSRFBlockedError(`Malformed IPv4-mapped IPv6: ${ip}`);
    }
    return false;
  }

  // IPv6 loopback ::1
  if (
    v6[0] === 0 &&
    v6[1] === 0 &&
    v6[2] === 0 &&
    v6[3] === 0 &&
    v6[4] === 0 &&
    v6[5] === 0 &&
    v6[6] === 0 &&
    v6[7] === 0 &&
    v6[8] === 0 &&
    v6[9] === 0 &&
    v6[10] === 0 &&
    v6[11] === 0 &&
    v6[12] === 0 &&
    v6[13] === 0 &&
    v6[14] === 0 &&
    v6[15] === 1
  ) {
    return true;
  }

  // IPv6 unspecified ::
  if (v6.every((b) => b === 0)) {
    return true;
  }

  const b0 = v6[0] ?? 0;
  const b1 = v6[1] ?? 0;

  // IPv6 link-local fe80::/10 — top 10 bits == 1111111010.
  if (b0 === 0xfe && (b1 & 0xc0) === 0x80) return true;

  // IPv6 ULA fc00::/7 — top 7 bits == 1111110.
  if ((b0 & 0xfe) === 0xfc) return true;

  // IPv6 multicast ff00::/8.
  if (b0 === 0xff) return true;

  return false;
}

// ---------------------------------------------------------------------------
// safeFetch
// ---------------------------------------------------------------------------

export interface SafeFetchOptions {
  /** When true, `http://` + IPv4 loopback (`127.0.0.0/8`) is allowed. */
  allowInsecure: boolean;
  /** Maximum response body bytes. Exceeding → `MaxBytesExceededError`. */
  maxBytes: number;
  /** Per-request timeout in milliseconds. */
  timeoutMs: number;
  /** Expected `Content-Type` (media type only, no parameters). */
  expectContentType: string;
}

/**
 * Shape of the `lookup` option accepted by `net.Socket.connect` /
 * `http.request`. We type it as Node's `net.LookupFunction` so the assignment
 * to `http.RequestOptions.lookup` typechecks.
 */
type LookupFn = (
  hostname: string,
  options: dns.LookupOptions,
  callback: (err: NodeJS.ErrnoException | null, address: string, family: number) => void,
) => void;

interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

/**
 * Injectable DNS lookup. Tests swap this via `__setLookupForTests`; production
 * code uses Node's `dns.lookup`. The seam is necessary because ESM module
 * namespaces are immutable — `vi.spyOn(dns, "lookup")` throws under NodeNext.
 */
let lookupImpl: typeof dns.lookup = dns.lookup;

/**
 * Test-only: replace the `dns.lookup` implementation used by `resolveAll` and
 * the pinned-lookup fallback. Returns the previous implementation so tests
 * can restore it.
 *
 * @internal
 */
export function __setLookupForTests(fn: typeof dns.lookup): typeof dns.lookup {
  const previous = lookupImpl;
  lookupImpl = fn;
  return previous;
}

/**
 * Resolve a hostname to ALL A + AAAA records. If the host is a literal IP we
 * skip DNS entirely. Used as the first step of `safeFetch`.
 */
function resolveAll(hostname: string): Promise<ResolvedAddress[]> {
  // dns.lookup with all:true returns every A + AAAA the resolver knows about.
  // We deliberately use `lookup` (not `resolve4/6`) so /etc/hosts is honored —
  // matches what the kernel will use at connect time when not pinned.
  return new Promise((resolve, reject) => {
    lookupImpl(hostname, { all: true, verbatim: true }, (err, addresses) => {
      if (err !== null && err !== undefined) {
        reject(err);
        return;
      }
      const out: ResolvedAddress[] = addresses.map((a) => ({
        address: a.address,
        family: a.family === 6 ? 6 : 4,
      }));
      resolve(out);
    });
  });
}

/**
 * Read response body up to `maxBytes`. Aborts early via `controller` if
 * exceeded; throws `MaxBytesExceededError` after the abort.
 */
function readCapped(
  res: http.IncomingMessage,
  maxBytes: number,
  controller: AbortController,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let aborted = false;
    res.on("data", (chunk: Buffer) => {
      if (aborted) return;
      total += chunk.length;
      if (total > maxBytes) {
        aborted = true;
        controller.abort();
        res.destroy();
        reject(new MaxBytesExceededError(`Response exceeded ${String(maxBytes)} bytes`));
        return;
      }
      chunks.push(chunk);
    });
    res.on("end", () => {
      if (!aborted) resolve(Buffer.concat(chunks));
    });
    res.on("error", (err) => {
      if (!aborted) reject(err);
    });
  });
}

function mediaTypeOf(contentType: string | undefined): string {
  if (contentType === undefined) return "";
  const semi = contentType.indexOf(";");
  const head = semi === -1 ? contentType : contentType.slice(0, semi);
  return head.trim().toLowerCase();
}

/**
 * SSRF-safe one-shot HTTP fetch. See module header for invariants.
 *
 * Throws:
 *   * `SSRFBlockedError` — any resolved address is denylisted, or the URL is
 *     unparseable / uses an unsupported scheme.
 *   * `MaxBytesExceededError` — response body exceeds `maxBytes`.
 *   * `InvalidContentTypeError` — response `Content-Type` doesn't match
 *     `expectContentType`.
 *   * Generic `Error` — redirect encountered (we never follow), socket
 *     error, or timeout abort.
 */
export async function safeFetch(
  url: string,
  opts: SafeFetchOptions,
): Promise<{ status: number; body: string; headers: Headers }> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (cause) {
    throw new SSRFBlockedError(`Unparseable URL: ${url}`, { cause });
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new SSRFBlockedError(`Unsupported scheme: ${parsed.protocol}`);
  }

  const allowLoopback = opts.allowInsecure;
  if (parsed.protocol === "http:" && !allowLoopback) {
    // We allow http only when allowInsecure is true; that flag also opens up
    // loopback. Without it, plaintext is refused outright.
    throw new SSRFBlockedError(`Plaintext http:// not allowed (allowInsecure=false)`);
  }

  // Step 1+2: resolve all A+AAAA, deny if any one is in a denylisted range.
  const hostname = parsed.hostname;
  // Strip brackets for IPv6 literals: URL.hostname returns "[::1]" -> we want "::1".
  const bareHost =
    hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;

  // If the URL host is itself an IP literal, dns.lookup just echoes it back —
  // we still feed it through the same path so the deny check is uniform.
  const resolved = await resolveAll(bareHost);
  if (resolved.length === 0) {
    throw new SSRFBlockedError(`No addresses resolved for host: ${bareHost}`);
  }
  for (const addr of resolved) {
    if (isDeniedAddress(addr.address, { allowLoopback })) {
      throw new SSRFBlockedError(`Resolved address ${addr.address} for ${bareHost} is denylisted`);
    }
  }

  // Step 3: pin the connection to the first approved address. The `lookup`
  // override returns that pin verbatim — node:http will not consult DNS again.
  const pin = resolved[0];
  if (pin === undefined) {
    throw new SSRFBlockedError(`No resolved address to pin for ${bareHost}`);
  }
  // node:net's `lookupAndConnect` calls the supplied `lookup` with
  // `dnsopts.all = true` (for happy-eyeballs) — the callback expects an array
  // of `{ address, family }`. When `all` is unset it expects the legacy
  // `(err, address, family)` shape. We honor both because callers (https
  // agent, direct http.request) can differ across Node releases.
  const pinnedLookup: LookupFn = (_hostname, options, callback) => {
    if (typeof options === "object" && options !== null && options.all === true) {
      // Cast: this overload of the callback expects the array shape.
      (
        callback as unknown as (
          err: NodeJS.ErrnoException | null,
          addresses: Array<{ address: string; family: number }>,
        ) => void
      )(null, [{ address: pin.address, family: pin.family }]);
      return;
    }
    callback(null, pin.address, pin.family);
  };

  // Step 4-6: dispatch the actual request.
  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort();
  }, opts.timeoutMs);
  // node:setTimeout returns a Timeout we don't want to keep the event loop alive.
  if (typeof timeout.unref === "function") timeout.unref();

  try {
    const requester = parsed.protocol === "https:" ? https.request : http.request;
    const reqOptions: http.RequestOptions = {
      method: "GET",
      protocol: parsed.protocol,
      hostname: bareHost,
      port: parsed.port === "" ? undefined : Number.parseInt(parsed.port, 10),
      path: `${parsed.pathname}${parsed.search}`,
      headers: {
        host: parsed.host,
        accept: opts.expectContentType,
      },
      lookup: pinnedLookup,
      signal: controller.signal,
    };

    const res = await new Promise<http.IncomingMessage>((resolve, reject) => {
      const req = requester(reqOptions, (response) => {
        resolve(response);
      });
      req.on("error", (err) => {
        reject(err);
      });
      req.end();
    });

    const status = res.statusCode ?? 0;

    // maxRedirects: 0 — surface 3xx as an error rather than silently following.
    if (status >= 300 && status < 400) {
      res.destroy();
      throw new SSRFBlockedError(`Redirect (${String(status)}) not allowed (maxRedirects=0)`);
    }

    const bodyBuf = await readCapped(res, opts.maxBytes, controller);

    // Build a Headers object from the response headers for the return shape.
    const headers = new Headers();
    for (const [k, v] of Object.entries(res.headers)) {
      if (v === undefined) continue;
      if (Array.isArray(v)) {
        for (const item of v) headers.append(k, item);
      } else {
        headers.set(k, v);
      }
    }

    const actualMedia = mediaTypeOf(headers.get("content-type") ?? undefined);
    const expectedMedia = opts.expectContentType.toLowerCase();
    if (actualMedia !== expectedMedia) {
      throw new InvalidContentTypeError(
        `Expected Content-Type ${expectedMedia}, got "${actualMedia}"`,
      );
    }

    return { status, body: bodyBuf.toString("utf8"), headers };
  } finally {
    clearTimeout(timeout);
  }
}
