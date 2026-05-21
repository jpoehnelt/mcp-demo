# Step 4 — Shared HTTP Layer

## Spec anchors

- [shared-library.md §3.1](../specs/shared-library.md) — `WWW-Authenticate` header helpers
- [shared-library.md §3.2](../specs/shared-library.md) — SSRF-safe fetch
- [architecture.md §4.9](../specs/architecture.md) — Invariant: CIMD URL validation + SSRF rejection
- [authorization-server.md §4.3](../specs/authorization-server.md) — SSRF protection (full IP family table)

## Goal

Land the SSRF-safe fetch (used by the IdP when retrieving CIMD documents and by the MCP server when fetching JWKS via discovery) and the `WWW-Authenticate` header build/parse helpers (used by the MCP server's 401/403 responses).

## Deliverables

- `packages/shared/src/http/ssrf.ts` + `ssrf.test.ts`
- `packages/shared/src/http/www-authenticate.ts` + `www-authenticate.test.ts`
- Update `packages/shared/src/index.ts` to re-export

## Public API

```ts
// ssrf.ts
export function isDeniedAddress(
  ip: string,
  opts: { allowLoopback: boolean },
): boolean;

export interface SafeFetchOptions {
  allowInsecure: boolean;     // when true, http:// + loopback is allowed
  maxBytes: number;
  timeoutMs: number;
  expectContentType: string;  // e.g. "application/json"
  // maxRedirects is hardcoded to 0
}

export function safeFetch(
  url: string,
  opts: SafeFetchOptions,
): Promise<{ status: number; body: string; headers: Headers }>;

// www-authenticate.ts
export function buildUnauthorizedHeader(opts: {
  realm: string;
  resourceMetadata: string;
  scope: string;
}): string;

export function buildInsufficientScopeHeader(opts: {
  realm: string;
  scope: string;
  resourceMetadata: string;
  errorDescription?: string;
}): string;

export function parseWWWAuthenticate(header: string): {
  scheme: string;
  params: Record<string, string>;
};
```

## Acceptance criteria

### SSRF (§3.2)

Denylisted address ranges (when `allowLoopback === false`):

| Family | Ranges |
|---|---|
| IPv4 private (RFC 1918) | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| IPv4 loopback | `127.0.0.0/8` (toggleable via `allowLoopback`) |
| IPv4 link-local | `169.254.0.0/16` |
| IPv4 CGNAT (RFC 6598) | `100.64.0.0/10` |
| IPv4 multicast | `224.0.0.0/4` |
| IPv4 broadcast / unspecified | `255.255.255.255/32`, `0.0.0.0/8` |
| IPv6 loopback | `::1/128` |
| IPv6 link-local | `fe80::/10` |
| IPv6 ULA | `fc00::/7` |
| IPv6 multicast | `ff00::/8` |
| IPv4-mapped IPv6 | `::ffff:0:0/96` (recursively re-check the embedded IPv4) |

When `allowLoopback === true`, IPv4 `127.0.0.0/8` is excluded; all other families still denied.

`safeFetch` steps (in order):

1. Parse URL. Resolve hostname to **all** A and AAAA records via `dns.lookup`.
2. If **any** resolved IP fails `isDeniedAddress` → `throw new SSRFBlockedError(...)`. Do not attempt connection to other addresses.
3. Pin the connection to a specific approved address (defeats DNS rebinding between resolve-time and connect-time). Use Node's `lookup` option on the fetch (or http(s) agent) to override DNS.
4. Fetch with `AbortController` for `timeoutMs` and `maxRedirects: 0`.
5. Stream the response body with a byte counter; if `maxBytes` exceeded → `throw new MaxBytesExceededError(...)`.
6. Validate response `Content-Type` matches `expectContentType` → `throw new InvalidContentTypeError(...)` if not.

### `WWW-Authenticate` (§3.1)

- `buildUnauthorizedHeader`: `Bearer realm="<...>", resource_metadata="<...>", scope="<...>"`.
- `buildInsufficientScopeHeader`: `Bearer realm="<...>", error="insufficient_scope", scope="<...>", resource_metadata="<...>"` (with optional `error_description="..."`).
- Quoted-string escaping per [RFC 7235 §2.1](https://datatracker.ietf.org/doc/html/rfc7235#section-2.1) — backslash-escape `"` and `\` inside quoted values.
- `parseWWWAuthenticate` returns `{ scheme, params }` from a syntactically valid header.

## Test patterns

### SSRF

- Each denylisted range from the table gets one positive test on `isDeniedAddress`.
- `allowLoopback: true` lets `127.0.0.1` through but still denies `10.0.0.1`, `::1`, `169.254.0.0`, etc.
- DNS-rebinding simulation: stub `dns.lookup` to return a public IP on first call and a private IP on second; assert `safeFetch` either rejects upfront OR the connection actually goes to the public IP (the pin worked). The strongest assertion is on the underlying `lookup` callback used by the fetch — check it was called once with the pinned IP.
- `maxRedirects: 0` is enforced — a 302 response → throw (don't follow).
- `maxBytes` exceeded → `MaxBytesExceededError`.
- Wrong `Content-Type` → `InvalidContentTypeError`.
- Tag the rebinding test `[INV-4.9]`.

### `WWW-Authenticate`

- Round-trip: `parseWWWAuthenticate(buildUnauthorizedHeader(opts)).params` equals `opts`.
- Quoted values containing `"` or `\` are correctly escaped/unescaped.
- Output is `Bearer ...` (scheme followed by space-separated `key="value"` params, comma-separated).

## Out of scope

- The JWT verifier itself (uses `safeFetch` indirectly via jose's remote JWKS, but that's slice 5).
- The discovery cascade (slice 5).
- App-level usage (slices 6+).

## Notes for the agent

- For the DNS pin, Node 18+'s `fetch` doesn't take a `lookup` option directly; use `undici.Agent` with a `connect: { lookup: ... }` override, or fall back to `https.request` + `http.request` with `lookup` option.
- Test the SSRF address logic without real network calls — `isDeniedAddress` is the pure function, `safeFetch` is integration. Use `nock` or vitest's `vi.spyOn(dns, 'lookup', ...)` to stub.

## Verification

```bash
test -f packages/shared/src/http/ssrf.ts
test -f packages/shared/src/http/ssrf.test.ts
test -f packages/shared/src/http/www-authenticate.ts
test -f packages/shared/src/http/www-authenticate.test.ts

pnpm typecheck
pnpm lint
pnpm test

pnpm exec vitest run -t '[INV-4.9]' --reporter=verbose

# Independent AI review — address findings before commit
cr review --agent --type uncommitted -c CLAUDE.md -c specs/shared-library.md
```

All gate commands must exit 0. CodeRabbit findings: address or explicitly acknowledge.
