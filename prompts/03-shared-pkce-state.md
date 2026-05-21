# Step 3 — Shared PKCE + State

## Spec anchors

- [architecture.md §4.4](../specs/architecture.md) — Invariant: PKCE S256 required
- [architecture.md §4.14](../specs/architecture.md) — Invariant: CSRF state ≥128 bits
- [shared-library.md §2.2](../specs/shared-library.md) — PKCE module
- [shared-library.md §2.3](../specs/shared-library.md) — CSRF state module

## Goal

Pure crypto helpers for PKCE (RFC 7636) and OAuth `state` (CSRF defense). Both use `crypto.timingSafeEqual` for comparisons.

## Deliverables

- `packages/shared/src/oauth/pkce.ts` + `pkce.test.ts`
- `packages/shared/src/oauth/state.ts` + `state.test.ts`
- Update `packages/shared/src/index.ts` to re-export

## Public API

```ts
// pkce.ts
export function generatePKCE(): {
  verifier: PKCEVerifier;
  challenge: PKCEChallenge;
  method: "S256";
};

export function verifyPKCE(
  verifier: PKCEVerifier,
  challenge: PKCEChallenge,
): boolean; // constant-time

// state.ts
export function generateState(): StateParam;
export function verifyState(received: string, expected: StateParam): boolean; // constant-time
```

`PKCEVerifier`, `PKCEChallenge`, and `StateParam` come from `types/brands.ts` (slice 1). Mint them via `unsafeBrand` only inside these modules, immediately after the invariant check.

## Acceptance criteria

### PKCE

- Verifier: 43–128 chars from the unreserved set (`ALPHA / DIGIT / "-" / "." / "_" / "~"`) per [RFC 7636 §4.1](https://datatracker.ietf.org/doc/html/rfc7636#section-4.1).
- Verifier entropy: ≥256 bits. Use `crypto.randomBytes(32)`, then base64url-encode (Node `'base64url'` encoding) — that produces 43 chars from the unreserved set.
- **Do NOT use `Buffer.from(x, 'base64')`** — use Node's `'base64url'` encoding; padding and charset differ.
- Challenge: `base64url(SHA-256(ASCII(verifier)))` with NO padding. Use `crypto.createHash('sha256')`.
- `verifyPKCE`: constant-time compare of `base64url(SHA-256(verifier))` vs the presented challenge using `crypto.timingSafeEqual`.

### State

- 32 random bytes (`crypto.randomBytes(32)`) base64url-encoded → ≥256 bits entropy, well above the 128-bit floor.
- `verifyState`: constant-time compare via `crypto.timingSafeEqual` on the raw byte buffers (decode the base64url first).
- Length-mismatch returns `false` without throwing.

## Test patterns

### PKCE

- Generated verifier is 43 chars, all from the unreserved set (regex `^[A-Za-z0-9._~-]{43,128}$`).
- Generated challenge is the SHA-256 base64url-no-padding of its verifier.
- `verifyPKCE(verifier, challenge)` returns `true` for matching pair.
- `verifyPKCE(verifier, otherChallenge)` returns `false`.
- Manually-crafted RFC 7636 §B example: `verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"` → `challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"`. Use this to prove correctness against the reference.
- Tag at least one test `[INV-4.4]`.

### State

- Generated state matches `^[A-Za-z0-9_-]{43}$` (32 bytes → 43 base64url chars).
- `verifyState(s, s)` is true; `verifyState(otherWithSameLen, s)` is false.
- `verifyState("", s)` returns false (different length, no throw).
- Tag at least one test `[INV-4.14]`.

## Out of scope

- Storing/retrieving the verifier/state (callers' responsibility).
- HTTP-level flow integration (slices 8, 9, 12).

## Verification

```bash
test -f packages/shared/src/oauth/pkce.ts
test -f packages/shared/src/oauth/pkce.test.ts
test -f packages/shared/src/oauth/state.ts
test -f packages/shared/src/oauth/state.test.ts

pnpm typecheck
pnpm lint
pnpm test

# Invariant tags exist
pnpm exec vitest run -t '[INV-4.4]' --reporter=verbose
pnpm exec vitest run -t '[INV-4.14]' --reporter=verbose

# Independent AI review — address findings before commit
cr review --agent --type uncommitted -c CLAUDE.md -c specs/shared-library.md
```

All gate commands must exit 0. CodeRabbit findings: address or explicitly acknowledge.
