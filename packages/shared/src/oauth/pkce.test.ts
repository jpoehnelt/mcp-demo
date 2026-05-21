import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { PKCEChallenge, PKCEVerifier } from "../types/brands.js";
import { unsafeBrand } from "../types/brands.js";
import { generatePKCE, verifyPKCE } from "./pkce.js";

// RFC 7636 §4.1 unreserved set: ALPHA / DIGIT / "-" / "." / "_" / "~".
const UNRESERVED_43_128 = /^[A-Za-z0-9._~-]{43,128}$/;

// RFC 7636 base64url challenge alphabet (no padding).
const BASE64URL_NO_PAD = /^[A-Za-z0-9_-]+$/;

describe("generatePKCE [INV-4.4]", () => {
  it("produces a 43-char verifier from the unreserved set", () => {
    const { verifier } = generatePKCE();
    expect(verifier).toHaveLength(43);
    expect(UNRESERVED_43_128.test(verifier)).toBe(true);
  });

  it("produces a challenge equal to base64url(SHA-256(verifier))", () => {
    const { verifier, challenge } = generatePKCE();
    const expected = createHash("sha256").update(verifier).digest("base64url");
    expect(challenge).toBe(expected);
    expect(BASE64URL_NO_PAD.test(challenge)).toBe(true);
  });

  it("reports the S256 method", () => {
    const { method } = generatePKCE();
    expect(method).toBe("S256");
  });

  it("generates fresh values on every call", () => {
    const a = generatePKCE();
    const b = generatePKCE();
    expect(a.verifier).not.toBe(b.verifier);
    expect(a.challenge).not.toBe(b.challenge);
  });
});

describe("verifyPKCE", () => {
  it("matches the RFC 7636 §B reference vector [INV-4.4]", () => {
    // From RFC 7636 Appendix B:
    //   verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    //   challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    const verifier = unsafeBrand<string, "PKCEVerifier">(
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    );
    const challenge = unsafeBrand<string, "PKCEChallenge">(
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
    expect(verifyPKCE(verifier, challenge)).toBe(true);
  });

  it("returns true for a freshly-generated matching pair", () => {
    const { verifier, challenge } = generatePKCE();
    expect(verifyPKCE(verifier, challenge)).toBe(true);
  });

  it("returns false when the challenge belongs to a different verifier", () => {
    const a = generatePKCE();
    const b = generatePKCE();
    expect(verifyPKCE(a.verifier, b.challenge)).toBe(false);
  });

  it("returns false for a length-mismatched challenge without throwing", () => {
    const { verifier } = generatePKCE();
    const bogus: PKCEChallenge = unsafeBrand<string, "PKCEChallenge">("short");
    expect(() => verifyPKCE(verifier, bogus)).not.toThrow();
    expect(verifyPKCE(verifier, bogus)).toBe(false);
  });

  it("returns false for an empty challenge without throwing", () => {
    const { verifier } = generatePKCE();
    const empty: PKCEChallenge = unsafeBrand<string, "PKCEChallenge">("");
    expect(() => verifyPKCE(verifier, empty)).not.toThrow();
    expect(verifyPKCE(verifier, empty)).toBe(false);
  });

  it("does not accept a verifier with one byte flipped", () => {
    const { verifier, challenge } = generatePKCE();
    // Flip the last character to a different unreserved-set char.
    const last = verifier.at(-1);
    const flipped = `${verifier.slice(0, -1)}${last === "A" ? "B" : "A"}`;
    const mutated: PKCEVerifier = unsafeBrand<string, "PKCEVerifier">(flipped);
    expect(verifyPKCE(mutated, challenge)).toBe(false);
  });
});
