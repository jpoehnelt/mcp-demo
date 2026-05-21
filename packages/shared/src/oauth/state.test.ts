import { describe, expect, it } from "vitest";
import { unsafeBrand } from "../types/brands.js";
import { generateState, verifyState } from "./state.js";

const BASE64URL_43 = /^[A-Za-z0-9_-]{43}$/;

describe("generateState [INV-4.14]", () => {
  it("produces a 43-char base64url string (32 bytes → ≥256 bits entropy)", () => {
    const state = generateState();
    expect(state).toHaveLength(43);
    expect(BASE64URL_43.test(state)).toBe(true);
  });

  it("returns a fresh value on every call", () => {
    const a = generateState();
    const b = generateState();
    expect(a).not.toBe(b);
  });
});

describe("verifyState", () => {
  it("returns true for the same value [INV-4.14]", () => {
    const state = generateState();
    expect(verifyState(state, state)).toBe(true);
  });

  it("returns false for two different same-length values", () => {
    const a = generateState();
    const b = generateState();
    expect(verifyState(a, b)).toBe(false);
  });

  it("returns false for an empty string without throwing", () => {
    const expected = generateState();
    expect(() => verifyState("", expected)).not.toThrow();
    expect(verifyState("", expected)).toBe(false);
  });

  it("returns false when the received value is shorter", () => {
    const expected = generateState();
    const shorter = expected.slice(0, -4);
    expect(() => verifyState(shorter, expected)).not.toThrow();
    expect(verifyState(shorter, expected)).toBe(false);
  });

  it("returns false when one byte is flipped", () => {
    const expected = generateState();
    const first = expected[0];
    const flipped = `${first === "A" ? "B" : "A"}${expected.slice(1)}`;
    expect(verifyState(flipped, expected)).toBe(false);
  });

  it("accepts the branded expected parameter without consuming brand for received", () => {
    // Compile-time check: `received` is plain string; only `expected` is branded.
    const expected = generateState();
    const raw: string = expected;
    expect(verifyState(raw, expected)).toBe(true);
    // And rejects a plainly-different unbranded string of the same shape.
    const otherRaw: string = unsafeBrand<string, "StateParam">(
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
    expect(verifyState(otherRaw, expected)).toBe(false);
  });
});
