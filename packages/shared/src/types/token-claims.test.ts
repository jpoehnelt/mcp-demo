import { describe, expect, it } from "vitest";
import { z } from "zod";
import { parseTokenClaims } from "./token-claims.js";

const minimalValid = {
  iss: "https://idp.example.com",
  sub: "user-123",
  aud: "https://api.example.com/mcp",
  exp: 1_900_000_000,
  iat: 1_700_000_000,
  jti: "jti-abc",
  scope: "read write",
  client_id: "https://client.example.com/cimd",
};

describe("parseTokenClaims", () => {
  describe("happy path", () => {
    it("accepts the minimal valid claims set", () => {
      const parsed = parseTokenClaims(minimalValid);
      expect(parsed.iss).toBe("https://idp.example.com");
      expect(parsed.aud).toBe("https://api.example.com/mcp");
      expect(parsed.scope).toBe("read write");
    });

    it("accepts aud as a non-empty string array (RFC 7519 §4.1.3)", () => {
      const parsed = parseTokenClaims({
        ...minimalValid,
        aud: ["https://api.example.com/mcp", "https://other.example.com"],
      });
      expect(parsed.aud).toEqual(["https://api.example.com/mcp", "https://other.example.com"]);
    });

    it("accepts optional nbf claim", () => {
      const parsed = parseTokenClaims({ ...minimalValid, nbf: 1_700_000_000 });
      expect(parsed.nbf).toBe(1_700_000_000);
    });

    it("accepts empty scope string", () => {
      const parsed = parseTokenClaims({ ...minimalValid, scope: "" });
      expect(parsed.scope).toBe("");
    });
  });

  describe("required-field omissions", () => {
    it("rejects missing iss", () => {
      const { iss: _ignored, ...rest } = minimalValid;
      expect(() => parseTokenClaims(rest)).toThrow(z.ZodError);
    });

    it("rejects missing sub", () => {
      const { sub: _ignored, ...rest } = minimalValid;
      expect(() => parseTokenClaims(rest)).toThrow(z.ZodError);
    });

    it("rejects missing aud", () => {
      const { aud: _ignored, ...rest } = minimalValid;
      expect(() => parseTokenClaims(rest)).toThrow(z.ZodError);
    });

    it("rejects missing exp", () => {
      const { exp: _ignored, ...rest } = minimalValid;
      expect(() => parseTokenClaims(rest)).toThrow(z.ZodError);
    });

    it("rejects missing iat", () => {
      const { iat: _ignored, ...rest } = minimalValid;
      expect(() => parseTokenClaims(rest)).toThrow(z.ZodError);
    });

    it("rejects missing jti", () => {
      const { jti: _ignored, ...rest } = minimalValid;
      expect(() => parseTokenClaims(rest)).toThrow(z.ZodError);
    });

    it("rejects missing scope", () => {
      const { scope: _ignored, ...rest } = minimalValid;
      expect(() => parseTokenClaims(rest)).toThrow(z.ZodError);
    });

    it("rejects missing client_id", () => {
      const { client_id: _ignored, ...rest } = minimalValid;
      expect(() => parseTokenClaims(rest)).toThrow(z.ZodError);
    });
  });

  describe("type rejections", () => {
    it("rejects empty aud array", () => {
      expect(() => parseTokenClaims({ ...minimalValid, aud: [] })).toThrow(z.ZodError);
    });

    it("rejects non-numeric exp", () => {
      expect(() => parseTokenClaims({ ...minimalValid, exp: "1900000000" })).toThrow(z.ZodError);
    });
  });
});
