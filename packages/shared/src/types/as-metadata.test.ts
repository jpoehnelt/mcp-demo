import { describe, expect, it } from "vitest";
import { z } from "zod";
import { parseASMetadata } from "./as-metadata.js";

const minimalValid = {
  issuer: "https://idp.example.com",
  authorization_endpoint: "https://idp.example.com/authorize",
  token_endpoint: "https://idp.example.com/token",
  jwks_uri: "https://idp.example.com/.well-known/jwks.json",
  response_types_supported: ["code"],
  code_challenge_methods_supported: ["S256"],
};

describe("parseASMetadata", () => {
  describe("happy path", () => {
    it("accepts the minimal valid document", () => {
      const parsed = parseASMetadata(minimalValid);
      expect(parsed.issuer).toBe("https://idp.example.com");
      expect(parsed.code_challenge_methods_supported).toEqual(["S256"]);
    });

    it("accepts a full document with optional fields", () => {
      const parsed = parseASMetadata({
        ...minimalValid,
        grant_types_supported: ["authorization_code", "refresh_token"],
        scopes_supported: ["openid", "read", "write"],
        token_endpoint_auth_methods_supported: ["none"],
        client_id_metadata_document_supported: true,
        registration_endpoint: "https://idp.example.com/register",
      });
      expect(parsed.client_id_metadata_document_supported).toBe(true);
      expect(parsed.registration_endpoint).toBe("https://idp.example.com/register");
    });

    it("accepts code_challenge_methods_supported without S256 (downstream slice 5 enforces)", () => {
      // The schema itself does NOT enforce S256 presence — that's slice 5 (discovery).
      const parsed = parseASMetadata({
        ...minimalValid,
        code_challenge_methods_supported: ["plain"],
      });
      expect(parsed.code_challenge_methods_supported).toEqual(["plain"]);
    });
  });

  describe("required-field omissions", () => {
    it("rejects missing issuer", () => {
      const { issuer: _ignored, ...rest } = minimalValid;
      expect(() => parseASMetadata(rest)).toThrow(z.ZodError);
    });

    it("rejects missing authorization_endpoint", () => {
      const { authorization_endpoint: _ignored, ...rest } = minimalValid;
      expect(() => parseASMetadata(rest)).toThrow(z.ZodError);
    });

    it("rejects missing token_endpoint", () => {
      const { token_endpoint: _ignored, ...rest } = minimalValid;
      expect(() => parseASMetadata(rest)).toThrow(z.ZodError);
    });

    it("rejects missing jwks_uri", () => {
      const { jwks_uri: _ignored, ...rest } = minimalValid;
      expect(() => parseASMetadata(rest)).toThrow(z.ZodError);
    });

    it("rejects missing response_types_supported", () => {
      const { response_types_supported: _ignored, ...rest } = minimalValid;
      expect(() => parseASMetadata(rest)).toThrow(z.ZodError);
    });

    it("rejects missing code_challenge_methods_supported", () => {
      const { code_challenge_methods_supported: _ignored, ...rest } = minimalValid;
      expect(() => parseASMetadata(rest)).toThrow(z.ZodError);
    });

    it("rejects empty response_types_supported", () => {
      expect(() => parseASMetadata({ ...minimalValid, response_types_supported: [] })).toThrow(
        z.ZodError,
      );
    });

    it("rejects empty code_challenge_methods_supported", () => {
      expect(() =>
        parseASMetadata({ ...minimalValid, code_challenge_methods_supported: [] }),
      ).toThrow(z.ZodError);
    });
  });
});
