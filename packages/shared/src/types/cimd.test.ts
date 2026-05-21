import { describe, expect, it } from "vitest";
import { z } from "zod";
import { parseCIMDDocument } from "./cimd.js";

const minimalValid = {
  client_id: "https://client.example.com/cimd",
  client_name: "Example Client",
  redirect_uris: ["https://client.example.com/cb"],
};

describe("parseCIMDDocument", () => {
  describe("happy path", () => {
    it("accepts the minimal valid document and applies defaults", () => {
      const parsed = parseCIMDDocument(minimalValid, { allowInsecure: false });
      expect(parsed.client_id).toBe("https://client.example.com/cimd");
      expect(parsed.client_name).toBe("Example Client");
      expect(parsed.redirect_uris).toEqual(["https://client.example.com/cb"]);
      expect(parsed.grant_types).toEqual(["authorization_code"]);
      expect(parsed.response_types).toEqual(["code"]);
      expect(parsed.token_endpoint_auth_method).toBe("none");
    });

    it("accepts a full document with all optional fields", () => {
      const parsed = parseCIMDDocument(
        {
          ...minimalValid,
          client_uri: "https://client.example.com/",
          logo_uri: "https://client.example.com/logo.png",
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
          token_endpoint_auth_method: "none",
          scope: "read write",
        },
        { allowInsecure: false },
      );
      expect(parsed.grant_types).toEqual(["authorization_code", "refresh_token"]);
      expect(parsed.scope).toBe("read write");
    });

    it("accepts http://127.0.0.1[:port] client_id only when allowInsecure is true", () => {
      const doc = {
        ...minimalValid,
        client_id: "http://127.0.0.1:8080/cimd",
      };
      expect(() => parseCIMDDocument(doc, { allowInsecure: true })).not.toThrow();
      expect(() => parseCIMDDocument(doc, { allowInsecure: false })).toThrow(z.ZodError);
    });

    it("accepts http://127.0.0.1[:port] redirect_uris regardless of allowInsecure", () => {
      const doc = {
        ...minimalValid,
        redirect_uris: ["http://127.0.0.1:5173/cb"],
      };
      expect(() => parseCIMDDocument(doc, { allowInsecure: false })).not.toThrow();
      expect(() => parseCIMDDocument(doc, { allowInsecure: true })).not.toThrow();
    });
  });

  describe("required-field omissions", () => {
    it("rejects missing client_id", () => {
      const { client_id: _ignored, ...rest } = minimalValid;
      expect(() => parseCIMDDocument(rest, { allowInsecure: false })).toThrow(z.ZodError);
    });

    it("rejects missing client_name", () => {
      const { client_name: _ignored, ...rest } = minimalValid;
      expect(() => parseCIMDDocument(rest, { allowInsecure: false })).toThrow(z.ZodError);
    });

    it("rejects missing redirect_uris", () => {
      const { redirect_uris: _ignored, ...rest } = minimalValid;
      expect(() => parseCIMDDocument(rest, { allowInsecure: false })).toThrow(z.ZodError);
    });

    it("rejects empty redirect_uris array", () => {
      expect(() =>
        parseCIMDDocument({ ...minimalValid, redirect_uris: [] }, { allowInsecure: false }),
      ).toThrow(z.ZodError);
    });
  });

  describe("strict mode — unknown top-level keys", () => {
    it("rejects an unknown top-level key", () => {
      expect(() =>
        parseCIMDDocument({ ...minimalValid, software_id: "unexpected" }, { allowInsecure: false }),
      ).toThrow(z.ZodError);
    });
  });

  describe("client_id rules", () => {
    it("rejects a bare domain (empty path)", () => {
      expect(() =>
        parseCIMDDocument(
          { ...minimalValid, client_id: "https://client.example.com" },
          { allowInsecure: false },
        ),
      ).toThrow(z.ZodError);
    });

    it("rejects a root path", () => {
      expect(() =>
        parseCIMDDocument(
          { ...minimalValid, client_id: "https://client.example.com/" },
          { allowInsecure: false },
        ),
      ).toThrow(z.ZodError);
    });

    it("rejects http:// (non-loopback)", () => {
      expect(() =>
        parseCIMDDocument(
          { ...minimalValid, client_id: "http://client.example.com/cimd" },
          { allowInsecure: true },
        ),
      ).toThrow(z.ZodError);
    });

    it("rejects non-URL values", () => {
      expect(() =>
        parseCIMDDocument({ ...minimalValid, client_id: "not-a-url" }, { allowInsecure: false }),
      ).toThrow(z.ZodError);
    });
  });

  describe("redirect_uris rules", () => {
    it("rejects http://localhost", () => {
      expect(() =>
        parseCIMDDocument(
          { ...minimalValid, redirect_uris: ["http://localhost:5173/cb"] },
          { allowInsecure: true },
        ),
      ).toThrow(z.ZodError);
    });

    it("rejects non-https / non-loopback http entries", () => {
      expect(() =>
        parseCIMDDocument(
          { ...minimalValid, redirect_uris: ["http://example.com/cb"] },
          { allowInsecure: true },
        ),
      ).toThrow(z.ZodError);
    });
  });

  describe("grant_types / response_types / token_endpoint_auth_method", () => {
    it("rejects an unknown grant_type", () => {
      expect(() =>
        parseCIMDDocument(
          { ...minimalValid, grant_types: ["client_credentials"] },
          { allowInsecure: false },
        ),
      ).toThrow(z.ZodError);
    });

    it("rejects an unknown response_type", () => {
      expect(() =>
        parseCIMDDocument({ ...minimalValid, response_types: ["token"] }, { allowInsecure: false }),
      ).toThrow(z.ZodError);
    });

    it("rejects an unknown token_endpoint_auth_method", () => {
      expect(() =>
        parseCIMDDocument(
          { ...minimalValid, token_endpoint_auth_method: "client_secret_basic" },
          { allowInsecure: false },
        ),
      ).toThrow(z.ZodError);
    });
  });
});
