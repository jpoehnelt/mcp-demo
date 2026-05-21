import { describe, expect, it } from "vitest";
import { z } from "zod";
import { parsePRM } from "./prm.js";

const minimalValid = {
  resource: "https://api.example.com/mcp",
  authorization_servers: ["https://idp.example.com"],
};

describe("parsePRM", () => {
  describe("happy path", () => {
    it("accepts the minimal valid document and applies bearer_methods_supported default", () => {
      const parsed = parsePRM(minimalValid);
      expect(parsed.resource).toBe("https://api.example.com/mcp");
      expect(parsed.authorization_servers).toEqual(["https://idp.example.com"]);
      expect(parsed.bearer_methods_supported).toEqual(["header"]);
    });

    it("accepts a full document with all optional fields", () => {
      const parsed = parsePRM({
        ...minimalValid,
        scopes_supported: ["read", "write"],
        bearer_methods_supported: ["header", "body"],
        resource_documentation: "https://docs.example.com",
      });
      expect(parsed.scopes_supported).toEqual(["read", "write"]);
      expect(parsed.bearer_methods_supported).toEqual(["header", "body"]);
      expect(parsed.resource_documentation).toBe("https://docs.example.com");
    });
  });

  describe("required-field omissions", () => {
    it("rejects missing resource", () => {
      const { resource: _ignored, ...rest } = minimalValid;
      expect(() => parsePRM(rest)).toThrow(z.ZodError);
    });

    it("rejects missing authorization_servers", () => {
      const { authorization_servers: _ignored, ...rest } = minimalValid;
      expect(() => parsePRM(rest)).toThrow(z.ZodError);
    });

    it("rejects empty authorization_servers array", () => {
      expect(() => parsePRM({ ...minimalValid, authorization_servers: [] })).toThrow(z.ZodError);
    });
  });
});
