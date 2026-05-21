import { describe, expect, it } from "vitest";
import { z } from "zod";
import { InvalidCIMDError } from "../errors.js";
import { validateFetchedCIMD } from "./cimd-validator.js";

const baseDoc = {
  client_id: "https://example.com/cimd",
  client_name: "Example Client",
  redirect_uris: ["https://example.com/callback"],
};

describe("validateFetchedCIMD", () => {
  it("accepts matching fetch URL and client_id (exact form)", () => {
    const result = validateFetchedCIMD("https://example.com/cimd", baseDoc, {
      allowInsecure: false,
    });
    expect(result.client_id).toBe("https://example.com/cimd");
    expect(result.client_name).toBe("Example Client");
    expect(result.redirect_uris).toEqual(["https://example.com/callback"]);
  });

  it("[INV-4.9] accepts URL with semantic alias (uppercase host) — canonicalize lowercases", () => {
    const result = validateFetchedCIMD("https://EXAMPLE.com/cimd", baseDoc, {
      allowInsecure: false,
    });
    expect(result.client_id).toBe("https://example.com/cimd");
  });

  it("[INV-4.9] accepts client_id with semantic alias (uppercase host)", () => {
    const result = validateFetchedCIMD(
      "https://example.com/cimd",
      { ...baseDoc, client_id: "https://EXAMPLE.com/cimd" },
      { allowInsecure: false },
    );
    expect(result.client_id).toBe("https://example.com/cimd");
  });

  it("[INV-4.9] accepts URL with trailing-slash difference (canonicalize strips)", () => {
    const result = validateFetchedCIMD("https://example.com/cimd/", baseDoc, {
      allowInsecure: false,
    });
    expect(result.client_id).toBe("https://example.com/cimd");
  });

  it("[INV-4.9] accepts URL with default-port difference (:443 stripped)", () => {
    const result = validateFetchedCIMD("https://example.com:443/cimd", baseDoc, {
      allowInsecure: false,
    });
    expect(result.client_id).toBe("https://example.com/cimd");
  });

  it("[INV-4.9] rejects when fetch URL path differs from client_id path", () => {
    expect(() =>
      validateFetchedCIMD(
        "https://example.com/cimd",
        { ...baseDoc, client_id: "https://example.com/other" },
        { allowInsecure: false },
      ),
    ).toThrow(InvalidCIMDError);
  });

  it("[INV-4.9] rejects when fetch URL host differs from client_id host", () => {
    expect(() =>
      validateFetchedCIMD("https://attacker.example.com/cimd", baseDoc, { allowInsecure: false }),
    ).toThrow(InvalidCIMDError);
  });

  it("[INV-4.9] rejects when scheme differs (http vs https) under allowInsecure", () => {
    // With allowInsecure=true, http://127.0.0.1[:port] is permitted as a
    // client_id scheme. But the fetch URL must still match canonically — a
    // mismatch in scheme alone fails the byte-equal check.
    expect(() =>
      validateFetchedCIMD(
        "http://127.0.0.1:7777/cimd",
        { ...baseDoc, client_id: "https://example.com/cimd" },
        { allowInsecure: true },
      ),
    ).toThrow(InvalidCIMDError);
  });

  // ---- schema-level rejections that bubble through ----

  it("rejects bare-domain client_id (schema enforces non-empty path)", () => {
    expect(() =>
      validateFetchedCIMD(
        "https://example.com",
        { ...baseDoc, client_id: "https://example.com" },
        { allowInsecure: false },
      ),
    ).toThrow(z.ZodError);
  });

  it("rejects bare-domain client_id with path=/", () => {
    expect(() =>
      validateFetchedCIMD(
        "https://example.com/",
        { ...baseDoc, client_id: "https://example.com/" },
        { allowInsecure: false },
      ),
    ).toThrow(z.ZodError);
  });

  it("rejects http://localhost redirect URI (schema)", () => {
    expect(() =>
      validateFetchedCIMD(
        "https://example.com/cimd",
        { ...baseDoc, redirect_uris: ["http://localhost:7777/cb"] },
        { allowInsecure: false },
      ),
    ).toThrow(z.ZodError);
  });

  it("accepts http://127.0.0.1[:port] redirect URI", () => {
    const result = validateFetchedCIMD(
      "https://example.com/cimd",
      { ...baseDoc, redirect_uris: ["http://127.0.0.1:7777/cb"] },
      { allowInsecure: false },
    );
    expect(result.redirect_uris).toEqual(["http://127.0.0.1:7777/cb"]);
  });

  it("rejects an unparseable fetch URL", () => {
    expect(() => validateFetchedCIMD("not-a-url", baseDoc, { allowInsecure: false })).toThrow(
      InvalidCIMDError,
    );
  });

  it("under allowInsecure=true, accepts http://127.0.0.1[:port] client_id when paths match", () => {
    const result = validateFetchedCIMD(
      "http://127.0.0.1:7777/cimd",
      {
        ...baseDoc,
        client_id: "http://127.0.0.1:7777/cimd",
        redirect_uris: ["http://127.0.0.1:7777/cb"],
      },
      { allowInsecure: true },
    );
    expect(result.client_id).toBe("http://127.0.0.1:7777/cimd");
  });
});
