import { describe, expect, it } from "vitest";
import { InvalidCanonicalURIError } from "../errors.js";
import { canonicalize, equalsCanonical } from "./canonical-uri.js";

describe("canonicalize [INV-4.11]", () => {
  // Each row covers a rule from architecture §4.11. The MCP-spec "Canonical
  // Server URI" examples are baked in: lowercasing host, dropping default
  // port, dropping fragment, collapsing `/` path, stripping trailing slash.
  it.each<[string, string, string]>([
    ["passthrough", "https://example.com/api", "https://example.com/api"],
    ["lowercases host", "https://EXAMPLE.com/api", "https://example.com/api"],
    ["lowercases mixed-case host", "https://ExAmple.COM/Path", "https://example.com/Path"],
    ["lowercases scheme", "HTTPS://example.com/api", "https://example.com/api"],
    ["strips default https port", "https://example.com:443/api", "https://example.com/api"],
    ["strips default http port", "http://example.com:80/api", "http://example.com/api"],
    ["keeps non-default port", "https://example.com:8443/api", "https://example.com:8443/api"],
    [
      "keeps http port 443 (non-default for http)",
      "http://example.com:443/api",
      "http://example.com:443/api",
    ],
    ["drops fragment", "https://example.com/api#section", "https://example.com/api"],
    ["drops fragment with empty path", "https://example.com#x", "https://example.com"],
    ["collapses `/` path to empty", "https://example.com/", "https://example.com"],
    ["empty path stays empty", "https://example.com", "https://example.com"],
    [
      "strips single trailing slash on non-root path",
      "https://example.com/api/",
      "https://example.com/api",
    ],
    ["preserves multi-segment path", "https://example.com/a/b/c", "https://example.com/a/b/c"],
    [
      "preserves query string",
      "https://example.com/api?x=1&y=2",
      "https://example.com/api?x=1&y=2",
    ],
    [
      "normalizes percent-encoding to uppercase hex",
      "https://example.com/%7euser",
      "https://example.com/~user",
    ],
    [
      "decodes percent-encoded unreserved characters",
      "https://example.com/%41%42%43",
      "https://example.com/ABC",
    ],
    [
      "uppercases hex of reserved percent triplets",
      "https://example.com/a%2fb",
      "https://example.com/a%2Fb",
    ],
    [
      "loopback IPv4 with non-default port",
      "http://127.0.0.1:8080/cimd",
      "http://127.0.0.1:8080/cimd",
    ],
  ])("%s", (_label, input, expected) => {
    expect(canonicalize(input)).toBe(expected);
  });

  it("rejects a non-absolute URL", () => {
    expect(() => canonicalize("/relative/path")).toThrow(InvalidCanonicalURIError);
  });

  it("rejects an empty string", () => {
    expect(() => canonicalize("")).toThrow(InvalidCanonicalURIError);
  });

  it("rejects a bare scheme without authority", () => {
    expect(() => canonicalize("https:")).toThrow(InvalidCanonicalURIError);
  });

  it("rejects garbage input", () => {
    expect(() => canonicalize("not a url")).toThrow(InvalidCanonicalURIError);
  });

  it("rejects malformed percent-encoding", () => {
    expect(() => canonicalize("https://example.com/%ZZ")).toThrow(InvalidCanonicalURIError);
  });

  it("rejects a non-string input", () => {
    // The API is `(url: string) => CanonicalURI`; calling with a non-string
    // must still throw a typed error rather than crashing the runtime.
    expect(() => canonicalize(123 as unknown as string)).toThrow(InvalidCanonicalURIError);
  });
});

describe("equalsCanonical [INV-4.11]", () => {
  it("returns true for byte-equal canonical forms", () => {
    expect(equalsCanonical("https://example.com/api", "https://example.com/api")).toBe(true);
  });

  it("returns true for inputs that canonicalize to the same value", () => {
    expect(equalsCanonical("https://EXAMPLE.com/api/", "https://example.com:443/api")).toBe(true);
  });

  it("returns false for different canonical forms", () => {
    expect(equalsCanonical("https://example.com/a", "https://example.com/b")).toBe(false);
  });

  it("returns false for unequal-length canonical forms (no timingSafeEqual crash)", () => {
    // `timingSafeEqual` throws on differing buffer lengths; the helper must
    // short-circuit to `false` so callers never see a thrown length error.
    expect(equalsCanonical("https://example.com/a", "https://example.com/aaaa")).toBe(false);
  });

  it("propagates InvalidCanonicalURIError on bad input", () => {
    expect(() => equalsCanonical("https://example.com/a", "/relative")).toThrow(
      InvalidCanonicalURIError,
    );
  });
});
