import { describe, expect, it } from "vitest";
import {
  buildInsufficientScopeHeader,
  buildUnauthorizedHeader,
  parseWWWAuthenticate,
} from "./www-authenticate.js";

describe("buildUnauthorizedHeader", () => {
  it("emits Bearer with realm, resource_metadata, and scope in that order", () => {
    const header = buildUnauthorizedHeader({
      realm: "https://mcp.example.com",
      resourceMetadata: "https://mcp.example.com/.well-known/oauth-protected-resource",
      scope: "mcp:read",
    });
    expect(header).toBe(
      'Bearer realm="https://mcp.example.com", ' +
        'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", ' +
        'scope="mcp:read"',
    );
  });

  it("escapes embedded quotes and backslashes per RFC 7235", () => {
    const header = buildUnauthorizedHeader({
      realm: 'a"b\\c',
      resourceMetadata: "https://r/",
      scope: "x",
    });
    // backslash escaped first, then quote.
    expect(header).toContain('realm="a\\"b\\\\c"');
  });
});

describe("buildInsufficientScopeHeader", () => {
  it("includes error=insufficient_scope and required params", () => {
    const header = buildInsufficientScopeHeader({
      realm: "https://mcp.example.com",
      scope: "mcp:write",
      resourceMetadata: "https://mcp.example.com/.well-known/oauth-protected-resource",
    });
    expect(header).toBe(
      'Bearer realm="https://mcp.example.com", ' +
        'error="insufficient_scope", ' +
        'scope="mcp:write", ' +
        'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"',
    );
  });

  it("appends error_description when provided", () => {
    const header = buildInsufficientScopeHeader({
      realm: "r",
      scope: "s",
      resourceMetadata: "rm",
      errorDescription: "Need higher scope",
    });
    expect(header).toContain('error_description="Need higher scope"');
  });

  it("omits error_description when undefined", () => {
    const header = buildInsufficientScopeHeader({
      realm: "r",
      scope: "s",
      resourceMetadata: "rm",
    });
    expect(header).not.toContain("error_description");
  });
});

describe("parseWWWAuthenticate", () => {
  it("extracts scheme and quoted params", () => {
    const parsed = parseWWWAuthenticate(
      'Bearer realm="https://mcp", resource_metadata="https://rm", scope="x"',
    );
    expect(parsed.scheme).toBe("Bearer");
    expect(parsed.params).toEqual({
      realm: "https://mcp",
      resource_metadata: "https://rm",
      scope: "x",
    });
  });

  it("unescapes backslash-escaped quotes and backslashes", () => {
    const parsed = parseWWWAuthenticate('Bearer realm="a\\"b\\\\c"');
    expect(parsed.params.realm).toBe('a"b\\c');
  });

  it("accepts token (unquoted) values", () => {
    const parsed = parseWWWAuthenticate("Bearer error=insufficient_scope, scope=mcp:read");
    expect(parsed.params).toEqual({ error: "insufficient_scope", scope: "mcp:read" });
  });

  it("tolerates extra whitespace around `=` and `,`", () => {
    const parsed = parseWWWAuthenticate('Bearer  realm = "r"  ,   scope  =  "s"');
    expect(parsed.params).toEqual({ realm: "r", scope: "s" });
  });

  it("throws on empty input", () => {
    expect(() => parseWWWAuthenticate("")).toThrow();
  });

  it("throws on unterminated quoted-string", () => {
    expect(() => parseWWWAuthenticate('Bearer realm="oops')).toThrow();
  });

  it("throws on missing `=`", () => {
    expect(() => parseWWWAuthenticate('Bearer realm "r"')).toThrow();
  });
});

describe("WWW-Authenticate round-trip", () => {
  it("buildUnauthorizedHeader → parse yields the original opts", () => {
    const opts = {
      realm: "https://mcp.example.com",
      resourceMetadata: "https://mcp.example.com/.well-known/oauth-protected-resource",
      scope: "mcp:read mcp:write",
    };
    const header = buildUnauthorizedHeader(opts);
    const parsed = parseWWWAuthenticate(header);
    expect(parsed.scheme).toBe("Bearer");
    expect(parsed.params).toEqual({
      realm: opts.realm,
      resource_metadata: opts.resourceMetadata,
      scope: opts.scope,
    });
  });

  it("buildInsufficientScopeHeader → parse round-trips including error_description", () => {
    const opts = {
      realm: "https://mcp",
      scope: "mcp:write",
      resourceMetadata: "https://rm",
      errorDescription: 'a "quoted" value with \\ slash',
    };
    const header = buildInsufficientScopeHeader(opts);
    const parsed = parseWWWAuthenticate(header);
    expect(parsed.params.realm).toBe(opts.realm);
    expect(parsed.params.scope).toBe(opts.scope);
    expect(parsed.params.resource_metadata).toBe(opts.resourceMetadata);
    expect(parsed.params.error).toBe("insufficient_scope");
    expect(parsed.params.error_description).toBe(opts.errorDescription);
  });

  it("round-trips values containing both quote and backslash", () => {
    const opts = {
      realm: 'realm with " and \\ inside',
      resourceMetadata: "https://rm",
      scope: "x",
    };
    const header = buildUnauthorizedHeader(opts);
    const parsed = parseWWWAuthenticate(header);
    expect(parsed.params.realm).toBe(opts.realm);
  });
});
