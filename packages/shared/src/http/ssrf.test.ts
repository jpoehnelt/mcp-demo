import type * as dns from "node:dns";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { InvalidContentTypeError, MaxBytesExceededError, SSRFBlockedError } from "../errors.js";
import { __setLookupForTests, isDeniedAddress, safeFetch } from "./ssrf.js";

// ---------------------------------------------------------------------------
// isDeniedAddress — pure function. One positive test per range from the table.
// ---------------------------------------------------------------------------

describe("isDeniedAddress (allowLoopback=false)", () => {
  const denied: Array<[string, string]> = [
    ["IPv4 private 10/8", "10.0.0.1"],
    ["IPv4 private 172.16/12", "172.16.0.1"],
    ["IPv4 private 172.31/12 (upper bound)", "172.31.255.254"],
    ["IPv4 private 192.168/16", "192.168.1.1"],
    ["IPv4 loopback 127/8", "127.0.0.1"],
    ["IPv4 link-local 169.254/16", "169.254.169.254"],
    ["IPv4 CGNAT 100.64/10", "100.64.0.1"],
    ["IPv4 multicast 224/4", "224.0.0.1"],
    ["IPv4 broadcast 255.255.255.255", "255.255.255.255"],
    ["IPv4 unspecified 0/8", "0.0.0.0"],
    ["IPv6 loopback ::1", "::1"],
    ["IPv6 link-local fe80::", "fe80::1"],
    ["IPv6 ULA fc00::", "fc00::1"],
    ["IPv6 ULA fd00::", "fd00::1"],
    ["IPv6 multicast ff00::", "ff02::1"],
    ["IPv4-mapped IPv6 (loopback)", "::ffff:127.0.0.1"],
    ["IPv4-mapped IPv6 (private)", "::ffff:10.0.0.1"],
  ];
  it.each(denied)("denies %s (%s)", (_label, ip) => {
    expect(isDeniedAddress(ip, { allowLoopback: false })).toBe(true);
  });

  const allowed: Array<[string, string]> = [
    ["IPv4 public", "8.8.8.8"],
    ["IPv4 just above 100.64/10 (100.128.0.0)", "100.128.0.0"],
    ["IPv4 just above 172.16/12 (172.32.0.0)", "172.32.0.0"],
    ["IPv6 public 2001:db8::", "2001:db8::1"],
    ["IPv4-mapped public IP", "::ffff:8.8.8.8"],
  ];
  it.each(allowed)("permits %s (%s)", (_label, ip) => {
    expect(isDeniedAddress(ip, { allowLoopback: false })).toBe(false);
  });
});

describe("isDeniedAddress (allowLoopback=true)", () => {
  it("permits IPv4 127.0.0.1", () => {
    expect(isDeniedAddress("127.0.0.1", { allowLoopback: true })).toBe(false);
  });
  it("permits IPv4 127.255.255.254", () => {
    expect(isDeniedAddress("127.255.255.254", { allowLoopback: true })).toBe(false);
  });
  it("still denies IPv4 10.0.0.1", () => {
    expect(isDeniedAddress("10.0.0.1", { allowLoopback: true })).toBe(true);
  });
  it("permits IPv6 ::1 (loopback exemption covers both families)", () => {
    expect(isDeniedAddress("::1", { allowLoopback: true })).toBe(false);
  });
  it("still denies IPv4 169.254.169.254", () => {
    expect(isDeniedAddress("169.254.169.254", { allowLoopback: true })).toBe(true);
  });
  it("permits IPv4-mapped 127.0.0.1 over IPv6", () => {
    expect(isDeniedAddress("::ffff:127.0.0.1", { allowLoopback: true })).toBe(false);
  });
});

describe("isDeniedAddress (malformed input)", () => {
  it("throws on empty string", () => {
    expect(() => isDeniedAddress("", { allowLoopback: false })).toThrow(SSRFBlockedError);
  });
  it("throws on garbage", () => {
    expect(() => isDeniedAddress("not-an-ip", { allowLoopback: false })).toThrow(SSRFBlockedError);
  });
});

// ---------------------------------------------------------------------------
// safeFetch — integration via local 127.0.0.1 listener.
// ---------------------------------------------------------------------------

interface TestServerHandle {
  url: string;
  port: number;
  close: () => Promise<void>;
}

async function startTestServer(handler: http.RequestListener): Promise<TestServerHandle> {
  const server = http.createServer(handler);
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${String(addr.port)}`,
    port: addr.port,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => {
          if (err !== undefined && err !== null) reject(err);
          else resolve();
        });
      }),
  };
}

/**
 * Build a `dns.lookup`-shaped mock. Calls the callback with whatever the
 * supplier returns for the given (hostname, options) tuple. Handles both
 * `lookup(host, cb)` and `lookup(host, opts, cb)` forms.
 */
type LookupResult =
  | { kind: "all"; addresses: Array<{ address: string; family: number }> }
  | { kind: "one"; address: string; family: number }
  | { kind: "err"; err: NodeJS.ErrnoException };

function makeLookupMock(
  supply: (hostname: string, all: boolean) => LookupResult,
  countRef?: { calls: number },
): typeof dns.lookup {
  // We cast through `unknown` because `dns.lookup` is a heavily-overloaded
  // function and writing every overload by hand is noisy.
  return ((hostname: string, optionsOrCb: unknown, maybeCb?: unknown): void => {
    if (countRef !== undefined) countRef.calls += 1;
    const cb =
      typeof optionsOrCb === "function"
        ? (optionsOrCb as (...args: unknown[]) => void)
        : (maybeCb as (...args: unknown[]) => void);
    const all =
      typeof optionsOrCb === "object" && optionsOrCb !== null
        ? (optionsOrCb as { all?: boolean }).all === true
        : false;
    const result = supply(hostname, all);
    if (result.kind === "err") {
      cb(result.err);
      return;
    }
    if (result.kind === "all") {
      cb(null, result.addresses);
      return;
    }
    cb(null, result.address, result.family);
  }) as unknown as typeof dns.lookup;
}

describe("safeFetch", () => {
  let server: TestServerHandle | null = null;
  let restoreLookup: typeof dns.lookup | null = null;

  afterEach(async () => {
    if (server !== null) {
      await server.close();
      server = null;
    }
    if (restoreLookup !== null) {
      __setLookupForTests(restoreLookup);
      restoreLookup = null;
    }
  });

  it("fetches a JSON body successfully", async () => {
    server = await startTestServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true}');
    });
    const result = await safeFetch(server.url, {
      allowInsecure: true,
      maxBytes: 1024,
      timeoutMs: 2000,
      expectContentType: "application/json",
    });
    expect(result.status).toBe(200);
    expect(result.body).toBe('{"ok":true}');
    expect(result.headers.get("content-type")).toBe("application/json");
  });

  it("rejects http:// when allowInsecure=false", async () => {
    server = await startTestServer((_req, res) => {
      res.end("never reached");
    });
    await expect(
      safeFetch(server.url, {
        allowInsecure: false,
        maxBytes: 1024,
        timeoutMs: 2000,
        expectContentType: "application/json",
      }),
    ).rejects.toBeInstanceOf(SSRFBlockedError);
  });

  it("rejects when DNS resolves to a denylisted IP (allowInsecure=false)", async () => {
    restoreLookup = __setLookupForTests(
      makeLookupMock(() => ({
        kind: "all",
        addresses: [{ address: "10.0.0.1", family: 4 }],
      })),
    );
    await expect(
      safeFetch("https://attacker.example.com/foo", {
        allowInsecure: false,
        maxBytes: 1024,
        timeoutMs: 2000,
        expectContentType: "application/json",
      }),
    ).rejects.toBeInstanceOf(SSRFBlockedError);
  });

  it("rejects if ANY resolved address is denied (mixed A records)", async () => {
    restoreLookup = __setLookupForTests(
      makeLookupMock(() => ({
        kind: "all",
        addresses: [
          { address: "8.8.8.8", family: 4 },
          { address: "127.0.0.1", family: 4 },
        ],
      })),
    );
    await expect(
      safeFetch("https://mixed.example.com/foo", {
        allowInsecure: false,
        maxBytes: 1024,
        timeoutMs: 2000,
        expectContentType: "application/json",
      }),
    ).rejects.toBeInstanceOf(SSRFBlockedError);
  });

  it("rejects a 302 redirect (maxRedirects=0)", async () => {
    server = await startTestServer((_req, res) => {
      res.writeHead(302, { Location: "http://example.com/" });
      res.end();
    });
    await expect(
      safeFetch(server.url, {
        allowInsecure: true,
        maxBytes: 1024,
        timeoutMs: 2000,
        expectContentType: "application/json",
      }),
    ).rejects.toBeInstanceOf(SSRFBlockedError);
  });

  it("throws MaxBytesExceededError when body exceeds cap", async () => {
    server = await startTestServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      // 20KB > 1KB cap. Use a single write so the data event fires once.
      res.end("a".repeat(20000));
    });
    await expect(
      safeFetch(server.url, {
        allowInsecure: true,
        maxBytes: 1024,
        timeoutMs: 5000,
        expectContentType: "application/json",
      }),
    ).rejects.toBeInstanceOf(MaxBytesExceededError);
  });

  it("throws InvalidContentTypeError on mismatched Content-Type", async () => {
    server = await startTestServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<html></html>");
    });
    await expect(
      safeFetch(server.url, {
        allowInsecure: true,
        maxBytes: 1024,
        timeoutMs: 2000,
        expectContentType: "application/json",
      }),
    ).rejects.toBeInstanceOf(InvalidContentTypeError);
  });

  it("accepts Content-Type with charset parameter", async () => {
    server = await startTestServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
      res.end('{"ok":true}');
    });
    const result = await safeFetch(server.url, {
      allowInsecure: true,
      maxBytes: 1024,
      timeoutMs: 2000,
      expectContentType: "application/json",
    });
    expect(result.status).toBe(200);
  });

  it("rejects unsupported scheme", async () => {
    await expect(
      safeFetch("ftp://example.com/foo", {
        allowInsecure: false,
        maxBytes: 1024,
        timeoutMs: 2000,
        expectContentType: "application/json",
      }),
    ).rejects.toBeInstanceOf(SSRFBlockedError);
  });
});

// ---------------------------------------------------------------------------
// DNS rebinding — [INV-4.9].
// ---------------------------------------------------------------------------

describe("[INV-4.9] safeFetch DNS-rebinding defense", () => {
  let server: TestServerHandle | null = null;
  let restoreLookup: typeof dns.lookup | null = null;

  beforeEach(() => {
    // no-op; per-test setup wires the lookup mock.
  });

  afterEach(async () => {
    if (server !== null) {
      await server.close();
      server = null;
    }
    if (restoreLookup !== null) {
      __setLookupForTests(restoreLookup);
      restoreLookup = null;
    }
  });

  it("pins to the resolved IP — http.request uses the pin, not a fresh DNS query", async () => {
    server = await startTestServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"pinned":true}');
    });
    const localPort = server.port;

    // Simulate the rebinding race. The first (all:true) lookup returns
    // loopback — the deny check passes under allowInsecure=true and that
    // address is what gets pinned. If anything OTHER than the pin queries
    // DNS mid-flight, the kind:"one" branch fires and we'd see the call
    // count jump above 1. The pinned `lookup` option means the http stack
    // never makes a fresh DNS query.
    const counter = { calls: 0 };
    restoreLookup = __setLookupForTests(
      makeLookupMock((_host, all) => {
        if (all) {
          return { kind: "all", addresses: [{ address: "127.0.0.1", family: 4 }] };
        }
        // Would-be rebinding answer — if the pin is broken, http.request
        // would reach here and try to connect to 10.0.0.1.
        return { kind: "one", address: "10.0.0.1", family: 4 };
      }, counter),
    );

    const result = await safeFetch(`http://rebinding.example.com:${String(localPort)}/foo`, {
      allowInsecure: true,
      maxBytes: 1024,
      timeoutMs: 2000,
      expectContentType: "application/json",
    });
    expect(result.body).toBe('{"pinned":true}');
    // Exactly one dns.lookup call (the initial all:true resolveAll). The
    // pinned `lookup` option intercepted the http stack's connect-time DNS,
    // so the rebinding answer was never consulted.
    expect(counter.calls).toBe(1);
  });

  it("captures lookup result up-front — second dns.lookup result is never used", async () => {
    server = await startTestServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"served":true}');
    });
    const localPort = server.port;

    const counter = { calls: 0 };
    restoreLookup = __setLookupForTests(
      makeLookupMock((_host, all) => {
        if (all) {
          // First answer: allowed loopback (under allowInsecure=true).
          return { kind: "all", addresses: [{ address: "127.0.0.1", family: 4 }] };
        }
        // Subsequent answers (would-be rebinding) — never used.
        return { kind: "one", address: "10.0.0.1", family: 4 };
      }, counter),
    );

    const result = await safeFetch(`http://race.example.com:${String(localPort)}/foo`, {
      allowInsecure: true,
      maxBytes: 1024,
      timeoutMs: 2000,
      expectContentType: "application/json",
    });
    expect(result.body).toBe('{"served":true}');
    expect(counter.calls).toBe(1);
  });
});
