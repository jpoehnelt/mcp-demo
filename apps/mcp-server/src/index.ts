#!/usr/bin/env node
// MCP Resource Server runtime entry. The app factory is `app.ts` — this
// file owns process-level concerns only (env load, discovery + verifier
// construction live in the factory, HTTP listen, graceful shutdown).
//
// Spec: specs/resource-server.md (whole document); §2 (env), §3 (PRM),
// §4 (token validation), §4.12 (no-secret-logging) cover the boot path.

import { pathToFileURL } from "node:url";
import { serve } from "@hono/node-server";
import { createMCPServerApp } from "./app.js";
import type { MCPServerEnv } from "./env.js";
import { parseEnv } from "./env.js";
import type { Logger } from "./log.js";
import { createLogger } from "./log.js";

async function boot(): Promise<void> {
  // 1. Env validation. Build the bootstrap logger first so we can emit a
  //    structured error and exit non-zero on invalid config.
  const bootLog = createLogger();
  let env: MCPServerEnv;
  try {
    env = parseEnv(process.env);
  } catch (err) {
    bootLog.error({ err }, "invalid configuration");
    process.exit(1);
  }

  // 2. App factory. Performs RFC 8414 discovery + verifier construction
  //    internally; throws on discovery failure so we never start serving
  //    /mcp without a working JWKS reference.
  const log: Logger = bootLog;
  let app: Awaited<ReturnType<typeof createMCPServerApp>>;
  try {
    app = await createMCPServerApp({ env, log });
  } catch (err) {
    log.error({ err }, "MCP server bootstrap failed");
    process.exit(1);
  }

  // 3. Listen.
  const server = serve({ fetch: app.fetch, port: env.MCP_PORT }, () => {
    log.info(
      { audience: env.MCP_AUDIENCE, issuer: env.MCP_OIDC_ISSUER_URL, port: env.MCP_PORT },
      "mcp server listening",
    );
  });

  // 4. Graceful shutdown — close the HTTP server (stops accepting new
  //    connections); either signal triggers the same path.
  const shutdown = (signal: NodeJS.Signals): void => {
    log.info({ signal }, "shutdown requested");
    server.close((err) => {
      if (err !== undefined && err !== null) {
        log.error({ err }, "error closing http server");
      }
      log.info("shutdown complete");
      process.exit(0);
    });
  };
  process.on("SIGINT", () => {
    shutdown("SIGINT");
  });
  process.on("SIGTERM", () => {
    shutdown("SIGTERM");
  });
}

// Re-export the public surface so smoke scripts can import builders from
// the entry module if needed.
export { createMCPServerApp } from "./app.js";
export type { MCPServerEnv } from "./env.js";
export { parseEnv } from "./env.js";
export type { Logger } from "./log.js";
export { createLogger } from "./log.js";

// Only run the boot sequence when invoked as a script — re-importing the
// module (e.g. from tests) MUST NOT spawn an HTTP listener. pathToFileURL
// handles Windows backslashes + special-char encoding correctly.
const isMain = import.meta.url === pathToFileURL(process.argv[1] ?? "").href;
if (isMain) {
  boot().catch((err: unknown) => {
    // Boot failures past env validation: log + exit. No partial startup.
    const log = createLogger();
    log.error({ err }, "fatal boot error");
    process.exit(1);
  });
}
