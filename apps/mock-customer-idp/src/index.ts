#!/usr/bin/env node
// Mock Authorization Server runtime entry. The app factory is `app.ts` —
// this file owns process-level concerns only (env load, DB open, key
// bootstrap, HTTP listen, graceful shutdown).
//
// Spec: specs/authorization-server.md (whole document); §2 (env), §6
// (keys), §7 (storage), §8 (logging) cover the boot path in particular.

import { serve } from "@hono/node-server";
import { createIdPApp } from "./app.js";
import { applySchema, openDatabase } from "./db.js";
import type { IdPEnv } from "./env.js";
import { parseEnv } from "./env.js";
import { loadOrGenerateKey } from "./keys.js";
import type { Logger } from "./log.js";
import { createLogger } from "./log.js";

async function boot(): Promise<void> {
  // 1. Env validation. Construct the bootstrap logger before parsing so we
  //    can emit a structured error and exit cleanly.
  const bootLog = createLogger();
  let env: IdPEnv;
  try {
    env = parseEnv(process.env);
  } catch (err) {
    bootLog.error({ err }, "invalid configuration");
    process.exit(1);
  }

  // 2. DB + schema.
  const db = openDatabase(env.AS_DB_PATH);
  applySchema(db);

  // 3. Signing key.
  const keys = await loadOrGenerateKey(db, env.AS_SIGNING_ALG);

  // 4. App.
  const log: Logger = bootLog;
  const app = createIdPApp({ env, db, log, keys });

  // 5. Listen.
  const server = serve({ fetch: app.fetch, port: env.AS_PORT }, () => {
    log.info(`idp listening on ${env.AS_ISSUER_URL}`);
  });

  // 6. Graceful shutdown — close the HTTP server first (stops accepting
  //    new connections), then the DB. Either signal triggers the same path.
  const shutdown = (signal: NodeJS.Signals): void => {
    log.info({ signal }, "shutdown requested");
    server.close((err) => {
      if (err !== undefined && err !== null) {
        log.error({ err }, "error closing http server");
      }
      try {
        db.close();
      } catch (closeErr) {
        log.error({ err: closeErr }, "error closing database");
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

// Re-export the public surface so other slices (or smoke scripts) can
// import builders from the entry module if needed.
export { createIdPApp } from "./app.js";
export type { DB } from "./db.js";
export { applySchema, openDatabase } from "./db.js";
export type { IdPEnv } from "./env.js";
export { parseEnv } from "./env.js";
export type { SigningKeyset } from "./keys.js";
export { loadOrGenerateKey } from "./keys.js";
export type { Logger } from "./log.js";
export { createLogger } from "./log.js";

// Only run the boot sequence when invoked as a script — re-importing the
// module (e.g. from tests) MUST NOT spawn an HTTP listener.
const isMain = import.meta.url === `file://${process.argv[1] ?? ""}`;
if (isMain) {
  boot().catch((err: unknown) => {
    // Boot failures past env validation: log + exit. No partial startup.
    const log = createLogger();
    log.error({ err }, "fatal boot error");
    process.exit(1);
  });
}
