// Hono app factory. Exported separately from `index.ts` so integration tests
// can construct an app and drive it via `app.request()` without binding a
// real port. `index.ts` is the only place that calls `serve` from
// `@hono/node-server`.
//
// Future slices will mount /authorize, /token, /jwks.json, and metadata
// routes here, each behind a `Hono` sub-app pulled in from `src/routes/`.

import { Hono } from "hono";
import type { DB } from "./db.js";
import type { IdPEnv } from "./env.js";
import type { SigningKeyset } from "./keys.js";
import type { Logger } from "./log.js";
import { healthzRoute } from "./routes/healthz.js";

export interface IdPDeps {
  env: IdPEnv;
  db: DB;
  log: Logger;
  keys: SigningKeyset;
}

/**
 * Hono `Variables` shape — deps that downstream routes can pull off `c.var`.
 * Exporting the type lets later slices (token, authorize, jwks) consume the
 * same typed handles without re-declaring them.
 */
export interface IdPVariables {
  env: IdPEnv;
  db: DB;
  log: Logger;
  keys: SigningKeyset;
}

export type IdPApp = Hono<{ Variables: IdPVariables }>;

export function createIdPApp(deps: IdPDeps): IdPApp {
  // Bind deps to a closure so future routes can pull them off `c.var`
  // without re-importing the module that owns them.
  const app = new Hono<{ Variables: IdPVariables }>();

  app.use("*", async (c, next) => {
    c.set("env", deps.env);
    c.set("db", deps.db);
    c.set("log", deps.log);
    c.set("keys", deps.keys);
    await next();
  });

  app.route("/", healthzRoute());

  return app;
}
