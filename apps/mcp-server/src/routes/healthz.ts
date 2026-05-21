// GET /healthz — liveness probe used by tests and the smoke script. No deps;
// a 500 here means the Hono app itself is wedged.

import { Hono } from "hono";

export function healthzRoute(): Hono {
  const app = new Hono();
  app.get("/healthz", (c) => c.json({ status: "ok" }));
  return app;
}
