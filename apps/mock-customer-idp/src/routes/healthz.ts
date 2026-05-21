// GET /healthz — liveness probe used by tests and the future smoke script.
// Intentionally has no dependencies: a 500 here would mean the Hono app
// itself is wedged.

import { Hono } from "hono";

export function healthzRoute(): Hono {
  const app = new Hono();
  app.get("/healthz", (c) => c.json({ status: "ok" }));
  return app;
}
