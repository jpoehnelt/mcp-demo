// MCP tool registrations. See specs/resource-server.md §6.
//
// Each tool is registered against a per-request `McpServer` instance so that
// the verified `TokenClaims` (set on the Hono context by the slice 10 auth
// middleware) can be captured in a fresh closure for every `POST /mcp`. This
// sidesteps the SDK's `AuthInfo` shape (which only carries `scopes: string[]`)
// and lets us hand `requireScope` the same `TokenClaims` shape used elsewhere.
//
// Token-forwarding prohibition (§4.3): outputs are computed locally —
// no outbound HTTP, no propagating the caller's bearer token to anything.

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { TokenClaims } from "@poc/shared";
import { z } from "zod";
import { requireScope } from "../middleware/require-scope.js";

// Hardcoded fixture — `list_cities` returns this verbatim. Three cities is
// enough to exercise the "list" tool shape without bloating snapshots.
const CITIES = ["Denver", "Seattle", "Austin"] as const;

// ---------------------------------------------------------------------------
// Mock outputs
// ---------------------------------------------------------------------------

function mockWeather(city: string): { city: string; tempF: number; conditions: string } {
  // Deterministic mock — tests don't need real weather data, just a shape
  // that round-trips through the MCP envelope.
  return { city, tempF: 72, conditions: "sunny" };
}

function mockPremiumForecast(city: string): {
  city: string;
  forecast: { day: number; tempF: number; conditions: string }[];
} {
  const forecast: { day: number; tempF: number; conditions: string }[] = [];
  for (let day = 1; day <= 14; day += 1) {
    forecast.push({ day, tempF: 70 + (day % 10), conditions: day % 2 === 0 ? "cloudy" : "sunny" });
  }
  return { city, forecast };
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/**
 * Register the three demo tools (`list_cities`, `get_weather`,
 * `get_premium_forecast`) on a freshly-constructed per-request `McpServer`.
 *
 * `claims` is captured by closure so each tool handler reads the exact
 * claims set verified for this HTTP request — not a value that could race
 * with another in-flight request.
 */
export function registerTools(server: McpServer, claims: TokenClaims): void {
  // list_cities — no required scope. Authentication alone (slice 10
  // middleware) is the gate; the spec §6 forbids calling `requireScope`
  // here because there's no concrete scope to check.
  server.registerTool(
    "list_cities",
    {
      description: "Return the list of cities for which weather data is available.",
      inputSchema: {},
    },
    () => ({
      content: [{ type: "text", text: JSON.stringify(CITIES) }],
    }),
  );

  // get_weather — requires `weather:read`. This scope IS advertised in PRM
  // `scopes_supported`, so a fresh client typically already has it.
  server.registerTool(
    "get_weather",
    {
      description: "Get the current weather for a city.",
      inputSchema: z.object({ city: z.string().min(1) }),
    },
    ({ city }: { city: string }) => {
      requireScope(claims, "weather:read");
      return {
        content: [{ type: "text", text: JSON.stringify(mockWeather(city)) }],
      };
    },
  );

  // get_premium_forecast — requires `weather:premium`. This scope is
  // deliberately NOT in PRM `scopes_supported` (§3.1); the 403 step-up
  // challenge tells the client to re-authorize with the premium scope.
  server.registerTool(
    "get_premium_forecast",
    {
      description: "Get a 14-day premium forecast for a city.",
      inputSchema: z.object({ city: z.string().min(1) }),
    },
    ({ city }: { city: string }) => {
      requireScope(claims, "weather:premium");
      return {
        content: [{ type: "text", text: JSON.stringify(mockPremiumForecast(city)) }],
      };
    },
  );
}
