// End-to-end smoke test — spawns the IdP and MCP server as real Node
// subprocesses on their default ports, then runs the client subprocess in
// `--headless` mode and asserts the demo's expected output.
//
// This is the closest thing to a production demo we have, so it doubles as
// a regression check for the run scripts (`pnpm dev:idp`, `pnpm dev:mcp`,
// `pnpm dev:client`).
//
// Long-running by design (~10s for the subprocess boot path). Skipped by
// default; set `RUN_SMOKE=1` to enable. The in-process auth-flow.test.ts
// covers the same surface in a fraction of the time and runs on every
// `pnpm test`, so the smoke test is opt-in.
//
// Set `CI_SKIP_SMOKE=1` to force-skip even when `RUN_SMOKE=1` is set
// (useful for CI matrices that selectively disable long tests).

import { type ChildProcess, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const FORCE_SKIP = process.env.CI_SKIP_SMOKE !== undefined && process.env.CI_SKIP_SMOKE !== "";
const OPT_IN = process.env.RUN_SMOKE !== undefined && process.env.RUN_SMOKE !== "";
const SKIP_SMOKE = FORCE_SKIP || !OPT_IN;
// fileURLToPath: `new URL(...).pathname` returns `/C:/foo` on Windows which
// breaks spawn(cwd).
const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));

const IDP_PORT = 4444;
const MCP_PORT = 3333;

async function waitForHttp(url: string, timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      // Only 2xx is a healthy boot. 4xx/5xx mean the listener is up but the
      // app isn't ready (e.g. discovery still failing) — keep waiting.
      if (res.ok) return;
    } catch (err) {
      lastErr = err;
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(
    `timed out waiting for ${url} (last error: ${lastErr instanceof Error ? lastErr.message : String(lastErr)})`,
  );
}

async function collectOutput(
  proc: ChildProcess,
): Promise<{ stdout: string; stderr: string; exitCode: number | null }> {
  let stdout = "";
  let stderr = "";
  proc.stdout?.setEncoding("utf8");
  proc.stderr?.setEncoding("utf8");
  proc.stdout?.on("data", (chunk: string) => {
    stdout += chunk;
  });
  proc.stderr?.on("data", (chunk: string) => {
    stderr += chunk;
  });
  const exitCode = await new Promise<number | null>((resolve) => {
    proc.on("exit", (code) => resolve(code));
  });
  return { stdout, stderr, exitCode };
}

function killProc(proc: ChildProcess | undefined): void {
  if (proc === undefined || proc.killed) return;
  try {
    proc.kill("SIGTERM");
  } catch {
    // ignore
  }
}

describe.skipIf(SKIP_SMOKE)("subprocess smoke test", () => {
  let idp: ChildProcess | undefined;
  let mcp: ChildProcess | undefined;

  beforeEach(async () => {
    idp = spawn("pnpm", ["dev:idp"], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        AS_ISSUER_URL: `http://localhost:${String(IDP_PORT)}`,
        AS_PORT: String(IDP_PORT),
        AS_AUTO_APPROVE: "true",
        AS_DEV_ALLOW_INSECURE_CIMD: "true",
        // Force ephemeral DB so reruns don't share state.
        AS_DB_PATH: ":memory:",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    mcp = spawn("pnpm", ["dev:mcp"], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        MCP_OIDC_ISSUER_URL: `http://localhost:${String(IDP_PORT)}`,
        MCP_AUDIENCE: `http://localhost:${String(MCP_PORT)}`,
        MCP_PRM_AUTH_SERVERS: `http://localhost:${String(IDP_PORT)}`,
        MCP_PORT: String(MCP_PORT),
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    await waitForHttp(`http://localhost:${String(IDP_PORT)}/healthz`);
    await waitForHttp(`http://localhost:${String(MCP_PORT)}/healthz`);
  }, 30_000);

  afterEach(() => {
    killProc(mcp);
    killProc(idp);
    mcp = undefined;
    idp = undefined;
  });

  it("end-to-end happy path via subprocesses (get_weather)", async () => {
    const client = spawn(
      "pnpm",
      [
        "dev:client",
        "--headless",
        "--server",
        `http://localhost:${String(MCP_PORT)}`,
        "--tool",
        "get_weather",
        "--args",
        '{"city":"Denver"}',
      ],
      { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "pipe"] },
    );
    const { stdout, exitCode } = await collectOutput(client);
    expect(exitCode).toBe(0);
    // The tool returns `{"city":"Denver","tempF":72,"conditions":"sunny"}`.
    expect(stdout).toContain("Denver");
    expect(stdout).toContain("72");
    expect(stdout).toContain("sunny");
  }, 30_000);

  it("end-to-end step-up via subprocesses (get_premium_forecast)", async () => {
    const client = spawn(
      "pnpm",
      [
        "dev:client",
        "--headless",
        "--server",
        `http://localhost:${String(MCP_PORT)}`,
        "--tool",
        "get_premium_forecast",
        "--args",
        '{"city":"Denver"}',
      ],
      { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "pipe"] },
    );
    const { stdout, exitCode } = await collectOutput(client);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("forecast");
    // The premium forecast has 14 days; the result rendering should include
    // at least `day` and `tempF` keys.
    expect(stdout).toContain("day");
    expect(stdout).toContain("tempF");
  }, 45_000);
});
