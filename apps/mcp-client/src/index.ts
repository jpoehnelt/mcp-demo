#!/usr/bin/env node
// MCP Client CLI entry. The flow lives in `flow.ts`; this file only:
//
//   1. parses argv via commander,
//   2. validates the result with `parseOptions` (zod),
//   3. wires a stdout reporter + stderr logger,
//   4. runs the flow and exits with the right status code.
//
// Spec: specs/client.md §1 (CLI surface), §5 (output format).
//
// The CLI has a single operation (drive the full OAuth + tool-call flow),
// so we expose it as flat program-level options rather than a subcommand.
// pnpm's `--` separator (`pnpm dev:client -- --tool foo`) only works
// cleanly without a subcommand because commander would otherwise treat
// trailing args as positional inputs to the subcommand.

import { pathToFileURL } from "node:url";
import { Command } from "commander";
import { z } from "zod";
import {
  DEFAULT_ARGS_JSON,
  DEFAULT_CIMD_PORT,
  DEFAULT_SERVER_URL,
  DEFAULT_TOOL,
  parseOptions,
  type RawOptions,
} from "./cli.js";
import { type Reporter, runFlow } from "./flow.js";
import { createLogger } from "./log.js";

const STEP_PREFIX = "✓ "; // ✓
const RESULT_PREFIX = "\nResult: ";

function makeStdoutReporter(): Reporter {
  return {
    step(line: string): void {
      process.stdout.write(`${STEP_PREFIX}${line}\n`);
    },
    result(line: string): void {
      process.stdout.write(`${RESULT_PREFIX}${line}\n`);
    },
  };
}

/**
 * Pretty-print the tool's result payload. Tools return JSON-serialized
 * strings (per the MCP server's `JSON.stringify` calls); render an
 * indented form for readability when the payload parses as JSON.
 */
function formatToolResult(text: string): string {
  try {
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed === "object" && parsed !== null) {
      return JSON.stringify(parsed, null, 2);
    }
  } catch {
    // Fall through — not JSON, render verbatim.
  }
  return text;
}

async function main(argv: string[]): Promise<void> {
  const program = new Command();
  program
    .name("mcp-client")
    .description(
      "MCP Demo Client — drives OAuth 2.1 + CIMD discovery, authorization, and tool call",
    )
    .option("--server <url>", "MCP server URL", DEFAULT_SERVER_URL)
    .option("--tool <name>", "Tool to call", DEFAULT_TOOL)
    .option("--args <json>", "Tool arguments (JSON object)", DEFAULT_ARGS_JSON)
    .option("--scope <scopes>", "Initial scope request (default: from 401 challenge)")
    .option("--cimd-port <n>", "Port for local CIMD/callback server", String(DEFAULT_CIMD_PORT))
    .option("--auto-open", "Open the browser automatically (default: true unless --headless or CI)")
    .option("--headless", "Auto-approve consent via direct HTTP (CI demo)")
    .option("--verbose", "Print the full handshake timeline");

  // Strip standalone `--` from argv. pnpm forwards `pnpm dev:client -- --tool
  // foo` as `... -- --tool foo`, preserving the separator; commander then
  // treats everything after `--` as positional args and errors with "too many
  // arguments". The `--` is a pnpm artifact, not user intent — remove it.
  const cleanedArgv = argv.filter((arg, i) => !(arg === "--" && i >= 2));
  program.parse(cleanedArgv);
  const rawOpts = program.opts<RawOptions>();

  let options: ReturnType<typeof parseOptions>;
  try {
    options = parseOptions(rawOpts);
  } catch (err) {
    if (err instanceof z.ZodError) {
      for (const issue of err.issues) {
        process.stderr.write(`error: ${issue.message}\n`);
      }
    } else {
      process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
    }
    process.exit(2);
  }

  const log = createLogger({ level: options.verbose ? "debug" : "info" });
  const reporter = makeStdoutReporter();

  try {
    const result = await runFlow(options, { log, reporter });
    reporter.result(formatToolResult(result.resultText));
    if (options.verbose) {
      process.stdout.write(
        `\n(handshake completed; step-ups=${String(result.stepUpsPerformed)}, final scope="${result.finalScope}")\n`,
      );
    }
    process.exit(0);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`\nFlow failed: ${message}\n`);
    log.error({ err }, "client flow failed");
    process.exit(1);
  }
}

// pathToFileURL handles Windows backslashes + special-char encoding correctly;
// `file://${process.argv[1]}` would mis-match on either.
const isMain = import.meta.url === pathToFileURL(process.argv[1] ?? "").href;
if (isMain) {
  main(process.argv).catch((err: unknown) => {
    const log = createLogger();
    log.error({ err }, "fatal client error");
    process.exit(1);
  });
}

export { startCIMDServer } from "./cimd-server.js";
export type { ClientOptions } from "./cli.js";
export { parseOptions } from "./cli.js";
// Public surface — other packages / tests can import the flow building blocks.
export { runFlow } from "./flow.js";
export { createLogger } from "./log.js";
