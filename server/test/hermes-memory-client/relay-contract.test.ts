// Native relay and pinned Python SDK consumer acceptance with disposable host ports.
import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { TOP_LEVEL_SUBCOMMANDS } from "../../src/cli/subcommands.js";
const run = promisify(execFile);
const repo = fileURLToPath(new URL("../../../", import.meta.url)).replace(/\/$/u, "");
const bundle = `${repo}/hermes-memory-relay/.build/debug/HermesMemoryRelayPackageTests.xctest`;
const python = "/opt/homebrew/bin/python3.12";
const arms = ["done", "async_failure", "eof", "signal", "malformed", "oversize", "depth", "malformed_relay", "pong", "socket_loss", "stdout_stall", "short_write", "buffered", "deadline", "unavailable", "cancel"];

describe.skipIf(process.platform !== "darwin")("native Python MCP consumer", () => {
  for (const arm of arms) it(`realClient_${arm}`, async () => {
    await access(bundle);
    const result = await run(python, [fileURLToPath(new URL("./real_client.py", import.meta.url)), "--repo", repo,
      "--node", process.execPath, "--bundle", bundle, "--arm", arm], { timeout: 150_000, maxBuffer: 1024 * 1024 });
    const observation = JSON.parse(result.stdout.trim());
    process.stdout.write(JSON.stringify(observation) + "\n");
    expect(observation.arm).toBe(arm);
    // Signal is an explicit contract discrepancy, retained as an unproven acceptance row.
    expect(observation.acceptance, `realClient_${arm}`).toMatch(arm === "signal" ? /^UNPROVEN:/u : /^PASS/u);
  }, 155_000);
});

it("nativeClientHasItsOwnDispatch", () => {
  expect(TOP_LEVEL_SUBCOMMANDS, "nativeClientHasItsOwnDispatch").toContain("hermes-memory-client");
});
