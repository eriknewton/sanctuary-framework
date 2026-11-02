// The portable unit tier uses only Python's standard library and temporary state.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { resolve } from "node:path";
import { expect, it } from "vitest";

it("passes the isolated Python unit tier", async () => {
  const result = await promisify(execFile)("python3", ["-I", "-B", "-m", "unittest", "discover", "-s",
    "hermes-plugin/tests/unit", "-t", "hermes-plugin", "-p", "test_*.py"], {
    cwd: resolve(".."), timeout: 60_000, maxBuffer: 1024 * 1024,
  }); // A minute and one MiB bound the entire portable suite.
  expect(result.stderr + result.stdout).toMatch(/^OK$/m);
}, 65_000); // Allow five seconds beyond the child timeout for reporting and cleanup.
