import { readFile } from "node:fs/promises";
import { expect, it, vi } from "vitest";
import { parseDarwinProcessStartToken, parseLinuxProcessStartToken, readProcessStartToken, PROCESS_START_TOKEN_TIMEOUT_MS } from "../../src/operational/process-start-token.js";

async function fixture(name: string) {
  const record = JSON.parse(await readFile(new URL(`../fixtures/audit-lock/${name}.json`, import.meta.url), "utf8"));
  return Buffer.from(record.bytes_base64, "base64").toString("utf8");
}
it("reads exact field 22 from captured and hostile-comm proc records", async () => {
  expect(parseLinuxProcessStartToken(await fixture("proc-stat-box1"))).toBe("192517291");
  expect(parseLinuxProcessStartToken(await fixture("proc-stat-hostile-comm"))).toBe("192517291");
  for (const value of ["", "123 (comm) S 1 2", "garbage"]) expect(parseLinuxProcessStartToken(value)).toBeUndefined();
});
it("runs the captured Darwin ps shape through the scrubbed exec seam on Linux", async () => {
  const exec = vi.fn(async () => fixture("ps-lstart-mac"));
  expect(await readProcessStartToken(123, "darwin", exec)).toBe("Sun Nov  1 10:46:41 2026");
  expect(exec).toHaveBeenCalledWith("/bin/ps", ["-p", "123", "-o", "lstart="], { env: { LC_ALL: "C", TZ: "UTC" }, timeout: PROCESS_START_TOKEN_TIMEOUT_MS });
});
it("refuses malformed, failed and timed-out identity reads", async () => {
  for (const text of ["Sun Nov  1 10:46:41 2026\r\n", "Sun Nov 1 10:46:41 2026", "Sun Nov  1 10:46:41 2026\n\n", "garbage"]) expect(parseDarwinProcessStartToken(text)).toBeUndefined();
  for (const code of ["ETIMEDOUT", "ENOENT", "nonzero exit"]) expect(await readProcessStartToken(123, "darwin", async () => { throw new Error(code); })).toBeUndefined();
  expect(await readProcessStartToken(0)).toBeUndefined();
});
