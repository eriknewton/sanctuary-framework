/**
 * MCP stdio stdout purity — audit-log startup announcement (F5, v1.6.1).
 *
 * On an MCP stdio boot, stdout is the JSON-RPC channel: any non-JSON-RPC
 * byte written there before the initialize response corrupts the protocol
 * stream. The AuditLog constructor's one-time "cross-process file locking
 * enabled" announcement previously went through console.info, which writes
 * to STDOUT in Node (it was empirically the first line of stdout, ahead of
 * the initialize response). This pins the fix: the announcement goes to
 * stderr, and the constructor writes NOTHING to stdout.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuditLog } from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

describe("AuditLog construction stdout purity (F5)", () => {
  const dirs: string[] = [];

  afterEach(async () => {
    for (const d of dirs.splice(0)) {
      await rm(d, { recursive: true, force: true });
    }
  });

  it("routes the file-locking announcement to stderr (console.error), never a stdout-bound console method", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-audit-stdout-"));
    dirs.push(root);

    // In Node, console.log/info/debug write to STDOUT and console.error/warn
    // write to STDERR. Spying the console methods (rather than the raw
    // streams, which vitest's console interception bypasses) pins that the
    // announcement can never land on the JSON-RPC stdout channel.
    const stdoutBound = [
      vi.spyOn(console, "log").mockImplementation(() => {}),
      vi.spyOn(console, "info").mockImplementation(() => {}),
      vi.spyOn(console, "debug").mockImplementation(() => {}),
    ];
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      new AuditLog(
        new FilesystemStorage(join(root, "state")),
        generateRandomKey(),
        { integrityMode: "lenient" },
      );
      // Protocol invariant: constructing the audit log (part of the MCP
      // stdio boot path) must emit nothing through a stdout-bound method.
      for (const spy of stdoutBound) {
        expect(spy).not.toHaveBeenCalled();
      }
      // The operator-facing announcement still fires, on stderr.
      const stderrText = errorSpy.mock.calls
        .map((call) => call.map(String).join(" "))
        .join("\n");
      expect(stderrText).toContain("cross-process file locking enabled");
    } finally {
      for (const spy of stdoutBound) spy.mockRestore();
      errorSpy.mockRestore();
    }
  });
});
