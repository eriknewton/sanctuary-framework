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
 *
 * F4 (Exit V2 D1 operator finding, 2026-08-23) added a second invariant:
 * every `sanctuary exit` verb constructs an AuditLog, so this internal lock
 * -path detail used to land on an operator's terminal on every invocation.
 * It is now gated on SANCTUARY_VERBOSE and silent by default; the first
 * test below pins that default-quiet behavior, the second pins that the
 * F5 stderr-only invariant still holds once an operator opts in.
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

  it("prints NOTHING (default, SANCTUARY_VERBOSE unset): the lock-path announcement is opt-in, not every-invocation noise (F4)", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-audit-stdout-quiet-"));
    dirs.push(root);
    const previous = process.env.SANCTUARY_VERBOSE;
    delete process.env.SANCTUARY_VERBOSE;

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
      for (const spy of stdoutBound) {
        expect(spy).not.toHaveBeenCalled();
      }
      expect(errorSpy).not.toHaveBeenCalled();
    } finally {
      for (const spy of stdoutBound) spy.mockRestore();
      errorSpy.mockRestore();
      if (previous === undefined) delete process.env.SANCTUARY_VERBOSE;
      else process.env.SANCTUARY_VERBOSE = previous;
    }
  });

  it("with SANCTUARY_VERBOSE=1: routes the file-locking announcement to stderr (console.error), never a stdout-bound console method", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-audit-stdout-verbose-"));
    dirs.push(root);
    const previous = process.env.SANCTUARY_VERBOSE;
    process.env.SANCTUARY_VERBOSE = "1";

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
      // The operator-facing announcement still fires, on stderr, once
      // opted in.
      const stderrText = errorSpy.mock.calls
        .map((call) => call.map(String).join(" "))
        .join("\n");
      expect(stderrText).toContain("cross-process file locking enabled");
    } finally {
      for (const spy of stdoutBound) spy.mockRestore();
      errorSpy.mockRestore();
      if (previous === undefined) delete process.env.SANCTUARY_VERBOSE;
      else process.env.SANCTUARY_VERBOSE = previous;
    }
  });
});
