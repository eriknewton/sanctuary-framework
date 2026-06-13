/**
 * Phase S1 — Spawn launcher transient-key handoff (codex R2-H2).
 *
 * Proves the security property the env-handoff fix exists for: the transient
 * key reaches the child ONLY over the one-shot inherited fd pipe, and is NEVER
 * present in the child's environment or argv. Spawns a tiny real node child
 * that reports what it saw, so the assertion is against actual process
 * behaviour, not a mock.
 */

import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openSync, writeSync, closeSync, mkdtempSync as _mk } from "node:fs";
import {
  SpawnAgentLauncher,
  SUPERVISOR_KEY_FD_ENV,
  readSupervisorTransientKey,
  SupervisorKeyHandoffError,
} from "../../src/supervisor/spawn-launcher.js";
import { toBase64url } from "../../src/core/encoding.js";

describe("SpawnAgentLauncher transient-key handoff", () => {
  it("delivers the key over the fd pipe and NEVER via env or argv", async () => {
    const dir = mkdtempSync(join(tmpdir(), "superd-spawn-"));
    try {
      // A stub "cli" that reads fd 3, and reports whether the key bytes appear
      // in its env or argv. Writes a JSON report to a file we then read.
      const reportPath = join(dir, "report.json");
      const stub = join(dir, "stub.cjs");
      writeFileSync(
        stub,
        `
        const fs = require("fs");
        const fdRaw = process.env[${JSON.stringify(SUPERVISOR_KEY_FD_ENV)}];
        let fromFd = null;
        try { fromFd = fs.readFileSync(Number(fdRaw), "utf-8").trim(); } catch (e) { fromFd = "ERR:" + e.code; }
        const envBlob = JSON.stringify(process.env);
        const argvBlob = JSON.stringify(process.argv);
        fs.writeFileSync(${JSON.stringify(reportPath)}, JSON.stringify({ fromFd, envBlob, argvBlob }));
        `,
      );

      const KEY = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const keyB64 = toBase64url(KEY);
      const launcher = new SpawnAgentLauncher({ cliPath: stub, nodePath: process.execPath });

      // The launcher invokes `node stub.cjs wrap --config ... --harness ...`.
      // Our stub ignores the args and just reports. (The default argv shape is
      // fine; the stub only inspects fd/env/argv for the key.)
      const child = await launcher.launch({
        agent_id: "a1",
        harness: "claude_code",
        config_path: "/conf/a.json",
        transientKey: KEY,
      });

      await new Promise<void>((resolve) => child.onExit(() => resolve()));

      const report = JSON.parse(
        (await import("node:fs")).readFileSync(reportPath, "utf-8"),
      ) as { fromFd: string; envBlob: string; argvBlob: string };

      // The child read the key off the fd pipe.
      expect(report.fromFd).toBe(keyB64);
      // The key bytes are NOT in env or argv (codex R2-H2).
      expect(report.envBlob).not.toContain(keyB64);
      expect(report.argvBlob).not.toContain(keyB64);
      // The fd-number env var is present (it is not secret).
      expect(report.envBlob).toContain(SUPERVISOR_KEY_FD_ENV);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("readSupervisorTransientKey (fail-closed, codex R3-M1)", () => {
  it("returns null when not in supervisor mode (env absent)", () => {
    expect(readSupervisorTransientKey({})).toBeNull();
  });

  it("THROWS on a malformed fd env when supervisor mode is indicated", () => {
    expect(() => readSupervisorTransientKey({ [SUPERVISOR_KEY_FD_ENV]: "3x" })).toThrow(
      SupervisorKeyHandoffError,
    );
    expect(() => readSupervisorTransientKey({ [SUPERVISOR_KEY_FD_ENV]: "2" })).toThrow(
      SupervisorKeyHandoffError,
    );
  });

  it("round-trips a real key written to a temp fd, then closes the fd", () => {
    const dir = _mk(join(tmpdir(), "superd-fd-"));
    try {
      const file = join(dir, "key");
      const key = new Uint8Array([9, 8, 7, 6, 5]);
      const wfd = openSync(file, "w");
      writeSync(wfd, `${toBase64url(key)}\n`);
      closeSync(wfd);
      const rfd = openSync(file, "r");
      const out = readSupervisorTransientKey({ [SUPERVISOR_KEY_FD_ENV]: String(rfd) });
      expect(out).not.toBeNull();
      expect([...(out as Uint8Array)]).toEqual([9, 8, 7, 6, 5]);
      // The reader closed the fd; a second close throws EBADF.
      expect(() => closeSync(rfd)).toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("THROWS on a non-base64url key body in supervisor mode (no silent fallback)", () => {
    const dir = _mk(join(tmpdir(), "superd-fd2-"));
    try {
      const file = join(dir, "key");
      const wfd = openSync(file, "w");
      writeSync(wfd, "!!!not base64url!!!\n");
      closeSync(wfd);
      const rfd = openSync(file, "r");
      expect(() => readSupervisorTransientKey({ [SUPERVISOR_KEY_FD_ENV]: String(rfd) })).toThrow(
        SupervisorKeyHandoffError,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
