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
import { EventEmitter } from "node:events";
import {
  SpawnAgentLauncher,
  SpawnedChild,
  type ChildExitState,
  SUPERVISOR_KEY_FD_ENV,
  readSupervisorTransientKey,
  SupervisorKeyHandoffError,
} from "../../src/supervisor/spawn-launcher.js";
import { toBase64url } from "../../src/core/encoding.js";

/**
 * Arm an exit latch the same way SpawnAgentLauncher.launch() does at
 * spawn-confirmation (codex S1 R11): a PERSISTENT `exit` listener that records
 * into the shared state and replays to a registered callback. Returns the state
 * object to hand to SpawnedChild — modelling the no-gap latch.
 */
function armExitLatch(child: EventEmitter): ChildExitState {
  const state: ChildExitState = { exited: null, cb: null };
  child.on("exit", (code: number | null, signal: string | null) => {
    state.exited = { code, signal };
    if (state.cb) {
      const cb = state.cb;
      state.cb = null;
      cb({ code, signal });
    }
  });
  return state;
}

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

  it("REJECTS (does not return a child) when the spawn fails — bad executable (codex S1 R4-H1)", async () => {
    // A non-existent node binary makes spawn fail asynchronously via an `error`
    // event (ENOENT). The launcher MUST reject the promise so the Supervisor
    // zeroes the key + drops the entry, NOT resolve a SpawnedChild for a process
    // that never started (which would leave the transient key resident in
    // `running`). This proves the honest fail-closed residency property (#7).
    const launcher = new SpawnAgentLauncher({
      cliPath: "/nonexistent/cli.js",
      nodePath: "/nonexistent/definitely-not-a-real-node-binary",
    });
    await expect(
      launcher.launch({
        agent_id: "a-bad",
        harness: "claude_code",
        config_path: "/conf/x.json",
        transientKey: new Uint8Array([1, 2, 3, 4]),
      }),
    ).rejects.toThrow(/failed to spawn|exited before spawn/);
  });
});

describe("SpawnedChild exit-race latch (codex S1 R6-H1 + R11)", () => {
  it("delivers an exit that happened BEFORE SpawnedChild was even constructed (no-gap latch)", async () => {
    // The hardest race (R11): the child exits in the gap between spawn-
    // confirmation (where launch() arms the latch) and SpawnedChild
    // construction. The latch is armed FIRST, so the exit is captured into the
    // shared state before the wrapper exists; a late onExit must still fire.
    const child = new EventEmitter() as EventEmitter & {
      exitCode: number | null;
      signalCode: string | null;
    };
    child.exitCode = null;
    child.signalCode = null;
    const state = armExitLatch(child); // launch() arms this at spawn-confirmation
    // Child exits NOW — before SpawnedChild is constructed.
    child.exitCode = 2;
    child.emit("exit", 2, null);
    expect(state.exited).toEqual({ code: 2, signal: null });

    const wrapped = new SpawnedChild(child as never, 50, state);
    // The supervisor registers its callback LATE — it must still fire.
    const seen = await new Promise<{ code: number | null; signal: string | null }>(
      (resolve) => wrapped.onExit(resolve),
    );
    expect(seen.code).toBe(2);
  });

  it("delivers an exit that happened BEFORE onExit was registered (but after construction)", async () => {
    const child = new EventEmitter() as EventEmitter & {
      exitCode: number | null;
      signalCode: string | null;
    };
    child.exitCode = null;
    child.signalCode = null;
    const state = armExitLatch(child);
    const wrapped = new SpawnedChild(child as never, 50, state);
    child.exitCode = 2;
    child.emit("exit", 2, null);

    const seen = await new Promise<{ code: number | null; signal: string | null }>(
      (resolve) => wrapped.onExit(resolve),
    );
    expect(seen.code).toBe(2);
  });

  it("delivers a future exit to a callback registered before it", async () => {
    const child = new EventEmitter() as EventEmitter & {
      exitCode: number | null;
      signalCode: string | null;
    };
    child.exitCode = null;
    child.signalCode = null;
    const state = armExitLatch(child);
    const wrapped = new SpawnedChild(child as never, 50, state);
    const p = new Promise<{ code: number | null; signal: string | null }>((resolve) =>
      wrapped.onExit(resolve),
    );
    child.emit("exit", 1, "SIGTERM");
    const seen = await p;
    expect(seen.code).toBe(1);
    expect(seen.signal).toBe("SIGTERM");
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
