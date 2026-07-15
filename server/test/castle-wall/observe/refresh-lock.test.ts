/**
 * Castle Wall Observe -- cross-process refresh lockfile tests (Codex
 * two-family gate: round-1 BLOCKER concurrent double-count, round-2 HIGH
 * stale-break TOCTOU).
 *
 * The load-bearing properties:
 *   1. O_EXCL exclusivity: exactly one acquirer wins; the loser gets null
 *      (=> `refresh_in_progress`), never a second lock.
 *   2. NO automatic stale-lock breaking, ever: even a lock recorded by a
 *      provably-dead pid is not removed (any same-call break-and-retry has a
 *      TOCTOU where a slow breaker unlinks a peer's fresh lock); the
 *      contention callback carries operator guidance instead.
 *   3. Release removes the file and a later acquire succeeds.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { observeRefreshFileLock } from "../../../src/cli/castle-wall-observe.js";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "observe-refresh-lock-"));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("observeRefreshFileLock", () => {
  it("acquires exclusively: the second acquirer gets null while the first holds, and succeeds after release", async () => {
    const lockA = observeRefreshFileLock(dir);
    const lockB = observeRefreshFileLock(dir);

    const releaseA = await lockA.acquire();
    expect(releaseA).not.toBeNull();
    expect(await lockB.acquire()).toBeNull();

    await releaseA!();
    const releaseB = await lockB.acquire();
    expect(releaseB).not.toBeNull();
    await releaseB!();
  });

  it("records its holder pid, and the contention callback describes a LIVE holder without touching the lock", async () => {
    const lock = observeRefreshFileLock(dir);
    const release = await lock.acquire();
    const raw = JSON.parse(await readFile(join(dir, ".observe-refresh.lock"), "utf8")) as {
      pid: number;
    };
    expect(raw.pid).toBe(process.pid);

    let described = "";
    const contender = observeRefreshFileLock(dir, (holder) => {
      described = holder;
    });
    expect(await contender.acquire()).toBeNull();
    expect(described).toContain(`running process ${process.pid}`);
    await release!();
  });

  it("NEVER auto-breaks a stale lock: a dead-pid lock still refuses acquisition, and the guidance names the dead holder and the file", async () => {
    const lockPath = join(dir, ".observe-refresh.lock");
    // A pid that cannot be running (beyond typical pid_max) but is a valid
    // integer -- process.kill() will ESRCH => "not alive".
    const deadPid = 2 ** 30;
    await writeFile(
      lockPath,
      JSON.stringify({ pid: deadPid, acquired_at: "2026-07-14T00:00:00.000Z" }),
      { mode: 0o600 },
    );

    let described = "";
    const lock = observeRefreshFileLock(dir, (holder) => {
      described = holder;
    });
    expect(await lock.acquire()).toBeNull();
    // The stale file was NOT removed (no automatic break; removal is a
    // deliberate human action per the operator guidance).
    expect(await readFile(lockPath, "utf8")).toContain(String(deadPid));
    expect(described).toContain("NO LONGER RUNNING");
    expect(described).toContain(lockPath);
  });

  it("an unreadable/garbage lock file also refuses acquisition (fail toward not folding)", async () => {
    const lockPath = join(dir, ".observe-refresh.lock");
    await writeFile(lockPath, "not json", { mode: 0o600 });
    const lock = observeRefreshFileLock(dir);
    expect(await lock.acquire()).toBeNull();
    expect(await readFile(lockPath, "utf8")).toBe("not json");
  });
});
