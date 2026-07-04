/**
 * Fleet license ledger I/O layer — durability + minimal O_EXCL mutation lock
 * (PR-1 fast-follow, fix-round 3) adversarial tests.
 *
 * These are the acceptance criteria for the durability fix and the SIMPLIFIED
 * lock contract:
 *   - Fix 1 (P0): `saveLedger` must be a DURABLE rename — it must fsync the temp
 *     FILE (and best-effort the parent DIRECTORY) before returning, so the blob
 *     is on stable storage before the external anchor can advance. Without this
 *     the "blob-before-anchor" ordering claim is FALSE and a crash can
 *     false-brick a legitimate fortress (`ledger.gen < anchor.gen`).
 *   - Fix-round 3: `withLedgerMutationLock` is a MINIMAL `O_EXCL` advisory lock
 *     with NO auto-stale-break. Acquire is a single atomic `open(lockPath,'wx')`;
 *     contention backs off and retries to a budget; budget exhaustion FAILS
 *     CLOSED with a recovery hint; release is an unconditional `unlink` of the
 *     file we created (sole holder by O_EXCL). The whole token/nonce/pid-liveness
 *     stale-break machinery was DELETED because its `stat`/`readFile`-then-
 *     `unlink` check-then-act was a `js/file-system-race` fail-open. The only
 *     behavior change is that a crashed-mid-mutation holder wedges until a
 *     one-time manual `rm` (a fail-safe, hinted in the error) — strictly better
 *     than a fail-open auto-break for a single-operator local CLI.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, open, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  saveLedger,
  loadLedger,
  withLedgerMutationLock,
} from "../../src/entitlement/ledger-io.js";
import { emptyLedger } from "../../src/entitlement/ledger.js";

describe("ledger-io — saveLedger is a DURABLE rename (Fix 1, the F1 class)", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sanctuary-ledger-io-"));
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await rm(dir, { recursive: true, force: true });
  });

  it("fsyncs the ledger blob (FileHandle.sync) before the write returns", async () => {
    const path = join(dir, "sub", "fleet-license-ledger.json");
    // Spy on FileHandle.prototype.sync so we can prove the durable path ran.
    const handle = await open(join(dir, "probe"), "w");
    const proto = Object.getPrototypeOf(handle) as { sync: () => Promise<void> };
    const syncSpy = vi.spyOn(proto, "sync");
    await handle.close();
    syncSpy.mockClear();

    await saveLedger(path, emptyLedger());

    // The durable-write helper fsyncs the temp FILE before rename (and
    // best-effort the parent DIR after). At minimum the ledger blob's own file
    // handle must have been synced — i.e. the mutation path is durable.
    expect(syncSpy).toHaveBeenCalled();
  });

  it("the blob is readable + parseable after saveLedger returns (durable + atomic)", async () => {
    const path = join(dir, "fleet-license-ledger.json");
    await saveLedger(path, emptyLedger());
    // Present on disk with owner-only mode, and it round-trips through loadLedger.
    const st = await stat(path);
    expect(st.mode & 0o777).toBe(0o600);
    const loaded = await loadLedger(path);
    expect(Array.isArray(loaded.rows)).toBe(true);
    expect(loaded.rows.length).toBe(0);
  });

  it("no stray .tmp file is left behind after a successful save", async () => {
    const path = join(dir, "fleet-license-ledger.json");
    await saveLedger(path, emptyLedger());
    const { readdir } = await import("node:fs/promises");
    const entries = await readdir(dir);
    expect(entries.some((e) => e.includes(".tmp"))).toBe(false);
    // Exactly the ledger file, nothing else.
    expect(entries).toEqual(["fleet-license-ledger.json"]);
  });
});

describe("ledger-io — minimal O_EXCL mutation lock (fix-round 3)", () => {
  let dir: string;
  let path: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sanctuary-ledger-lock-"));
    path = join(dir, "fleet-license-ledger.json");
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await rm(dir, { recursive: true, force: true });
  });

  it("serializes concurrent mutations (no interleave, no double-acquire)", async () => {
    // The CORE guarantee: two concurrent issue/revoke sequences must run one at
    // a time so neither lost-updates the ledger or races the anchor.
    const order: string[] = [];
    let active = 0;
    let maxActive = 0;
    const body = (tag: string) => async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      order.push(`${tag}-start`);
      await new Promise((r) => setTimeout(r, 15));
      order.push(`${tag}-end`);
      active--;
    };
    await Promise.all([
      withLedgerMutationLock(path, body("A")),
      withLedgerMutationLock(path, body("B")),
    ]);
    // Only ever one holder inside the critical section.
    expect(maxActive).toBe(1);
    // Neither run interleaved: each *-start is immediately followed by its *-end.
    expect(order).toContain("A-start");
    expect(order).toContain("B-start");
    const aStart = order.indexOf("A-start");
    const bStart = order.indexOf("B-start");
    const aEnd = order.indexOf("A-end");
    const bEnd = order.indexOf("B-end");
    if (aStart < bStart) {
      expect(aEnd).toBeLessThan(bStart); // A fully finished before B started
    } else {
      expect(bEnd).toBeLessThan(aStart);
    }
  });

  it("a held lock makes a second mutation FAIL CLOSED with a hint naming the lock path", async () => {
    // A lockfile already exists (a holder is mid-mutation, or a crashed holder
    // left it behind). With no auto-stale-break, the contender must exhaust its
    // budget and throw rather than proceed unlocked. The error must hint the
    // self-service recovery (`rm '<lockPath>'`) and name the lock path.
    const lockPath = `${path}.lock`;
    const heldHandle = await open(lockPath, "wx", 0o600);
    try {
      let contenderEntered = false;
      await expect(
        withLedgerMutationLock(
          path,
          async () => {
            contenderEntered = true;
            return "should-not-run";
          },
          { maxAttempts: 4, backoffMs: 5 },
        ),
      ).rejects.toThrow(/could not acquire/);
      // Never proceeded unlocked (no double-acquire / no unlocked mutate).
      expect(contenderEntered).toBe(false);
      // The recovery hint names the exact lock path so an operator can `rm` it.
      await expect(
        withLedgerMutationLock(path, async () => "x", {
          maxAttempts: 2,
          backoffMs: 5,
        }),
      ).rejects.toThrow(new RegExp(`rm '${lockPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}'`));
      // The held lockfile is left intact (the contender never breaks it).
      await expect(stat(lockPath)).resolves.toBeTruthy();
    } finally {
      await heldHandle.close();
    }
  });

  it("release removes the lockfile on the clean path (a subsequent acquire succeeds)", async () => {
    const lockPath = `${path}.lock`;
    await withLedgerMutationLock(path, async () => {
      // While held, the lockfile exists and carries the human diagnostic.
      const held = await readFile(lockPath, "utf-8");
      expect(held.trim().length).toBeGreaterThan(0);
    });
    // Lockfile gone after a clean release (sole-holder unconditional unlink).
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
    // And a subsequent acquire succeeds because the path is free again.
    let ran = false;
    await withLedgerMutationLock(path, async () => {
      ran = true;
    });
    expect(ran).toBe(true);
  });

  it("does NOT auto-break a pre-existing lockfile — it fails closed (no fail-open)", async () => {
    // Explicit regression for the deleted stale-break: even a lockfile with an
    // ancient mtime and an implausible/dead-looking pid must NOT be auto-broken.
    // There is no stat/mtime/pid-liveness path anymore; the contender simply
    // fails closed and leaves the file for a manual `rm`.
    const lockPath = `${path}.lock`;
    const { writeFile, utimes } = await import("node:fs/promises");
    await writeFile(lockPath, `2147483646\nstale\n`, { mode: 0o600 });
    const old = new Date(Date.now() - 10 * 60_000);
    await utimes(lockPath, old, old);

    let mutated = false;
    await expect(
      withLedgerMutationLock(
        path,
        async () => {
          mutated = true;
        },
        { maxAttempts: 3, backoffMs: 5 },
      ),
    ).rejects.toThrow(/could not acquire/);
    expect(mutated).toBe(false);
    // The pre-existing lockfile is untouched (never stale-broken).
    await expect(stat(lockPath)).resolves.toBeTruthy();
  });
});
