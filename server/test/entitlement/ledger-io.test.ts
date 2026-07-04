/**
 * Fleet license ledger I/O layer — durability + owner-verified lock (PR-1
 * fast-follow fix-round) adversarial tests.
 *
 * These are the acceptance criteria for the two durability/ordering fixes the
 * two-family gate demanded:
 *   - Fix 1 (P0): `saveLedger` must be a DURABLE rename — it must fsync the temp
 *     FILE (and best-effort the parent DIRECTORY) before returning, so the blob
 *     is on stable storage before the external anchor can advance. Without this
 *     the "blob-before-anchor" ordering claim is FALSE and a crash can
 *     false-brick a legitimate fortress (`ledger.gen < anchor.gen`).
 *   - Fix 2 (P1): `withLedgerMutationLock` must be OWNER-VERIFIED — a stale-break
 *     may only remove a lock whose recorded pid is provably DEAD, and a release
 *     may only unlink a lockfile that still carries OUR nonce. Otherwise a
 *     stale-break of a live-but-slow holder, or a foreign-token unlink, produces
 *     two live holders / vanishes a peer's lock mid-run.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  mkdtemp,
  open,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
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

describe("ledger-io — owner-verified mutation lock (Fix 2)", () => {
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

  it("serializes concurrent mutations (no interleave)", async () => {
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

  it("does NOT break a live-but-slow holder even past staleMs (no two holders)", async () => {
    // Holder A takes longer than staleMs. A contender B must NOT steal the lock,
    // because A's recorded pid (this very process) is provably ALIVE — the
    // stale-break guard requires BOTH age > staleMs AND a dead pid.
    let overlap = false;
    let aInside = false;

    const a = withLedgerMutationLock(
      path,
      async () => {
        aInside = true;
        // Hold well past staleMs while B contends.
        await new Promise((r) => setTimeout(r, 120));
        aInside = false;
      },
      { staleMs: 20, maxAttempts: 40, backoffMs: 10 },
    );

    // Give A time to acquire, then contend with B.
    await new Promise((r) => setTimeout(r, 30));
    const b = withLedgerMutationLock(
      path,
      async () => {
        // If B ever runs while A is still inside, that is two live holders.
        if (aInside) overlap = true;
      },
      { staleMs: 20, maxAttempts: 40, backoffMs: 10 },
    );

    await Promise.all([a, b]);
    expect(overlap).toBe(false);
  });

  it("DOES break a genuinely-dead holder's stale lock (pid not alive)", async () => {
    // Simulate a crashed holder: a stale lockfile recording a pid that is not a
    // live process. The contender must break it (age > staleMs AND pid dead) and
    // acquire, otherwise a single crash wedges the CLI forever.
    const lockPath = `${path}.lock`;
    const deadPid = 2_147_483_646; // implausibly high; not a live process
    await writeFile(
      lockPath,
      `${deadPid}\n${Date.now() - 10_000}\ndead-holder-nonce\n`,
      { mode: 0o600 },
    );
    // Backdate the mtime so it is older than staleMs.
    const { utimes } = await import("node:fs/promises");
    const old = new Date(Date.now() - 10_000);
    await utimes(lockPath, old, old);

    let ran = false;
    await withLedgerMutationLock(
      path,
      async () => {
        ran = true;
      },
      { staleMs: 100, maxAttempts: 40, backoffMs: 10 },
    );
    expect(ran).toBe(true);
  });

  it("does NOT break a stale lock whose recorded pid is still ALIVE", async () => {
    // A lockfile older than staleMs but recording THIS process's (alive) pid
    // must NOT be broken — that is the two-live-holders race. The acquire must
    // exhaust its budget and fail-closed instead of stealing a live lock.
    const lockPath = `${path}.lock`;
    await writeFile(
      lockPath,
      `${process.pid}\n${Date.now() - 10_000}\nlive-holder-nonce\n`,
      { mode: 0o600 },
    );
    const { utimes } = await import("node:fs/promises");
    const old = new Date(Date.now() - 10_000);
    await utimes(lockPath, old, old);

    await expect(
      withLedgerMutationLock(path, async () => "should-not-run", {
        staleMs: 100,
        maxAttempts: 3,
        backoffMs: 5,
      }),
    ).rejects.toThrow(/could not acquire/);
    // The live holder's lockfile is left intact (never broken).
    const still = await readFile(lockPath, "utf-8");
    expect(still).toContain("live-holder-nonce");
  });

  it("release unlinks ONLY our own nonce, never a foreign token", async () => {
    // Model the mid-run steal: while we hold the lock, a peer replaces the
    // lockfile contents with THEIR token. Our finally-release must see the
    // foreign nonce and LEAVE it (unlinking it would vanish the peer's lock).
    const lockPath = `${path}.lock`;
    let foreignSurvived = false;

    await withLedgerMutationLock(path, async () => {
      // A peer broke ours as stale and now holds it (different nonce).
      await writeFile(
        lockPath,
        `${process.pid}\n${Date.now()}\nforeign-peer-nonce\n`,
        { mode: 0o600 },
      );
    });

    // After our release, the foreign token must STILL be present.
    try {
      const after = await readFile(lockPath, "utf-8");
      foreignSurvived = after.includes("foreign-peer-nonce");
    } catch {
      foreignSurvived = false;
    }
    expect(foreignSurvived).toBe(true);
  });

  it("release removes our OWN lockfile on the normal (unstolen) path", async () => {
    const lockPath = `${path}.lock`;
    await withLedgerMutationLock(path, async () => {
      // Our nonce is on disk; a normal release should remove it.
      const held = await readFile(lockPath, "utf-8");
      expect(held.trim().length).toBeGreaterThan(0);
    });
    // Lockfile gone after a clean release.
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("fails closed (throws) rather than mutating unlocked when the lock cannot be acquired", async () => {
    // A live holder that outlasts the contender's budget → fail-closed, never a
    // silent unlocked mutate.
    const lockPath = `${path}.lock`;
    await writeFile(
      lockPath,
      `${process.pid}\n${Date.now()}\nheld-nonce\n`,
      { mode: 0o600 },
    );
    let mutated = false;
    await expect(
      withLedgerMutationLock(
        path,
        async () => {
          mutated = true;
        },
        { staleMs: 60_000, maxAttempts: 2, backoffMs: 5 },
      ),
    ).rejects.toThrow(/could not acquire/);
    expect(mutated).toBe(false);
  });
});
