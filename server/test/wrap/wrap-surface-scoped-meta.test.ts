/**
 * 2026-07-02 install-path hardening, Group B: surface-scoped wrap-meta and
 * backup discrimination, non-destructive meta removal, the orphan-wrap
 * guard on every rollback path, the deduplicated banner honesty predicate,
 * the wrap-time pinned-version resolvability probe, and the unwrap
 * recovery breadcrumb for wrap-created files.
 *
 * Findings pinned here (Review/Sanctuary/Hardening_Wave_Revise_List_2026-07-02.md):
 *   1. hasExistingWrapMeta / findNewerBackup discriminate by SURFACE
 *      (resolve()d originalPath), not tenant-globally / by extension alone.
 *   2. removeWrapMeta never unlinks the pointer on a transient READ error;
 *      only genuinely-absent (ENOENT) or affirmatively-unparseable content
 *      is removable.
 *   3. The MED-1 orphan-wrap guard fires beyond the meta-write-failure
 *      site: pinned here on the primary REWRITE-failure path, the primary
 *      VERIFY-failure path (the restoredOnFailure plumbing), and the
 *      Hermes-YAML write-failure rollback. (The remaining site, the
 *      Hermes-YAML verify-failure rollback, shares the identical
 *      guard(rollbackWrapSurfaces()) call shape but has no isolated
 *      trigger seam; it is covered by inspection, not by a test here.)
 *   4. The MED-2 crash-window warning fires for surface X even when a
 *      DIFFERENT surface Y's wrap-meta exists (regression for the
 *      tenant-global suppression).
 *   5. The wrap banner renders protection prose only from a branded
 *      ProtectionStateClaim.
 *   6. checkPinnedVersionResolvable outcomes + the honest wrap-output
 *      downgrade on unpublished/unreachable pins (never blocks the wrap).
 *   7. Unwrap of a wrap-created file preserves its final contents as a
 *      timestamped backup breadcrumb before removal.
 *
 * Second-round hardening pinned here (2026-07-02 fix round):
 *   8. Unwrap tolerates a null-backup auxiliary file that is ALREADY
 *      absent (ENOENT) instead of counting it as a restore failure — the
 *      orphan-wrap guard can persist an aux entry for a file the failed
 *      wrap never created, and treating the phantom as a failure kept the
 *      wrap-meta alive forever and wedged every --unwrap re-run.
 *   9. The unpublished/unreachable pin outcome reaches the TERMINAL-FINAL
 *      success banner (formatWrapSuccess / formatWrapSuccessNoDashboard),
 *      not only the mid-flow warning that scrolls above it.
 *
 * Third-round hardening pinned here (2026-07-02 fix round 2):
 *  10. F6 preservation fails CLOSED on a transient wrap-meta read error:
 *      saveWrapMeta refuses (WrapMetaUnreadableError) instead of treating
 *      "unreadable" as "absent" and clobbering what may be the only
 *      pristine pointer; hasExistingWrapMeta stays deliberately lenient
 *      (unreadable reads false, failing toward the crash-window warning).
 *  11. The pin probe consults the registry npx will actually use
 *      (resolveNpmRegistryForProbe: npm config env + project/user/global
 *      npmrc) and, when resolution is indirect (custom registry or proxy egress),
 *      a 404 maps to honest-unknown "unreachable" instead of the loud
 *      false "unpublished" dead-pin warning.
 *
 * Fifth-round hardening pinned here (2026-07-02 fix round 3):
 *  12. A degraded backup-dir LISTING (non-ENOENT readdir failure) on the
 *      strict write path throws WrapMetaUnreadableError instead of hiding
 *      the scoped slots and letting saveWrapMeta's slot-cleanup unlink an
 *      unconsulted pristine pointer.
 *  13. saveWrapMeta / removeWrapMeta serialize under the cross-process
 *      advisory lock (wrap-meta.lock): concurrent wraps of different
 *      surfaces cannot clobber each other's canonical pointer and the
 *      lock never lingers after release.
 *
 * Eighth-round hardening pinned here (2026-07-02 fix round 4):
 *  14. removeWrapMeta consults the restored surface's own scoped slot as a
 *      DETERMINISTIC candidate (derived from the path, no readdir), so a
 *      degraded directory listing cannot leave a stale scoped pointer
 *      behind under a clean-success report.
 *
 * Ninth-round hardening pinned here (2026-07-02 fix round 10):
 *  16. Displaced holders fail CLOSED: a holder whose lock was removed out
 *      from under it mid-critical-section (the operator's manual lock
 *      removal against a presumed-crashed stall) refuses to write/retire
 *      wrap metadata instead of mutating alongside the successor, and its
 *      release still never evicts the successor's lock.
 *
 * Thirteenth-round simplification pinned here (2026-07-02 fix round 13):
 *  17. The auto-break-stale machinery is GONE (chokepoint rule): a lock
 *      file that persists past the bounded wait - live contender or
 *      crashed holder's leftover - expires into a fail-closed refusal
 *      naming the lock path with manual recovery advice. No code path
 *      ever unlinks or renames a lock file it did not create: a live
 *      holder's lock is never touched by a waiter, and a pre-placed stale
 *      lock survives the refusal untouched. (These convert the former
 *      round 5-12 stale-break pins, items 13/15 of earlier rounds, into
 *      pins of the replacement behavior.)
 *
 * Isolation: temp HOME + SANCTUARY_STORAGE_PATH (never the real
 * ~/.sanctuary), per the existing wrap-test idiom.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  writeFile,
  readFile,
  mkdir,
  mkdtemp,
  rm,
  chmod,
  access,
  readdir,
  utimes,
  unlink,
} from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";

import {
  runWrap,
  checkPinnedVersionResolvable,
  resolveNpmRegistryForProbe,
  formatWrapSuccess,
  formatWrapSuccessNoDashboard,
} from "../../src/wrap/cli.js";
import {
  protectionStateClaimFromObservation,
  type ProtectionStateClaim,
} from "../../src/egress-gate/protection-claim.js";
import {
  backupConfig,
  findLatestBackup,
  findNewerBackup,
  hasExistingWrapMeta,
  removeWrapMeta,
  saveWrapMeta,
  WrapMetaUnreadableError,
  __wrapMetaLockTestHooks,
} from "../../src/wrap/config-reader.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";
import {
  agreeingHermesParity,
  installHermesParityHook,
  clearHermesParityHook,
} from "../helpers/hermes-parity.js";

const CRASH_WINDOW_MARKER = "already contains a Sanctuary entry";

function claim(state: "exclusive" | "coarse-only" | "unprotected" | "unknown"): ProtectionStateClaim {
  switch (state) {
    case "exclusive":
      return protectionStateClaimFromObservation({
        state,
        basis: "exclusive_egress_observed",
      });
    case "coarse-only":
      return protectionStateClaimFromObservation({
        state,
        basis: "coarse_wall_observed",
      });
    case "unprotected":
      return protectionStateClaimFromObservation({
        state,
        basis: "not_enforcing_observed",
      });
    case "unknown":
      return protectionStateClaimFromObservation({
        state,
        basis: "insufficient_evidence",
        reasons: ["test"],
      });
  }
}

// The parse-parity sidecar seam is a test-only module hook, not a public
// runWrap dep (DI-bypass closed 2026-07-03). makeDeps() installs an agreeing
// parity; clear it after EVERY test in this file (nested describe blocks have
// their own afterEach, so a single file-level one guarantees no leak).
afterEach(() => {
  clearHermesParityHook();
});

describe("surface-scoped wrap-meta + backups, orphan guard, banner gate, pin probe", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let errSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    // mkdtemp: atomic fresh 0o700 dir (CodeQL js/insecure-temporary-file).
    tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-surface-scope-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(async () => {
    errSpy.mockRestore();
    vi.restoreAllMocks();
    if (originalHome !== undefined) process.env.HOME = originalHome;
    else delete process.env.HOME;
    if (originalStoragePath !== undefined)
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    else delete process.env.SANCTUARY_STORAGE_PATH;
    try {
      await rm(tmpHome, { recursive: true, force: true });
    } catch {}
  });

  function makeDeps(overrides: Record<string, unknown> = {}) {
    // Agree with the scanner via the test-only sidecar hook so these Hermes
    // surface-scoped meta mechanics tests do not depend on the CI host
    // carrying PyYAML (the parse-parity guard is proven separately in
    // hermes-yaml-parse-parity.test.ts). The sidecar seam is NOT a public
    // runWrap dep (DI-bypass closed 2026-07-03).
    installHermesParityHook(agreeingHermesParity);
    const fakeHandle: DashboardHandle = {
      url: "http://127.0.0.1:0",
      port: 0,
      host: "127.0.0.1",
      mode: "co-located",
      stop: async () => {},
    } as unknown as DashboardHandle;
    return {
      startDashboard: async () => fakeHandle,
      openBrowser: async () => {},
      resolvePassphrase: async () => ({
        value: "test-passphrase",
        location: "test-keychain",
        source: "generated" as const,
      }),
      ...overrides,
    };
  }

  function stderrOutput(): string {
    return errSpy.mock.calls.map((c) => c.map(String).join(" ")).join("\n");
  }

  function backupDirPath(): string {
    return join(tmpHome, ".sanctuary", "backup");
  }

  async function seedMetaFor(originalPath: string): Promise<void> {
    await writeFile(originalPath, "{}");
    const backup = await backupConfig(originalPath);
    await saveWrapMeta({
      backupPath: backup,
      originalPath,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    });
  }

  // ── Finding 1: per-surface wrap-meta + backup discrimination ────────

  it("hasExistingWrapMeta is scoped to the surface's resolve()d originalPath", async () => {
    const surfaceY = join(tmpHome, "surface-y.json");
    await seedMetaFor(surfaceY);

    const surfaceX = join(tmpHome, "surface-x.json");
    expect(await hasExistingWrapMeta(surfaceY)).toBe(true);
    expect(await hasExistingWrapMeta(surfaceX)).toBe(false);
  });

  it("hasExistingWrapMeta reads false when no meta exists at all", async () => {
    expect(await hasExistingWrapMeta(join(tmpHome, "anything.json"))).toBe(
      false,
    );
  });

  it("findNewerBackup never points at a DIFFERENT surface's backup of the same extension", async () => {
    const surfaceA = join(tmpHome, "a-config.json");
    const surfaceB = join(tmpHome, "b-config.json");
    await writeFile(surfaceA, '{"a":1}');
    await writeFile(surfaceB, '{"b":1}');

    const backupA1 = await backupConfig(surfaceA);
    // Millisecond-resolution filenames: keep the timestamps distinct.
    await new Promise((resolve) => setTimeout(resolve, 5));
    await backupConfig(surfaceB); // newer, same .json extension, OTHER surface

    // Pre-fix this returned surface B's backup (prefix+extension matched).
    expect(await findNewerBackup(backupA1, surfaceA)).toBeNull();

    await new Promise((resolve) => setTimeout(resolve, 5));
    const backupA2 = await backupConfig(surfaceA);
    expect(await findNewerBackup(backupA1, surfaceA)).toBe(backupA2);
    // The newest backup of a chain has nothing newer.
    expect(await findNewerBackup(backupA2, surfaceA)).toBeNull();
  });

  // ── Finding 2: removeWrapMeta is non-destructive on a read error ────

  it.skipIf(process.getuid?.() === 0)(
    "removeWrapMeta leaves the pointer in place and reports a failure on a transient read error",
    async () => {
      const configPath = join(tmpHome, "unreadable-meta-config.json");
      await seedMetaFor(configPath);
      const metaPath = join(backupDirPath(), "wrap-meta.json");

      await chmod(metaPath, 0o000);
      try {
        const failures = await removeWrapMeta(configPath);
        // Read failures are tagged "unreadable" so the unwrap caller can
        // print do-NOT-delete advice (the file might be another surface's
        // only restore pointer) instead of "remove it manually".
        expect(failures).toContainEqual({
          path: metaPath,
          reason: "unreadable",
        });
      } finally {
        await chmod(metaPath, 0o600);
      }
      // The pointer survived the error path: unwrap remains re-runnable.
      expect(await findLatestBackup()).not.toBeNull();

      // Once readable again, removal completes normally.
      expect(await removeWrapMeta(configPath)).toEqual([]);
      expect(await findLatestBackup()).toBeNull();
    },
  );

  it("removeWrapMeta still removes an affirmatively unparseable pointer file", async () => {
    const metaPath = join(backupDirPath(), "wrap-meta.json");
    await mkdir(backupDirPath(), { recursive: true, mode: 0o700 });
    await writeFile(metaPath, "not json {{{");

    expect(await removeWrapMeta(join(tmpHome, "whatever.json"))).toEqual([]);
    await expect(access(metaPath)).rejects.toThrow();
  });

  // ── Fourth round: write-side surface scoping (no single-slot clobber) ──

  it("wrapping a SECOND surface relocates the first surface's pointer instead of clobbering it; sequential unwraps find both", async () => {
    const surfaceA = join(tmpHome, "claude-settings.json");
    const surfaceB = join(tmpHome, "hermes-cli-config.json");
    await writeFile(surfaceA, '{"a":"pristine"}');
    await writeFile(surfaceB, '{"b":"pristine"}');

    const backupA = await backupConfig(surfaceA);
    await saveWrapMeta({
      backupPath: backupA,
      originalPath: surfaceA,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    });
    const backupB = await backupConfig(surfaceB);
    await saveWrapMeta({
      backupPath: backupB,
      originalPath: surfaceB,
      platform: "hermes",
      wrappedAt: new Date().toISOString(),
    });

    // Pre-fix, B's canonical write silently destroyed A's only pointer.
    expect(await hasExistingWrapMeta(surfaceA)).toBe(true);
    expect(await hasExistingWrapMeta(surfaceB)).toBe(true);

    // First unwrap restores the newest wrap (B) and retires only B's pointer.
    const first = await findLatestBackup();
    expect(first?.originalPath).toBe(surfaceB);
    expect(first?.backupPath).toBe(backupB);
    expect(await removeWrapMeta(surfaceB)).toEqual([]);

    // Second unwrap finds A via the relocated scoped slot. Pre-fix this
    // returned null ("No Sanctuary wrap found") while A stayed wrapped and
    // A's pristine backup was orphaned.
    const second = await findLatestBackup();
    expect(second?.originalPath).toBe(surfaceA);
    expect(second?.backupPath).toBe(backupA);
    expect(await removeWrapMeta(surfaceA)).toEqual([]);
    expect(await findLatestBackup()).toBeNull();
  });

  it("a wedged first pointer (backup file missing) refuses loudly, names the surviving wrapped surface, and never hides it", async () => {
    const surfaceA = join(tmpHome, "wedge-surface-a.json");
    const surfaceB = join(tmpHome, "wedge-surface-b.json");
    await seedMetaFor(surfaceA);
    await seedMetaFor(surfaceB);

    // B holds the canonical (first-scanned) pointer; prune its backup
    // file - the operator-cleaned-the-backup-dir state.
    const first = await findLatestBackup();
    expect(first?.originalPath).toBe(surfaceB);
    await rm(first!.backupPath);

    const exitSpy = vi
      .spyOn(process, "exit")
      .mockImplementation(((code?: number) => {
        throw new Error(`process.exit:${code}`);
      }) as never);
    try {
      // Every run wedges on the same first pointer. Pre-fix, BOTH runs
      // ended on the bare "Backup file not found" line - exit 1 with no
      // mention that surface A remained wrapped behind the wedge, the
      // still-wrapped-surface-hidden output class the eighth-round
      // survivor note closed on the success path.
      for (let run = 0; run < 2; run++) {
        errSpy.mockClear();
        await expect(
          runWrap({ unwrap: true }, makeDeps()),
        ).rejects.toThrow("process.exit:1");
        const out = stderrOutput();
        expect(out).toContain(`Backup file not found: ${first!.backupPath}`);
        // The wedged pointer gets manual remediation advice...
        expect(out).toContain("remove the pointer file manually");
        // ...and the surviving wrapped surface is enumerated with a path
        // forward.
        expect(out).toContain("another wrapped surface remains");
        expect(out).toContain(surfaceA);
        expect(out).toContain("repaired or removed");
        // Nothing was modified: A's pointer is still live.
        expect(await hasExistingWrapMeta(surfaceA)).toBe(true);
      }
    } finally {
      exitSpy.mockRestore();
    }
  });

  it("a re-wrap of a relocated surface preserves its pristine pointer from the scoped slot (F6 across slots) and cleans the stale slot", async () => {
    const surfaceA = join(tmpHome, "surface-slot-a.json");
    const surfaceB = join(tmpHome, "surface-slot-b.json");
    await writeFile(surfaceA, '{"a":"pristine"}');
    await writeFile(surfaceB, '{"b":"pristine"}');

    const pristineA = await backupConfig(surfaceA);
    await saveWrapMeta({
      backupPath: pristineA,
      originalPath: surfaceA,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    });
    // Wrapping B relocates A's canonical meta into A's scoped slot.
    await saveWrapMeta({
      backupPath: await backupConfig(surfaceB),
      originalPath: surfaceB,
      platform: "hermes",
      wrappedAt: new Date().toISOString(),
    });

    // Re-wrap A: the fresh backup captures ALREADY-WRAPPED content, so the
    // F6 preservation must find A's pristine pointer in the scoped slot,
    // and B's canonical meta must be relocated in turn, never clobbered.
    await saveWrapMeta({
      backupPath: await backupConfig(surfaceA),
      originalPath: surfaceA,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    });

    const canonical = JSON.parse(
      await readFile(join(backupDirPath(), "wrap-meta.json"), "utf-8"),
    );
    expect(canonical.originalPath).toBe(surfaceA);
    expect(canonical.backupPath).toBe(pristineA);

    // Exactly ONE scoped slot remains (B's); A's stale slot was cleaned
    // after its content merged back into the canonical file.
    const slots = (await readdir(backupDirPath())).filter((name) =>
      /^wrap-meta-[0-9a-f]{12}\.json$/.test(name),
    );
    expect(slots).toHaveLength(1);
    const relocated = JSON.parse(
      await readFile(join(backupDirPath(), slots[0]!), "utf-8"),
    );
    expect(relocated.originalPath).toBe(surfaceB);
    expect(await hasExistingWrapMeta(surfaceB)).toBe(true);
  });

  // ── Third round: F6 preservation fails CLOSED on an unreadable pointer ──

  it.skipIf(process.getuid?.() === 0)(
    "saveWrapMeta refuses (WrapMetaUnreadableError) instead of clobbering the pointer on a transient read error",
    async () => {
      const configPath = join(tmpHome, "f6-unreadable-config.json");
      await seedMetaFor(configPath);
      const metaPath = join(backupDirPath(), "wrap-meta.json");
      const pristinePointer = await readFile(metaPath, "utf-8");

      await chmod(metaPath, 0o000);
      try {
        // A re-wrap while the meta is unreadable must NOT overwrite the
        // pointer with a fresh backup of already-wrapped content.
        await expect(
          saveWrapMeta({
            backupPath: join(backupDirPath(), "wrapped-content-backup.json"),
            originalPath: configPath,
            platform: "claude-code",
            wrappedAt: new Date().toISOString(),
          }),
        ).rejects.toThrow(WrapMetaUnreadableError);
      } finally {
        await chmod(metaPath, 0o600);
      }
      // The only pointer to the pristine backup survived byte-for-byte.
      expect(await readFile(metaPath, "utf-8")).toBe(pristinePointer);
    },
  );

  it.skipIf(process.getuid?.() === 0)(
    "hasExistingWrapMeta reads false on an unreadable pointer (fails toward the crash-window warning, never suppression)",
    async () => {
      const configPath = join(tmpHome, "unreadable-has-config.json");
      await seedMetaFor(configPath);
      const metaPath = join(backupDirPath(), "wrap-meta.json");

      await chmod(metaPath, 0o000);
      try {
        expect(await hasExistingWrapMeta(configPath)).toBe(false);
      } finally {
        await chmod(metaPath, 0o600);
      }
      expect(await hasExistingWrapMeta(configPath)).toBe(true);
    },
  );

  // ── Fifth round: degraded directory LISTING must not destroy a pointer ──

  it.skipIf(process.getuid?.() === 0)(
    "saveWrapMeta refuses when the backup dir cannot be LISTED instead of deleting a relocated pristine pointer",
    async () => {
      const surfaceA = join(tmpHome, "listing-a.json");
      const surfaceB = join(tmpHome, "listing-b.json");
      await writeFile(surfaceA, '{"a":"pristine"}');
      await writeFile(surfaceB, '{"b":"pristine"}');

      const pristineA = await backupConfig(surfaceA);
      await saveWrapMeta({
        backupPath: pristineA,
        originalPath: surfaceA,
        platform: "claude-code",
        wrappedAt: new Date().toISOString(),
      });
      // Wrapping B relocates A's pointer into its scoped slot (canonical
      // now names B); unwrapping B then retires the canonical pointer, so
      // A's ONLY pointer lives in the scoped slot the directory listing
      // must surface.
      await saveWrapMeta({
        backupPath: await backupConfig(surfaceB),
        originalPath: surfaceB,
        platform: "hermes",
        wrappedAt: new Date().toISOString(),
      });
      expect(await removeWrapMeta(surfaceB)).toEqual([]);
      const slots = (await readdir(backupDirPath())).filter((name) =>
        /^wrap-meta-[0-9a-f]{12}\.json$/.test(name),
      );
      expect(slots).toHaveLength(1);
      const slotPath = join(backupDirPath(), slots[0]!);

      // Write+execute but NOT read on the dir: per-file lookups (reads,
      // creations, unlinks) all still succeed while readdir fails - the
      // degraded state where the scoped slots turn invisible without any
      // per-file read error. Pre-fix, a re-wrap of A here saw "no meta
      // names A", skipped F6 preservation, and its slot-cleanup unlink
      // (which needs no directory read) destroyed A's only pristine
      // pointer.
      await chmod(backupDirPath(), 0o300);
      try {
        const refusal = await saveWrapMeta({
          backupPath: join(backupDirPath(), "already-wrapped-a.json"),
          originalPath: surfaceA,
          platform: "claude-code",
          wrappedAt: new Date().toISOString(),
        }).then(
          () => null,
          (err: unknown) => err,
        );
        expect(refusal).toBeInstanceOf(WrapMetaUnreadableError);
        // Eighth round: the refusal's remediation advice must match the
        // failure class. Here the unreadable path is the backup DIRECTORY
        // itself (it holds every pristine backup and restore pointer), so
        // the default file-oriented "remove it if you are certain it is
        // stale" would aim the operator at the exact asset this refusal
        // protects.
        expect((refusal as Error).message).toContain(
          "Do NOT remove the directory",
        );
        expect((refusal as Error).message).not.toContain(
          "remove it if you are certain",
        );
      } finally {
        await chmod(backupDirPath(), 0o700);
      }

      // A's only pristine pointer survived in its scoped slot.
      const relocated = JSON.parse(await readFile(slotPath, "utf-8"));
      expect(relocated.originalPath).toBe(surfaceA);
      expect(relocated.backupPath).toBe(pristineA);

      // Once the listing works again, the re-wrap preserves it (F6).
      await saveWrapMeta({
        backupPath: await backupConfig(surfaceA),
        originalPath: surfaceA,
        platform: "claude-code",
        wrappedAt: new Date().toISOString(),
      });
      const canonical = JSON.parse(
        await readFile(join(backupDirPath(), "wrap-meta.json"), "utf-8"),
      );
      expect(canonical.originalPath).toBe(surfaceA);
      expect(canonical.backupPath).toBe(pristineA);
    },
  );

  // ── Eighth round: removal consults the scoped slot without a readdir ───

  it.skipIf(process.getuid?.() === 0)(
    "removeWrapMeta retires the restored surface's scoped-slot pointer even when the directory cannot be LISTED",
    async () => {
      const surfaceA = join(tmpHome, "remove-listing-a.json");
      const surfaceB = join(tmpHome, "remove-listing-b.json");
      await writeFile(surfaceA, '{"a":"pristine"}');
      await writeFile(surfaceB, '{"b":"pristine"}');

      // Wrap A, wrap B (relocates A's pointer into its scoped slot), then
      // unwrap B (retires the canonical pointer): A's ONLY pointer now
      // lives in the scoped slot.
      await saveWrapMeta({
        backupPath: await backupConfig(surfaceA),
        originalPath: surfaceA,
        platform: "claude-code",
        wrappedAt: new Date().toISOString(),
      });
      await saveWrapMeta({
        backupPath: await backupConfig(surfaceB),
        originalPath: surfaceB,
        platform: "hermes",
        wrappedAt: new Date().toISOString(),
      });
      expect(await removeWrapMeta(surfaceB)).toEqual([]);
      const slotsBefore = (await readdir(backupDirPath())).filter((name) =>
        /^wrap-meta-[0-9a-f]{12}\.json$/.test(name),
      );
      expect(slotsBefore).toHaveLength(1);

      // Write+execute but NOT read on the dir: per-file lookups (reads,
      // creations, unlinks) still succeed while readdir fails. The lenient
      // listing degrades to the two fixed filenames, so pre-fix the scoped
      // slot was invisible, removeWrapMeta returned [] (clean success),
      // and the stale pointer survived - a LATER --unwrap would silently
      // re-restore ancient content over post-unwrap operator edits. The
      // scoped filename is derivable from the restored path alone, so the
      // deterministic candidate retires it with no readdir at all.
      await chmod(backupDirPath(), 0o300);
      try {
        expect(await removeWrapMeta(surfaceA)).toEqual([]);
      } finally {
        await chmod(backupDirPath(), 0o700);
      }
      const slotsAfter = (await readdir(backupDirPath())).filter((name) =>
        /^wrap-meta-[0-9a-f]{12}\.json$/.test(name),
      );
      expect(slotsAfter).toEqual([]);
      // No pointer of any kind survives: a later --unwrap finds nothing.
      expect(await findLatestBackup()).toBeNull();
    },
  );

  it.skipIf(process.getuid?.() === 0)(
    "unwrap refuses instead of reporting no wrap when scoped pointers cannot be listed",
    async () => {
      const surfaceA = join(tmpHome, "hidden-listing-a.json");
      const surfaceB = join(tmpHome, "hidden-listing-b.json");
      await writeFile(surfaceA, '{"a":"pristine"}');
      await writeFile(surfaceB, '{"b":"pristine"}');

      // Wrap A, then B. B is canonical; A is relocated into a scoped slot.
      await saveWrapMeta({
        backupPath: await backupConfig(surfaceA),
        originalPath: surfaceA,
        platform: "claude-code",
        wrappedAt: new Date().toISOString(),
      });
      await saveWrapMeta({
        backupPath: await backupConfig(surfaceB),
        originalPath: surfaceB,
        platform: "hermes",
        wrappedAt: new Date().toISOString(),
      });
      expect(await removeWrapMeta(surfaceB)).toEqual([]);

      // A's only pointer is now a scoped filename. If the directory cannot be
      // listed, unwrap must fail closed instead of treating the hidden slot as
      // absent and printing "No Sanctuary wrap found".
      const exitSpy = vi
        .spyOn(process, "exit")
        .mockImplementation(((code?: number) => {
          throw new Error(`process.exit:${code}`);
        }) as never);
      await chmod(backupDirPath(), 0o300);
      try {
        errSpy.mockClear();
        await expect(runWrap({ unwrap: true }, makeDeps())).rejects.toThrow(
          "process.exit:1",
        );
        const out = stderrOutput();
        expect(out).toContain("Sanctuary: Unwrap REFUSED");
        expect(out).toContain(
          "surface-scoped wrap-meta slots could not be enumerated",
        );
        expect(out).not.toContain("No Sanctuary wrap found");
      } finally {
        await chmod(backupDirPath(), 0o700);
        exitSpy.mockRestore();
      }

      expect(await hasExistingWrapMeta(surfaceA)).toBe(true);
      expect(await hasExistingWrapMeta(surfaceB)).toBe(false);
    },
  );

  // ── Fifth round: cross-process wrap-meta lock ──────────────────────────

  it("concurrent saveWrapMeta calls for different surfaces serialize; neither pointer is orphaned", async () => {
    const surfaceA = join(tmpHome, "race-a.json");
    const surfaceB = join(tmpHome, "race-b.json");
    await writeFile(surfaceA, '{"a":"pristine"}');
    await writeFile(surfaceB, '{"b":"pristine"}');
    const backupA = await backupConfig(surfaceA);
    const backupB = await backupConfig(surfaceB);

    // Pre-lock, both writers could read the canonical slot before either
    // wrote, so the loser overwrote the winner's pointer WITHOUT relocating
    // it. With the advisory lock, the interleaving is serialized and both
    // surfaces keep a live pointer.
    await Promise.all([
      saveWrapMeta({
        backupPath: backupA,
        originalPath: surfaceA,
        platform: "claude-code",
        wrappedAt: new Date().toISOString(),
      }),
      saveWrapMeta({
        backupPath: backupB,
        originalPath: surfaceB,
        platform: "hermes",
        wrappedAt: new Date().toISOString(),
      }),
    ]);

    expect(await hasExistingWrapMeta(surfaceA)).toBe(true);
    expect(await hasExistingWrapMeta(surfaceB)).toBe(true);
    // The lock file itself never lingers after release.
    await expect(
      access(join(backupDirPath(), "wrap-meta.lock")),
    ).rejects.toThrow();
  });

  it("a persisting STALE lock (crashed holder) is NEVER auto-broken: the bounded deadline expires into a fail-closed refusal with manual recovery advice", async () => {
    // Thirteenth round (chokepoint rule): rounds 5-12 auto-broke a stale
    // lock (stale-age detection, rename-then-verify, link()-restore), and
    // every round found a narrower residual race in the break dance. The
    // machinery is deleted: a lock file that persists past the bounded
    // wait - whatever left it there - expires into an explicit refusal
    // that names the lock path and the operator's exact recovery step.
    // This test doubles as the bounded-deadline pin: with the wait
    // shortened via the seam, the refusal arrives instead of an
    // indefinite wedge.
    const configPath = join(tmpHome, "stale-lock-config.json");
    await writeFile(configPath, "{}");
    const backup = await backupConfig(configPath);

    const lockPath = join(backupDirPath(), "wrap-meta.lock");
    await writeFile(lockPath, "999999\n");
    // A crashed holder's leftover: minutes old, no live process behind it.
    const past = new Date(Date.now() - 10 * 60_000);
    await utimes(lockPath, past, past);

    __wrapMetaLockTestHooks.waitMs = 250;
    let refusal: Error | null = null;
    try {
      await saveWrapMeta({
        backupPath: backup,
        originalPath: configPath,
        platform: "claude-code",
        wrappedAt: new Date().toISOString(),
      });
    } catch (err) {
      refusal = err as Error;
    } finally {
      delete __wrapMetaLockTestHooks.waitMs;
    }

    // Fail closed, with the full operator runbook in the message: the
    // lock path, the two possible causes, and the manual step.
    expect(refusal).not.toBeNull();
    expect(refusal!.message).toContain(lockPath);
    expect(refusal!.message).toContain("wrap-meta lock is held");
    expect(refusal!.message).toContain(
      "Verify no sanctuary wrap/unwrap process is running",
    );
    expect(refusal!.message).toContain(`remove ${lockPath} and re-run`);

    // Nothing was mutated, and the lock file this process did NOT create
    // was never unlinked or renamed (byte-identical survivor).
    expect(await hasExistingWrapMeta(configPath)).toBe(false);
    expect(await readFile(lockPath, "utf-8")).toBe("999999\n");

    // The operator's documented manual step unwedges the tenant.
    await unlink(lockPath);
    await saveWrapMeta({
      backupPath: backup,
      originalPath: configPath,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    });
    expect(await hasExistingWrapMeta(configPath)).toBe(true);
  });

  it("TWO waiters behind the same stale lock BOTH refuse fail-closed; neither breaks the lock and nothing is written", async () => {
    // Round 5-12 behavior was "one waiter breaks the stale lock, both
    // serialize through". Round 13 converts the pin: with the auto-break
    // deleted, BOTH waiters expire into the manual-recovery refusal, the
    // stale lock survives untouched, and no pointer is written - strictly
    // fail-closed, never unserialized.
    const surfaceA = join(tmpHome, "stale-race-a.json");
    const surfaceB = join(tmpHome, "stale-race-b.json");
    await writeFile(surfaceA, '{"a":"pristine"}');
    await writeFile(surfaceB, '{"b":"pristine"}');
    const backupA = await backupConfig(surfaceA);
    const backupB = await backupConfig(surfaceB);

    const lockPath = join(backupDirPath(), "wrap-meta.lock");
    await writeFile(lockPath, "999999\n");
    const past = new Date(Date.now() - 10 * 60_000);
    await utimes(lockPath, past, past);

    __wrapMetaLockTestHooks.waitMs = 250;
    let outcomes: PromiseSettledResult<void>[];
    try {
      outcomes = await Promise.allSettled([
        saveWrapMeta({
          backupPath: backupA,
          originalPath: surfaceA,
          platform: "claude-code",
          wrappedAt: new Date().toISOString(),
        }),
        saveWrapMeta({
          backupPath: backupB,
          originalPath: surfaceB,
          platform: "hermes",
          wrappedAt: new Date().toISOString(),
        }),
      ]);
    } finally {
      delete __wrapMetaLockTestHooks.waitMs;
    }

    for (const outcome of outcomes) {
      expect(outcome.status).toBe("rejected");
      expect(
        ((outcome as PromiseRejectedResult).reason as Error).message,
      ).toContain("wrap-meta lock is held");
    }
    // No pointer was written, the stale lock survived untouched, and no
    // break-name residue exists (there is no break machinery to leave any).
    expect(await hasExistingWrapMeta(surfaceA)).toBe(false);
    expect(await hasExistingWrapMeta(surfaceB)).toBe(false);
    const residue = (await readdir(backupDirPath())).filter((entry) =>
      entry.includes("wrap-meta.lock"),
    );
    expect(residue).toEqual(["wrap-meta.lock"]);
    expect(await readFile(lockPath, "utf-8")).toBe("999999\n");
    await unlink(lockPath);
  });

  it("a LIVE holder's lock is never touched by a waiter: the waiter waits, then acquires and completes after the holder releases", async () => {
    // Converts the former stale-break TOCTOU pin (a fresh lock substituted
    // inside the stat-to-break window had to survive the verified break).
    // Round 13 makes the property unconditional: there is no code path
    // that unlinks or renames a lock this process did not create, so a
    // live holder's lock survives by construction and the waiter honors
    // it until the holder releases.
    const configPath = join(tmpHome, "live-lock-config.json");
    await writeFile(configPath, "{}");
    const backup = await backupConfig(configPath);

    const lockPath = join(backupDirPath(), "wrap-meta.lock");
    await writeFile(lockPath, "live-holder\n");

    let saveSettled = false;
    const savePromise = saveWrapMeta({
      backupPath: backup,
      originalPath: configPath,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    }).then(() => {
      saveSettled = true;
    });

    // Many retry rounds (cadence 50ms): the live lock must survive them
    // all, byte-identical, with the waiter still pending and nothing
    // written.
    await new Promise((resolveSleep) => setTimeout(resolveSleep, 400));
    expect(await readFile(lockPath, "utf-8")).toBe("live-holder\n");
    expect(saveSettled).toBe(false);
    expect(await hasExistingWrapMeta(configPath)).toBe(false);

    // The live holder releases; the waiter acquires and completes.
    await unlink(lockPath);
    await savePromise;

    expect(await hasExistingWrapMeta(configPath)).toBe(true);
    const residue = (await readdir(backupDirPath())).filter((entry) =>
      entry.includes("wrap-meta.lock"),
    );
    expect(residue).toEqual([]);
  });

  it("displaced holder fails CLOSED: a save whose lock was removed out from under it mid-section refuses to write and does not evict its successor's lock", async () => {
    // Eighth round pinned the verified RELEASE (no successor eviction);
    // ninth round pins the fail-closed MUTATION guard; round 13 keeps
    // both. With the auto-break deleted, the displaced state arises from
    // the operator's documented manual recovery step: a holder stalls
    // inside the critical section (sleep/suspend, a long hang), the
    // operator judges it crashed and removes the lock, and a SUCCESSOR
    // acquires; the stalled holder then finishes fn() and would clobber
    // the pointer the successor just wrote. The assertLockHeld gate
    // before every destructive write must refuse instead, and the release
    // must still leave the successor's lock alone. Inject exactly that
    // state via the onLockAcquired seam: the holder's own lock is
    // replaced by a successor's before fn() runs.
    const configPath = join(tmpHome, "release-verify-config.json");
    await writeFile(configPath, "{}");
    const backup = await backupConfig(configPath);
    const lockPath = join(backupDirPath(), "wrap-meta.lock");

    let fired = false;
    __wrapMetaLockTestHooks.onLockAcquired = async (lock) => {
      if (fired) return;
      fired = true;
      await unlink(lock);
      await writeFile(lock, "successor-holder\n");
      // Force a distinct mtime so the identity check cannot collide with
      // the holder's capture even under inode reuse + same-millisecond
      // timestamps on a fast filesystem.
      const past = new Date(Date.now() - 5_000);
      await utimes(lock, past, past);
    };
    try {
      await expect(
        saveWrapMeta({
          backupPath: backup,
          originalPath: configPath,
          platform: "claude-code",
          wrappedAt: new Date().toISOString(),
        }),
      ).rejects.toThrow(/wrap-meta lock/);
    } finally {
      delete __wrapMetaLockTestHooks.onLockAcquired;
    }

    // The displaced holder wrote NOTHING (fail closed, no concurrent
    // mutator), and the successor's lock survived its release.
    expect(fired).toBe(true);
    expect(await hasExistingWrapMeta(configPath)).toBe(false);
    expect(await readFile(lockPath, "utf-8")).toBe("successor-holder\n");
    // Clean up the injected successor lock so later tests contend fresh.
    await unlink(lockPath);
  });

  it("displaced holder fails CLOSED on the unwrap side: removeWrapMeta refuses to retire pointers after its lock vanished mid-section", async () => {
    // Same ninth-round guard, remove path + the lock-vanished (ENOENT)
    // branch: the operator's manual lock removal against a stalled holder
    // leaves that holder's lock with no name at all. The holder must
    // detect the vanished lock before its first unlink and refuse,
    // leaving every pointer in place for the operator's re-run.
    const configPath = join(tmpHome, "remove-displaced-config.json");
    await writeFile(configPath, "{}");
    const backup = await backupConfig(configPath);
    await saveWrapMeta({
      backupPath: backup,
      originalPath: configPath,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    });
    expect(await hasExistingWrapMeta(configPath)).toBe(true);

    let fired = false;
    __wrapMetaLockTestHooks.onLockAcquired = async (lock) => {
      if (fired) return;
      fired = true;
      await unlink(lock);
    };
    try {
      await expect(removeWrapMeta(configPath)).rejects.toThrow(
        /wrap-meta lock/,
      );
    } finally {
      delete __wrapMetaLockTestHooks.onLockAcquired;
    }

    expect(fired).toBe(true);
    // Nothing was retired after the lock was lost; the pointer survives
    // and a later (serialized) unwrap can still find it.
    expect(await hasExistingWrapMeta(configPath)).toBe(true);
  });

  it("fourteenth round: when post-write identity capture fails, the release fails CLOSED (leaves the lock file) instead of an unconditional unlink", async () => {
    // Closes a round-13 overclaim: the release used to fall back to an
    // UNCONDITIONAL unlink whenever `acquired` was undefined at release
    // time, which this holder can also reach via a failed post-write
    // fstat (not just the ENOSPC-class create failure below, which
    // rethrows before ever entering the critical section). That fallback
    // could evict a live SUCCESSOR's lock if the operator manually removed
    // this holder's lock mid-section and another wrap/unwrap acquired
    // meanwhile - exactly the property this release exists to prevent.
    // The fix: skip the unlink entirely when identity was never captured,
    // leaving the file for the operator's manual-break runbook, same as an
    // ordinary crash would.
    const configPath = join(tmpHome, "stat-fail-config.json");
    await writeFile(configPath, "{}");
    const backup = await backupConfig(configPath);
    const lockPath = join(backupDirPath(), "wrap-meta.lock");

    errSpy.mockClear();
    __wrapMetaLockTestHooks.failStatAfterWrite = true;
    try {
      await saveWrapMeta({
        backupPath: backup,
        originalPath: configPath,
        platform: "claude-code",
        wrappedAt: new Date().toISOString(),
      });
    } finally {
      delete __wrapMetaLockTestHooks.failStatAfterWrite;
    }
    // The mutation itself still succeeded (identity loss degrades
    // assertLockHeld to a no-op, matching the release's degradation).
    expect(await hasExistingWrapMeta(configPath)).toBe(true);
    // The lock file was NOT unlinked: the release failed closed rather
    // than falling back to the old unconditional unlink.
    await expect(access(lockPath)).resolves.toBeUndefined();
    // Round 15: the run that orphaned the lock prints a contemporaneous
    // warning naming the lock path, so the operator learns of the wedge
    // from THIS run rather than only from the next run's refusal.
    expect(stderrOutput()).toContain(lockPath);
    expect(stderrOutput()).toMatch(/wrap-meta lock/);

    // Clean up the surviving lock (the operator's manual-break step) so
    // later tests in this file are not affected by lock-directory state.
    await unlink(lockPath);
  });

  it("a failed acquisition AFTER the O_EXCL create (ENOSPC-class) removes the just-created lock instead of leaking it", async () => {
    // The acquisition can fail after the lock file was created: the pid
    // write (ENOSPC, EIO) or the close() itself - both land in the same
    // single post-create catch that owns the cleanup, so this one seam
    // covers the whole class. Rethrowing with the lock left on disk would
    // wedge every later wrap/unwrap on the tenant into the false
    // manual-removal refusal while nothing else was running.
    const configPath = join(tmpHome, "enospc-config.json");
    await writeFile(configPath, "{}");
    const backup = await backupConfig(configPath);
    const lockPath = join(backupDirPath(), "wrap-meta.lock");

    let fired = false;
    __wrapMetaLockTestHooks.onLockCreated = async () => {
      if (fired) return;
      fired = true;
      const err = new Error(
        "ENOSPC: no space left on device, write",
      ) as NodeJS.ErrnoException;
      err.code = "ENOSPC";
      throw err;
    };
    try {
      await expect(
        saveWrapMeta({
          backupPath: backup,
          originalPath: configPath,
          platform: "claude-code",
          wrappedAt: new Date().toISOString(),
        }),
      ).rejects.toThrow(/ENOSPC/);
    } finally {
      delete __wrapMetaLockTestHooks.onLockCreated;
    }
    expect(fired).toBe(true);
    // The just-created lock did NOT leak...
    await expect(access(lockPath)).rejects.toThrow();
    // ...so the next mutation acquires immediately (a leaked lock would
    // stall it into the 15s fail-closed timeout) and completes.
    await saveWrapMeta({
      backupPath: backup,
      originalPath: configPath,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    });
    expect(await hasExistingWrapMeta(configPath)).toBe(true);
  });

  it("an unwrap whose meta retirement THROWS keeps the honest wrap voice: retirement WARNING + re-run advice + exit code 1, never an uncaught crash", async () => {
    // removeWrapMeta's lock acquisition is bounded + fail-closed and can
    // now THROW (lock-wait timeout, displaced-holder refusal). Pre-fix the
    // throw escaped unwrap() to the CLI's top-level catch, which printed
    // "Sanctuary MCP Server failed to start:" plus a raw error AFTER the
    // "Sanctuary: Unwrapped" success lines - a server-boot banner for a
    // wrap subcommand whose restore had already succeeded.
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));
    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());

    errSpy.mockClear();
    const originalExitCode = process.exitCode;
    let exitCodeAfter: typeof process.exitCode;
    let fired = false;
    __wrapMetaLockTestHooks.onLockAcquired = async (lock) => {
      if (fired) return;
      fired = true;
      // Displaced holder: the retirement's assertLockHeld gate throws.
      await unlink(lock);
    };
    try {
      // Must RESOLVE (the throw is handled in the unwrap flow), not reject
      // into the top-level server-boot catch.
      await runWrap({ unwrap: true }, makeDeps());
      exitCodeAfter = process.exitCode;
    } finally {
      delete __wrapMetaLockTestHooks.onLockAcquired;
      process.exitCode = originalExitCode;
    }
    expect(fired).toBe(true);

    const out = stderrOutput();
    // The restore genuinely succeeded and still says so...
    expect(out).toContain("Sanctuary: Unwrapped");
    expect(await readFile(settingsPath, "utf-8")).toBe(
      JSON.stringify({ mcpServers: {} }, null, 2),
    );
    // ...and the retirement failure is reported in the retirement-warning
    // voice with re-run advice, exiting non-zero without the misleading
    // server-boot banner.
    expect(out).toContain("WARNING: could not retire the wrap metadata");
    expect(out).toContain("wrap metadata was left in place");
    expect(out).not.toContain("failed to start");
    expect(exitCodeAfter).toBe(1);
    // The meta survives, so a re-run can retire it.
    expect(await hasExistingWrapMeta(settingsPath)).toBe(true);
  });

  it("a successful unwrap prints the survivor note when another wrapped surface remains (success-path multi-surface honesty)", async () => {
    // Eighth-round behavior, pinned in round 13 (the refusal-path twin is
    // the wedged-pointer test above): with surface-scoped meta slots, one
    // --unwrap run restores exactly ONE surface. Ending on an unqualified
    // "Unwrapped" while another surface still routes traffic through
    // Sanctuary is the dead-entry-behind-a-success-banner class, so the
    // clean-retirement path must enumerate the survivor and the re-run
    // step.
    const surfaceA = join(tmpHome, "survivor-surface-a.json");
    const surfaceB = join(tmpHome, "survivor-surface-b.json");
    await seedMetaFor(surfaceA);
    await seedMetaFor(surfaceB);
    // B holds the canonical (first-scanned) pointer; A's pointer was
    // relocated into its scoped slot by B's save.

    errSpy.mockClear();
    await runWrap({ unwrap: true }, makeDeps());
    const out = stderrOutput();

    // The restore itself succeeded and says so...
    expect(out).toContain("Sanctuary: Unwrapped");
    expect(out).toContain(`Original config restored to: ${surfaceB}`);
    // ...and the survivor note names the remaining wrapped surface with
    // the path forward.
    expect(out).toContain(`another wrapped surface remains (${surfaceA})`);
    expect(out).toContain("Re-run 'sanctuary wrap --unwrap' to restore it.");

    // A's pointer is still live, so the advertised re-run works.
    expect(await hasExistingWrapMeta(surfaceA)).toBe(true);
    expect(await hasExistingWrapMeta(surfaceB)).toBe(false);
    errSpy.mockClear();
    await runWrap({ unwrap: true }, makeDeps());
    expect(stderrOutput()).toContain(
      `Original config restored to: ${surfaceA}`,
    );
    expect(await hasExistingWrapMeta(surfaceA)).toBe(false);
  });

  // ── Findings 3 + 4: orphan guard on all rollbacks, crash-window scope ──

  it.skipIf(process.getuid?.() === 0)(
    "a failed rollback on the REWRITE failure path writes the fallback meta (orphan-wrap guard beyond the meta-write site)",
    async () => {
      const settingsDir = join(tmpHome, ".claude");
      await mkdir(settingsDir, { recursive: true });
      const settingsPath = join(settingsDir, "settings.json");
      const pristine = JSON.stringify({ mcpServers: {} }, null, 2);
      await writeFile(settingsPath, pristine);

      const exitSpy = vi
        .spyOn(process, "exit")
        .mockImplementation((code?: string | number | null) => {
          throw new Error(`process.exit:${code}`);
        });
      try {
        await expect(
          runWrap(
            { claudeCode: true, noOpen: true },
            makeDeps({
              rewriteConfig: async () => {
                // Corrupt the live config, make the rollback restore fail
                // (read-only target), then die: the exact shape that used
                // to end wrapped/corrupt with NO meta on disk.
                await writeFile(settingsPath, "corrupted {{{");
                await chmod(settingsPath, 0o400);
                throw new Error("EIO: simulated mid-write failure");
              },
            }),
          ),
        ).rejects.toThrow("process.exit:1");
      } finally {
        exitSpy.mockRestore();
      }

      // The guard wrote the fallback meta so --unwrap can find the wrap.
      const meta = await findLatestBackup();
      expect(meta?.originalPath).toBe(settingsPath);
      expect(await readFile(meta!.backupPath, "utf-8")).toBe(pristine);
      expect(stderrOutput()).toContain(
        "Wrap metadata was written after the failed restore",
      );
    },
  );

  it.skipIf(process.getuid?.() === 0)(
    "a failed rollback on the VERIFY failure path writes the fallback meta (restoredOnFailure plumbing)",
    async () => {
      const settingsDir = join(tmpHome, ".claude");
      await mkdir(settingsDir, { recursive: true });
      const settingsPath = join(settingsDir, "settings.json");
      const pristine = JSON.stringify({ mcpServers: {} }, null, 2);
      await writeFile(settingsPath, pristine);

      const exitSpy = vi
        .spyOn(process, "exit")
        .mockImplementation((code?: string | number | null) => {
          throw new Error(`process.exit:${code}`);
        });
      try {
        await expect(
          runWrap(
            { claudeCode: true, noOpen: true },
            makeDeps({
              rewriteConfig: async () => {
                // Rewrite "succeeds" but leaves invalid JSON behind and a
                // read-only target, so post-rewrite VERIFICATION fails and
                // its internal rollback restore ALSO fails. An inverted or
                // dropped restoredOnFailure boolean would skip the guard
                // and end wrapped/corrupt with NO meta on disk.
                await writeFile(settingsPath, "corrupted {{{");
                await chmod(settingsPath, 0o400);
              },
            }),
          ),
        ).rejects.toThrow("process.exit:1");
      } finally {
        exitSpy.mockRestore();
      }

      const meta = await findLatestBackup();
      expect(meta?.originalPath).toBe(settingsPath);
      expect(await readFile(meta!.backupPath, "utf-8")).toBe(pristine);
      expect(stderrOutput()).toContain(
        "Wrap metadata was written after the failed restore",
      );
    },
  );

  it.skipIf(process.getuid?.() === 0)(
    "a failed rollback on the Hermes-YAML write-failure path writes the fallback meta (aux entry included)",
    async () => {
      const hermesDir = join(tmpHome, ".hermes");
      await mkdir(hermesDir, { recursive: true });
      const jsonPath = join(hermesDir, "cli-config.json");
      const yamlPath = join(hermesDir, "config.yaml");
      await writeFile(jsonPath, "{}");
      // Pre-existing, readable-but-unwritable config.yaml: the plan
      // computes fine, the backup reads fine, then the YAML write fails
      // (EACCES) and rollbackWrapSurfaces' restore of the same read-only
      // file fails too — the exact double failure the guard exists for.
      const pristineYaml = "mcp_servers: {}\n";
      await writeFile(yamlPath, pristineYaml);
      await chmod(yamlPath, 0o400);

      const exitSpy = vi
        .spyOn(process, "exit")
        .mockImplementation((code?: string | number | null) => {
          throw new Error(`process.exit:${code}`);
        });
      try {
        await expect(
          runWrap({ hermes: true, noOpen: true }, makeDeps()),
        ).rejects.toThrow("process.exit:1");
      } finally {
        exitSpy.mockRestore();
        await chmod(yamlPath, 0o600);
      }

      // The guard wrote the fallback meta, INCLUDING the auxiliary pointer
      // at the yaml surface's pre-wrap backup, so --unwrap can find both.
      const meta = await findLatestBackup();
      expect(meta?.originalPath).toBe(jsonPath);
      expect(meta?.auxiliary).toHaveLength(1);
      expect(meta!.auxiliary![0]!.originalPath).toBe(yamlPath);
      expect(
        await readFile(meta!.auxiliary![0]!.backupPath as string, "utf-8"),
      ).toBe(pristineYaml);
      expect(stderrOutput()).toContain(
        "Wrap metadata was written after the failed restore",
      );
    },
  );

  it("crash-window warning fires for surface X even when surface Y's wrap-meta exists (MED-2 residual)", async () => {
    // Surface Y: some other config with a live wrap-meta.
    await seedMetaFor(join(tmpHome, "surface-y.json"));

    // Surface X: crash-window state — the config already carries the
    // sanctuary entry but no meta points at X.
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(
      settingsPath,
      JSON.stringify(
        { mcpServers: { sanctuary: { command: "npx", args: ["-y"] } } },
        null,
        2,
      ),
    );

    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());
    // Pre-fix, the tenant-global hasExistingWrapMeta saw Y's meta and
    // suppressed this warning.
    expect(stderrOutput()).toContain(CRASH_WINDOW_MARKER);
  });

  it("crash-window warning does NOT fire on a normal re-wrap (this surface's own meta exists)", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));

    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());
    errSpy.mockClear();
    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());
    expect(stderrOutput()).not.toContain(CRASH_WINDOW_MARKER);
  });

  // ── Finding 5: branded protection-state claim gate ─────────────────

  it("the success banner renders green only for the exclusive protection claim", () => {
    const base = {
      toolName: "Claude Code",
      version: "9.9.9",
      toolCount: 3,
      serverCount: 2,
      dashboardUrl: "http://127.0.0.1:3501",
      browserOpened: false,
      passphraseLocation: "test-keychain",
      passphraseSource: "generated",
      castleWallProtectionClaim: claim("unknown"),
    };
    expect(
      formatWrapSuccess({
        ...base,
        castleWallProtectionClaim: claim("exclusive"),
      }),
    ).toContain("Your agent is protected");
    for (const state of ["coarse-only", "unprotected", "unknown"] as const) {
      const out = formatWrapSuccess({
        ...base,
        castleWallProtectionClaim: claim(state),
      });
      expect(out).not.toContain("Your agent is protected");
      expect(out).not.toContain("Castle Wall Full");
    }
  });

  // ── Finding 6: wrap-time pinned-version resolvability ───────────────

  describe("checkPinnedVersionResolvable", () => {
    let server: Server | undefined;
    let savedNoUpdateKnob: string | undefined;
    let savedUpdateKnob: string | undefined;

    beforeEach(() => {
      // Zero-outbound-by-default (2026-07-05): the suite-wide vitest env sets
      // the back-compat alias knob (SANCTUARY_NO_UPDATE_CHECK), which alone
      // now forces the probe off regardless of the opt-in var. These tests
      // exercise the probe itself against a loopback server, so they must
      // both clear the alias AND set the opt-in var to actually arm the
      // probe under the new default.
      savedNoUpdateKnob = process.env.SANCTUARY_NO_UPDATE_CHECK;
      savedUpdateKnob = process.env.SANCTUARY_UPDATE_CHECK;
      delete process.env.SANCTUARY_NO_UPDATE_CHECK;
      process.env.SANCTUARY_UPDATE_CHECK = "1";
    });

    afterEach(async () => {
      if (savedNoUpdateKnob !== undefined)
        process.env.SANCTUARY_NO_UPDATE_CHECK = savedNoUpdateKnob;
      else delete process.env.SANCTUARY_NO_UPDATE_CHECK;
      if (savedUpdateKnob !== undefined)
        process.env.SANCTUARY_UPDATE_CHECK = savedUpdateKnob;
      else delete process.env.SANCTUARY_UPDATE_CHECK;
      if (server) {
        await new Promise<void>((resolve) => server!.close(() => resolve()));
        server = undefined;
      }
    });

    async function startRegistryStub(statusCode: number): Promise<string> {
      server = createServer((_req, res) => {
        res.statusCode = statusCode;
        res.end(statusCode === 200 ? '{"version":"9.9.9"}' : "{}");
      });
      await new Promise<void>((resolve) =>
        server!.listen(0, "127.0.0.1", () => resolve()),
      );
      const { port } = server!.address() as AddressInfo;
      return `http://127.0.0.1:${port}`;
    }

    it("a registry that serves the version reads resolvable", async () => {
      const base = await startRegistryStub(200);
      expect(
        await checkPinnedVersionResolvable("9.9.9", { registryBaseUrl: base }),
      ).toBe("resolvable");
    });

    it("an affirmative registry 404 reads unpublished", async () => {
      const base = await startRegistryStub(404);
      expect(
        await checkPinnedVersionResolvable("9.9.9", { registryBaseUrl: base }),
      ).toBe("unpublished");
    });

    it("a connection failure reads unreachable (honest-unknown), never resolvable", async () => {
      // Bind a port, then close it so nothing listens there.
      const probe = createServer();
      await new Promise<void>((resolve) =>
        probe.listen(0, "127.0.0.1", () => resolve()),
      );
      const { port } = probe.address() as AddressInfo;
      await new Promise<void>((resolve) => probe.close(() => resolve()));
      expect(
        await checkPinnedVersionResolvable("9.9.9", {
          registryBaseUrl: `http://127.0.0.1:${port}`,
          timeoutMs: 500,
        }),
      ).toBe("unreachable");
    });

    it("fourteenth round: a responder that trickles the HTTP status line one byte at a time keeps resetting the inactivity timer forever, but the probe still resolves within a bounded wall-clock deadline", async () => {
      // The `timeout` request option is a socket INACTIVITY timer: Node
      // resets it on every byte received, so req.on("timeout") only fires
      // after a gap with NO bytes. A tarpit / misbehaving proxy that
      // dribbles one byte on an interval shorter than the timeout, forever,
      // keeps re-arming that timer and the inactivity timeout never fires -
      // stalling the probe indefinitely and contradicting the documented
      // "never blocks the wrap" contract. Simulate that honestly: emit
      // "HTTP/1.1 200 " (a valid, syntactically INCOMPLETE status-line
      // prefix - no terminating \r\n yet) and then dribble additional
      // spaces forever, which stay valid inside an arbitrarily long reason
      // phrase without ever completing the line or desyncing the HTTP
      // parser (a raw byte like "H" instead would trip a parse-error
      // req.on("error") almost immediately, which is a DIFFERENT code path
      // and would not exercise the inactivity-timer gap this test targets).
      // Only a hard wall-clock deadline - not the inactivity timer, which
      // every tick keeps "fed" - can end this probe within a bounded time.
      const timeoutMs = 200;
      const statusPrefix = "HTTP/1.1 200 ";
      const drip = createServer();
      const dripIntervals: ReturnType<typeof setInterval>[] = [];
      drip.on("connection", (socket) => {
        let i = 0;
        const tickMs = Math.max(10, Math.floor(timeoutMs / 4));
        const interval = setInterval(() => {
          if (socket.destroyed) return;
          const byte = i < statusPrefix.length ? statusPrefix[i] : " ";
          socket.write(byte);
          i++;
        }, tickMs);
        dripIntervals.push(interval);
        socket.on("close", () => clearInterval(interval));
      });
      await new Promise<void>((resolve) =>
        drip.listen(0, "127.0.0.1", () => resolve()),
      );
      const { port } = drip.address() as AddressInfo;
      try {
        const started = Date.now();
        const result = await checkPinnedVersionResolvable("9.9.9", {
          registryBaseUrl: `http://127.0.0.1:${port}`,
          timeoutMs,
        });
        const elapsedMs = Date.now() - started;
        expect(result).toBe("unreachable");
        // Without a wall-clock deadline this drip runs forever (each tick
        // re-arms the inactivity timer indefinitely); a fixed deadline must
        // resolve near the single timeoutMs window instead. Generous slack
        // for CI scheduling jitter, still far short of "runs forever".
        expect(elapsedMs).toBeLessThan(timeoutMs * 6);
      } finally {
        for (const interval of dripIntervals) clearInterval(interval);
        await new Promise<void>((resolve) => drip.close(() => resolve()));
      }
    });

    it("sixteenth round: a responder that sends status+headers promptly then dribbles the body forever does not leak an open socket past settle", async () => {
      // Round 14 closed the PRE-settle tarpit window (a slow STATUS line).
      // This closes the POST-settle window: once status is consulted the
      // function only needs to decide resolvable/unreachable, but the
      // production code used to only res.resume()-drain the body instead
      // of destroying the request. A drained-but-open socket still has
      // Node's per-byte inactivity timer backing it, so a responder that
      // completes headers/status immediately and then dribbles the BODY
      // one byte at a time forever keeps that socket - and the process
      // event loop - alive indefinitely even though the promise already
      // resolved. Assert directly on the socket instead of only on timing:
      // the promise resolving fast was never the bug, the leaked handle
      // was.
      const dripIntervals: ReturnType<typeof setInterval>[] = [];
      const sockets: import("node:net").Socket[] = [];
      const drip = createServer((_req, res) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.write("{");
        const interval = setInterval(() => {
          if (res.destroyed) return;
          res.write(" ");
        }, 20);
        dripIntervals.push(interval);
        res.socket?.on("close", () => clearInterval(interval));
      });
      drip.on("connection", (socket) => sockets.push(socket));
      await new Promise<void>((resolve) =>
        drip.listen(0, "127.0.0.1", () => resolve()),
      );
      const { port } = drip.address() as AddressInfo;
      try {
        const result = await checkPinnedVersionResolvable("9.9.9", {
          registryBaseUrl: `http://127.0.0.1:${port}`,
          timeoutMs: 2000,
        });
        expect(result).toBe("resolvable");
        // The server-side socket for this request must observe the client
        // tearing down its end once settle() has decided the outcome, not
        // merely draining - otherwise the still-dribbling body keeps
        // resetting the client socket's inactivity timer and the handle
        // (and the event loop) never frees.
        await new Promise((r) => setTimeout(r, 50));
        expect(sockets.length).toBeGreaterThan(0);
        for (const socket of sockets) {
          expect(socket.destroyed || socket.readyState === "closed").toBe(
            true,
          );
        }
      } finally {
        for (const interval of dripIntervals) clearInterval(interval);
        await new Promise<void>((resolve) => drip.close(() => resolve()));
      }
    });

    it("SANCTUARY_NO_UPDATE_CHECK=1 skips the probe entirely (zero outbound)", async () => {
      process.env.SANCTUARY_NO_UPDATE_CHECK = "1";
      expect(
        await checkPinnedVersionResolvable("9.9.9", {
          registryBaseUrl: "http://127.0.0.1:1",
        }),
      ).toBe("skipped");
    });

    it("zero-outbound-by-default: skips the probe when neither env var is set", async () => {
      delete process.env.SANCTUARY_NO_UPDATE_CHECK;
      delete process.env.SANCTUARY_UPDATE_CHECK;
      expect(
        await checkPinnedVersionResolvable("9.9.9", {
          registryBaseUrl: "http://127.0.0.1:1",
        }),
      ).toBe("skipped");
    });

    it("SANCTUARY_NO_UPDATE_CHECK=1 wins even when SANCTUARY_UPDATE_CHECK=1 is also set (alias cannot be overridden)", async () => {
      process.env.SANCTUARY_UPDATE_CHECK = "1";
      process.env.SANCTUARY_NO_UPDATE_CHECK = "1";
      expect(
        await checkPinnedVersionResolvable("9.9.9", {
          registryBaseUrl: "http://127.0.0.1:1",
        }),
      ).toBe("skipped");
    });

    // ── Third round: the probe honors the registry npx actually uses ──

    describe("registry-config awareness (custom registry / proxy honesty)", () => {
      const ENV_KEYS = [
        "npm_config_registry",
        "NPM_CONFIG_REGISTRY",
        "npm_config_@sanctuary-framework:registry",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
      ];
      let savedEnv: Record<string, string | undefined>;

      beforeEach(() => {
        savedEnv = {};
        for (const key of ENV_KEYS) {
          savedEnv[key] = process.env[key];
          delete process.env[key];
        }
      });

      afterEach(() => {
        for (const key of ENV_KEYS) {
          if (savedEnv[key] !== undefined) process.env[key] = savedEnv[key]!;
          else delete process.env[key];
        }
      });

      it("no overrides resolves the public default registry, direct", async () => {
        expect(
          await resolveNpmRegistryForProbe({
            env: {},
            cwd: tmpHome,
            home: tmpHome,
            globalNpmrcPath: null,
          }),
        ).toEqual({ base: "https://registry.npmjs.org", indirect: false });
      });

      it("the default registry with a trailing slash still reads as direct (npx sets npm_config_registry even unconfigured)", async () => {
        expect(
          await resolveNpmRegistryForProbe({
            env: { npm_config_registry: "https://registry.npmjs.org/" },
            cwd: tmpHome,
            home: tmpHome,
            globalNpmrcPath: null,
          }),
        ).toEqual({ base: "https://registry.npmjs.org", indirect: false });
      });

      it("a custom registry in the npm config env is used and marked indirect", async () => {
        expect(
          await resolveNpmRegistryForProbe({
            env: { npm_config_registry: "https://npm.corp.example/" },
            cwd: tmpHome,
            home: tmpHome,
            globalNpmrcPath: null,
          }),
        ).toEqual({ base: "https://npm.corp.example", indirect: true });
      });

      it("registry URL userinfo is stripped and marked indirect before probing", async () => {
        // The probe is intentionally unauthenticated. npm registry URLs can
        // carry userinfo, and Node would otherwise convert that into a Basic
        // Authorization header on http(s).get.
        expect(
          await resolveNpmRegistryForProbe({
            env: {
              npm_config_registry:
                "https://user:pass@registry.npmjs.org/",
            },
            cwd: tmpHome,
            home: tmpHome,
            globalNpmrcPath: null,
          }),
        ).toEqual({
          base: "https://registry.npmjs.org",
          indirect: true,
        });
      });

      it("a registry= line in the user ~/.npmrc is honored; the scoped key beats the plain key", async () => {
        await writeFile(
          join(tmpHome, ".npmrc"),
          [
            "; comment",
            "registry=https://mirror.example/npm/",
            "@sanctuary-framework:registry = https://scoped.example/npm",
            "",
          ].join("\n"),
        );
        expect(
          await resolveNpmRegistryForProbe({
            env: {},
            cwd: tmpHome,
            home: tmpHome,
            globalNpmrcPath: null,
          }),
        ).toEqual({ base: "https://scoped.example/npm", indirect: true });
      });

      it("a deleted working directory (process.cwd throws) degrades to user config instead of crashing the wrap", async () => {
        // Fourth round: `sanctuary protect` run from a removed worktree /
        // cleaned tmp dir makes process.cwd() throw uv_cwd ENOENT. The
        // probe's contract is never-throws / never-blocks-the-wrap, so
        // the guard must fall back to user-level config only.
        const cwdSpy = vi.spyOn(process, "cwd").mockImplementation(() => {
          const err = new Error(
            "ENOENT: no such file or directory, uv_cwd",
          ) as NodeJS.ErrnoException;
          err.code = "ENOENT";
          throw err;
        });
        try {
          await expect(
            resolveNpmRegistryForProbe({
              env: {},
              home: tmpHome,
              globalNpmrcPath: null,
            }),
          ).resolves.toEqual({
            base: "https://registry.npmjs.org",
            indirect: false,
          });
        } finally {
          cwdSpy.mockRestore();
        }
      });

      it("proxy egress config marks even the default registry indirect", async () => {
        expect(
          await resolveNpmRegistryForProbe({
            env: { HTTPS_PROXY: "http://proxy.corp.example:8080" },
            cwd: tmpHome,
            home: tmpHome,
            globalNpmrcPath: null,
          }),
        ).toEqual({ base: "https://registry.npmjs.org", indirect: true });
      });

      it("a 404 from a CUSTOM registry reads honest-unknown unreachable, never the loud false unpublished", async () => {
        const base = await startRegistryStub(404);
        process.env.npm_config_registry = base;
        expect(await checkPinnedVersionResolvable("9.9.9")).toBe(
          "unreachable",
        );
      });

      it("a custom registry that serves the version still reads resolvable", async () => {
        const base = await startRegistryStub(200);
        process.env.npm_config_registry = base;
        expect(await checkPinnedVersionResolvable("9.9.9")).toBe("resolvable");
      });

      it("duplicate registry keys in one .npmrc are last-wins (npm ini semantics)", async () => {
        // First-wins reading kept the OLD value of a key that tooling later
        // re-appended, probed the wrong registry, and could re-create the
        // false-affirmative "unpublished" warning for an entry npx starts.
        await writeFile(
          join(tmpHome, ".npmrc"),
          [
            "registry=https://registry.npmjs.org",
            "registry=https://npm.corp.example/",
            "",
          ].join("\n"),
        );
        expect(
          await resolveNpmRegistryForProbe({
            env: {},
            cwd: tmpHome,
            home: tmpHome,
            globalNpmrcPath: null,
          }),
        ).toEqual({ base: "https://npm.corp.example", indirect: true });
      });

      it("a winning override the probe cannot interpret resolves default + INDIRECT, never default + direct", async () => {
        // npm expands ${VAR} in .npmrc values; this probe deliberately does
        // not. The winning-but-uninterpretable override must NOT silently
        // fall back to default+direct, where a 404 reads as the affirmative
        // "unpublished"; indirect keeps a 404 honest-unknown.
        await writeFile(
          join(tmpHome, ".npmrc"),
          "registry=${NPM_MIRROR}\n",
        );
        expect(
          await resolveNpmRegistryForProbe({
            env: {},
            cwd: tmpHome,
            home: tmpHome,
            globalNpmrcPath: null,
          }),
        ).toEqual({ base: "https://registry.npmjs.org", indirect: true });
      });

      it("the probe reads the PROJECT-ROOT .npmrc (upward walk), not just the literal cwd", async () => {
        // npm resolves the project config at the nearest ancestor holding
        // package.json or node_modules (localPrefix). A corporate operator
        // running the wrap from a SUBDIRECTORY of a repo whose root .npmrc
        // points at a mirror must not get the default registry resolved
        // direct - a mirror-only package then 404s into the loud false
        // "unpublished" dead-pin warning npx disproves at spawn time.
        const projectRoot = join(tmpHome, "repo");
        const subDir = join(projectRoot, "packages", "app");
        await mkdir(subDir, { recursive: true });
        await writeFile(join(projectRoot, "package.json"), "{}");
        await writeFile(
          join(projectRoot, ".npmrc"),
          "registry=https://mirror.corp.example/npm\n",
        );
        expect(
          await resolveNpmRegistryForProbe({
            env: {},
            cwd: subDir,
            home: tmpHome,
            globalNpmrcPath: null,
          }),
        ).toEqual({ base: "https://mirror.corp.example/npm", indirect: true });
      });

      it("with no project marker anywhere up the walk, the literal cwd .npmrc still applies (npm's localPrefix fallback)", async () => {
        const bareDir = join(tmpHome, "bare", "dir");
        await mkdir(bareDir, { recursive: true });
        await writeFile(
          join(bareDir, ".npmrc"),
          "registry=https://fallback.example/npm\n",
        );
        expect(
          await resolveNpmRegistryForProbe({
            env: {},
            cwd: bareDir,
            home: tmpHome,
            globalNpmrcPath: null,
          }),
        ).toEqual({ base: "https://fallback.example/npm", indirect: true });
      });

      it("a mirror configured ONLY in npm's global npmrc ($PREFIX/etc/npmrc) is honored and marked indirect", async () => {
        // `npm config set --location=global registry=...` writes the global
        // config file, a level the probe previously never read: the mirror
        // resolved to the public default marked DIRECT, so a mirror-only
        // version 404ed into the loud false-affirmative "unpublished"
        // dead-pin warning npx disproves at spawn time - the same class the
        // wrong-registry, duplicate-key, and project-root fixes closed for
        // the other config levels.
        const globalEtc = join(tmpHome, "prefix", "etc");
        await mkdir(globalEtc, { recursive: true });
        const globalNpmrc = join(globalEtc, "npmrc");
        await writeFile(
          globalNpmrc,
          "registry=https://global-mirror.corp.example/npm/\n",
        );
        expect(
          await resolveNpmRegistryForProbe({
            env: {},
            cwd: tmpHome,
            home: tmpHome,
            globalNpmrcPath: globalNpmrc,
          }),
        ).toEqual({
          base: "https://global-mirror.corp.example/npm",
          indirect: true,
        });
      });

      it("the user ~/.npmrc beats the global npmrc (npm's per-key precedence)", async () => {
        const globalEtc = join(tmpHome, "prefix", "etc");
        await mkdir(globalEtc, { recursive: true });
        const globalNpmrc = join(globalEtc, "npmrc");
        await writeFile(
          globalNpmrc,
          "registry=https://global-mirror.corp.example/npm\n",
        );
        await writeFile(
          join(tmpHome, ".npmrc"),
          "registry=https://user-mirror.corp.example/npm\n",
        );
        expect(
          await resolveNpmRegistryForProbe({
            env: {},
            cwd: tmpHome,
            home: tmpHome,
            globalNpmrcPath: globalNpmrc,
          }),
        ).toEqual({
          base: "https://user-mirror.corp.example/npm",
          indirect: true,
        });
      });

      it("an npm_config_globalconfig env override locates the global npmrc without the seam", async () => {
        // Production callers pass no globalNpmrcPath seam; the path is
        // derived from the npm config env (globalconfig beats prefix beats
        // node's install prefix). Pin the env-derivation branch.
        const globalNpmrc = join(tmpHome, "elsewhere-npmrc");
        await writeFile(
          globalNpmrc,
          "registry=https://derived.corp.example/npm\n",
        );
        expect(
          await resolveNpmRegistryForProbe({
            env: { npm_config_globalconfig: globalNpmrc },
            cwd: tmpHome,
            home: tmpHome,
          }),
        ).toEqual({
          base: "https://derived.corp.example/npm",
          indirect: true,
        });
      });
    });
  });

  it("an unpublished pin downgrades the wrap output with an honest WARNING and does not block the wrap", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));

    await runWrap(
      { claudeCode: true, noOpen: true },
      makeDeps({ checkPinResolvability: async () => "unpublished" }),
    );

    const out = stderrOutput();
    expect(out).toContain("does not have that version");
    expect(out).toContain("--dev-dist");
    // Availability: the wrap still completed.
    const wrapped = JSON.parse(await readFile(settingsPath, "utf-8"));
    expect(wrapped.mcpServers.sanctuary).toBeDefined();

    // Second round: the mid-flow warning alone is not enough — the
    // TERMINAL-FINAL success banner (the last thing printed) must carry the
    // dead-pin warning too, or the run still ends on an unqualified success
    // surface ~30 lines below the warning.
    const finalBanner = errSpy.mock.calls
      .at(-1)!
      .map(String)
      .join(" ");
    expect(finalBanner).toContain("which is not on the npm registry");
    expect(finalBanner).toContain("--dev-dist");
  });

  it("an unreachable registry prints the honest could-not-verify note and does not block the wrap", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));

    await runWrap(
      { claudeCode: true, noOpen: true },
      makeDeps({ checkPinResolvability: async () => "unreachable" }),
    );

    // The note must not claim the registry "could not be reached": the
    // outcome also covers a REACHED custom registry whose unauthenticated
    // 404 the probe declines to trust.
    const noteOut = stderrOutput();
    expect(noteOut).toContain(
      "could not confirm with the npm registry that the pinned version",
    );
    expect(noteOut).not.toContain("could not reach the npm registry");
    const wrapped = JSON.parse(await readFile(settingsPath, "utf-8"));
    expect(wrapped.mcpServers.sanctuary).toBeDefined();
  });

  // ── Finding 9 (second round): the pin outcome reaches the final banner ──

  describe("success banner carries the pin-resolvability outcome", () => {
    const baseInfo = {
      toolName: "Claude Code",
      version: "9.9.9",
      toolCount: 3,
      serverCount: 2,
      dashboardUrl: "http://127.0.0.1:3501",
      browserOpened: false,
      passphraseLocation: "test-keychain",
      passphraseSource: "generated",
      castleWallProtectionClaim: claim("unknown"),
    };

    it("an unpublished pin renders a loud warning in BOTH success surfaces", () => {
      for (const banner of [
        formatWrapSuccess({
          ...baseInfo,
          pinnedVersionResolvability: "unpublished",
        }),
        formatWrapSuccessNoDashboard({
          ...baseInfo,
          pinnedVersionResolvability: "unpublished",
        }),
      ]) {
        expect(banner).toContain("which is not on the npm registry");
        expect(banner).toContain("@sanctuary-framework/mcp-server@9.9.9");
        expect(banner).toContain("--dev-dist");
      }
    });

    it("an unreachable registry renders the honest could-not-verify note in both surfaces", () => {
      for (const banner of [
        formatWrapSuccess({
          ...baseInfo,
          pinnedVersionResolvability: "unreachable",
        }),
        formatWrapSuccessNoDashboard({
          ...baseInfo,
          pinnedVersionResolvability: "unreachable",
        }),
      ]) {
        expect(banner).toContain("could not verify");
        expect(banner).toContain("could not confirm the pinned MCP entry");
        // Cause wording stays honest for the custom-registry-404 subcase.
        expect(banner).not.toContain("registry was unreachable");
      }
    });

    it("resolvable / skipped / absent outcomes leave the banner byte-identical (no noise)", () => {
      const plain = formatWrapSuccess(baseInfo);
      expect(
        formatWrapSuccess({
          ...baseInfo,
          pinnedVersionResolvability: "resolvable",
        }),
      ).toBe(plain);
      expect(
        formatWrapSuccess({
          ...baseInfo,
          pinnedVersionResolvability: "skipped",
        }),
      ).toBe(plain);
      expect(plain).not.toContain("npm registry");
    });
  });

  it("a resolvable pin adds no warning noise", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));

    await runWrap(
      { claudeCode: true, noOpen: true },
      makeDeps({ checkPinResolvability: async () => "resolvable" }),
    );

    const out = stderrOutput();
    expect(out).not.toContain("does not have that version");
    expect(out).not.toContain("could not confirm with the npm registry");
  });

  // ── Finding 7: recovery breadcrumb for wrap-created files on unwrap ──

  it("unwrap of a wrap-created Hermes config.yaml preserves its final contents as a backup breadcrumb", async () => {
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    const jsonPath = join(hermesDir, "cli-config.json");
    const yamlPath = join(hermesDir, "config.yaml");
    await writeFile(jsonPath, "{}");
    // No config.yaml: wrap creates it fresh (backupPath: null).

    await runWrap({ hermes: true, noOpen: true }, makeDeps());

    // The operator adds their own MCP entry AFTER the wrap.
    const wrappedYaml = await readFile(yamlPath, "utf-8");
    const operatorLine = '  operator-added-server:\n    command: "my-tool"\n';
    await writeFile(yamlPath, wrappedYaml + operatorLine);

    errSpy.mockClear();
    await runWrap({ unwrap: true }, makeDeps());

    // Restore semantics unchanged: the wrap-created file is removed.
    await expect(access(yamlPath)).rejects.toThrow();
    // ...but its final contents survive in a timestamped backup, and the
    // operator was told where.
    expect(stderrOutput()).toContain("Its final contents were preserved at:");
    const backups = await readdir(backupDirPath());
    const yamlBackups = backups.filter((name) => name.endsWith(".yaml"));
    let preserved = false;
    for (const name of yamlBackups) {
      const content = await readFile(join(backupDirPath(), name), "utf-8");
      if (content.includes("operator-added-server")) preserved = true;
    }
    expect(preserved).toBe(true);
  });

  // ── Finding 8 (second round): phantom null-backup aux never wedges unwrap ──

  it("unwrap completes and retires the meta when a wrap-created config.yaml is ALREADY absent", async () => {
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    const jsonPath = join(hermesDir, "cli-config.json");
    const yamlPath = join(hermesDir, "config.yaml");
    await writeFile(jsonPath, "{}");
    // No config.yaml: wrap creates it fresh (backupPath: null in the meta).

    await runWrap({ hermes: true, noOpen: true }, makeDeps());

    // The file named by the null-backup aux entry is gone while its parent
    // dir survives (so validate-time `alreadyAbsent` does NOT fire). This
    // is the state the orphan-wrap guard leaves when the primary rewrite or
    // verify fails BEFORE the yaml was ever written (or after the rollback
    // already unlinked it) and the primary restore also fails: the guard's
    // meta names a file that does not exist.
    await rm(yamlPath);

    errSpy.mockClear();
    await runWrap({ unwrap: true }, makeDeps());

    const out = stderrOutput();
    // Pre-fix: the bare unlink threw ENOENT, counted as an auxiliary
    // restore failure, and the meta was kept forever — every --unwrap
    // re-run looped on a cause that is a nonexistent file.
    expect(out).toContain("already absent");
    expect(out).not.toContain("could not restore");
    expect(out).not.toContain("could not snapshot");
    // The unwrap COMPLETED: the meta pointer was retired.
    expect(await findLatestBackup()).toBeNull();
  });
});
