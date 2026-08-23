/**
 * F1 (Exit V2 D1 operator finding, 2026-08-23): `sanctuary exit recover`.
 *
 * Drill D1-OP-F1 found that every recovery hint in the codebase (doctor's
 * "exit import recovery" check, the admission-lock refusal, the
 * concurrent-import refusal, rotate/resume's own preflight refusals) told
 * the operator to run "any `sanctuary exit` verb (for example `sanctuary
 * exit verify`) to recover" - but `exit verify` (server/src/exit/cli.ts)
 * only checks a BUNDLE DIRECTORY and never opens the local fortress at
 * all, so an operator following that hint got a clean PASS/PASS while an
 * interrupted import stayed on disk (transcript: verify printed PASS
 * twice, the journal entry stayed on disk, doctor still failed).
 *
 * Round-3 fix (independent gate on #1304, HIGH; a SUBTRACTION, not a
 * patch): the round-1/round-2 cuts of `recover` resolved the fortress
 * path AMBIENTLY (`openExitContext`'s `loadConfig()`, then round 2's
 * `resolveStoragePath(env)`), and every ambient resolver diverges from
 * what OTHER `exit` verbs resolve to whenever the operator's fortress
 * path lives ONLY in `sanctuary.json`'s own `storage_path` key (proven
 * generally by test/unit/config-storage-path-divergence.test.ts). `recover`
 * now takes a REQUIRED `--fortress <path>` (the same flag name `sanctuary
 * doctor` uses) and reads no config file and no env var for the path at
 * all - there is no ambient source left to diverge from. This file's
 * no-diff tests snapshot the fortress directory tree before and after a
 * refused `recover` attempt and assert byte-identical, which is what
 * actually exercises "refuses without mutating" - a plain "did it print
 * the right message" assertion alone would not.
 *
 * Round-3 fix (LOW): `withPathLock` (storage/cross-process-lock.ts) mkdirs
 * the lock's namespace directory before attempting the O_EXCL acquire, so
 * even a no-op recovery used to leave a brand-new, empty
 * `_exit_import_journal` directory behind. `recover` now checks (read-only)
 * whether that directory exists before resolving a master key or locking
 * at all; if it does not, there is genuinely nothing to recover and it
 * returns without touching the lock machinery.
 *
 * This file proves the fix is actually WIRED, not just documented:
 *  - `recover` is dispatched by `runExitCommand` and opens THIS fortress
 *    through `openFortressForRecoveryOnly`, so
 *    `recoverInterruptedExitImportsOrThrow` runs with the standard
 *    admission-lock handling (a real planted journal entry is rolled
 *    back, not just a documented promise that it would be);
 *  - it refuses when `--fortress` is missing, even when
 *    SANCTUARY_STORAGE_PATH points at a real fortress (proving the flag is
 *    the ONLY path source, not merely an additional one);
 *  - it refuses while a live admission lock is held, exactly like
 *    export/import already do (same lock, same file), with NOTHING new
 *    on disk across the attempt;
 *  - it refuses on a fresh/virgin fortress (no custody envelope, no legacy
 *    markers) rather than silently bootstrapping one, with NOTHING on disk
 *    at all afterward;
 *  - it refuses on a legacy (pre-envelope) fortress rather than silently
 *    migrating it, naming the verb that legitimately performs that
 *    migration, with NOTHING new on disk;
 *  - it reports "nothing to recover" on a fortress with no journal
 *    directory at all, with NOTHING new on disk (the LOW fix);
 *  - every hint that used to hardcode `sanctuary exit verify` as the
 *    recovery verb now interpolates the ONE shared `EXIT_RECOVERY_VERB`
 *    constant AND the exact `--fortress <fortress path>` form, so this
 *    file also greps the known hint sites for both the stale literal and
 *    the required flag.
 */

import { afterEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdir, open, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import { deriveMasterKey } from "../../src/core/key-derivation.js";
import {
  runExitCommand,
  printExitHelp,
} from "../../src/exit/cli.js";
import { EXIT_IMPORT_JOURNAL_NAMESPACE, EXIT_RECOVERY_VERB } from "../../src/exit/bundle.js";
import { createTempFortress, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

/**
 * A content-addressed snapshot of everything under `root`: "ABSENT" if
 * nothing exists there at all, otherwise one sorted line per directory
 * (`D <relpath>`) and per file (`F <relpath>:<sha256 of its bytes>`). Two
 * snapshots being string-equal is this file's "the fortress tree did not
 * change AT ALL" assertion - stronger than "the expected files are
 * missing," since it also catches an unexpected file appearing anywhere in
 * the tree, not just at the specific paths a narrower check would think to
 * look at.
 */
async function snapshotTree(root: string): Promise<string> {
  try {
    await stat(root);
  } catch {
    return "ABSENT";
  }
  const rows: string[] = [];
  async function walk(dir: string, prefix: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of [...entries].sort((a, b) => a.name.localeCompare(b.name))) {
      const full = join(dir, entry.name);
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        rows.push(`D ${rel}`);
        await walk(full, rel);
      } else if (entry.isFile()) {
        const bytes = await readFile(full);
        rows.push(`F ${rel}:${createHash("sha256").update(bytes).digest("hex")}`);
      } else {
        rows.push(`? ${rel}`);
      }
    }
  }
  await walk(root, "");
  return rows.join("\n");
}

/** Bootstrap real custody on a temp fortress (test setup only - not part of any no-diff window). */
async function bootstrapFortress(storagePath: string): Promise<FilesystemStorage> {
  const storage = new FilesystemStorage(join(storagePath, "state"));
  await resolveCliMasterKey(storage, {
    passphrase: TEST_PASSPHRASE,
    bootstrap: true,
    storagePathHint: storagePath,
  });
  return storage;
}

describe("sanctuary exit recover (F1, Exit V2 D1 operator finding, 2026-08-23)", () => {
  it("EXIT_RECOVERY_VERB is exactly \"recover\" (pin: every hint below interpolates this literal value)", () => {
    expect(EXIT_RECOVERY_VERB).toBe("recover");
  });

  it("is dispatched by name: never falls through to 'Unknown exit command', even when it refuses", async () => {
    const tempFortress = await createTempFortress("sanctuary-recover-dispatch");
    try {
      const out = new StringWritable();
      const err = new StringWritable();
      const code = await runExitCommand({
        argv: [EXIT_RECOVERY_VERB, "--fortress", tempFortress.storagePath],
        out,
        err,
        env: {
          SANCTUARY_PASSPHRASE: TEST_PASSPHRASE,
        },
      });
      expect(err.text).not.toContain("Unknown exit command");
      // HIGH fix: a virgin fortress now REFUSES (never bootstraps).
      expect(code).toBe(1);
      expect(err.text).toContain("No fortress found at");
    } finally {
      await tempFortress.cleanup();
    }
  });

  it("HIGH fix (round 3, independent gate on #1304): refuses when --fortress is missing, ignoring SANCTUARY_STORAGE_PATH even when it names a real fortress, and creates NOTHING on disk (no-diff)", async () => {
    const tempFortress = await createTempFortress("sanctuary-recover-missing-flag-nodiff");
    try {
      // A REAL, bootstrapped fortress at the ambient path - so a pass
      // here can only be explained by --fortress genuinely being the
      // sole path source, not by there merely being nothing to find.
      await bootstrapFortress(tempFortress.storagePath);
      const before = await snapshotTree(tempFortress.storagePath);

      const out = new StringWritable();
      const err = new StringWritable();
      const code = await runExitCommand({
        argv: [EXIT_RECOVERY_VERB], // no --fortress
        out,
        err,
        env: {
          // Deliberately present and pointed at a REAL fortress: this
          // must be ignored. The round-2 cut would have used it via
          // resolveStoragePath(env) and this test would then observe
          // "nothing to recover" (code 0) instead of a refusal.
          SANCTUARY_STORAGE_PATH: tempFortress.storagePath,
          SANCTUARY_PASSPHRASE: TEST_PASSPHRASE,
        },
      });
      const after = await snapshotTree(tempFortress.storagePath);
      expect(after).toBe(before);
      expect(code).not.toBe(0);
      expect(err.text).toContain(`sanctuary exit ${EXIT_RECOVERY_VERB} requires --fortress <path>`);
      expect(err.text).toContain("never reads sanctuary.json");
      expect(err.text).toContain("never consults SANCTUARY_STORAGE_PATH");
    } finally {
      await tempFortress.cleanup();
    }
  });

  it("HIGH fix: refuses on a fresh/virgin fortress (no custody envelope, no legacy markers) and creates NOTHING on disk (no-diff)", async () => {
    const tempFortress = await createTempFortress("sanctuary-recover-fresh-nodiff");
    try {
      const before = await snapshotTree(tempFortress.storagePath);
      expect(before).toBe("ABSENT");

      const out = new StringWritable();
      const err = new StringWritable();
      const code = await runExitCommand({
        argv: [EXIT_RECOVERY_VERB, "--fortress", tempFortress.storagePath],
        out,
        err,
        env: {
          SANCTUARY_PASSPHRASE: TEST_PASSPHRASE,
        },
      });
      // The tree-diff assertion runs FIRST, ahead of the message/code
      // checks below: this is the property the test exists to prove, and
      // ordering it first means a divergence that still refuses (for a
      // wrong reason) but silently mutates fails HERE, not on a later,
      // less specific assertion.
      const after = await snapshotTree(tempFortress.storagePath);
      expect(after).toBe(before);
      expect(after).toBe("ABSENT");
      expect(code).toBe(1);
      expect(err.text).toContain("No fortress found at");
      expect(err.text).toContain("Nothing to recover");
      expect(err.text).toContain(`sanctuary exit ${EXIT_RECOVERY_VERB}`);
      expect(err.text).toContain("deliberately never establishes custody");
    } finally {
      await tempFortress.cleanup();
    }
  });

  it("LOW fix (round 2, independent gate on #1304): a custody sentinel with no envelope is refused as a possible integrity problem, not treated as 'no fortress', and creates NOTHING new on disk (no-diff)", async () => {
    const tempFortress = await createTempFortress("sanctuary-recover-sentinel-nodiff");
    try {
      // Plant ONLY the sentinel - no envelope, no legacy markers. This is
      // the shape `establishMaster` (core/master-custody.ts) treats as a
      // possible envelope loss or tampering: an envelope existed once
      // (only established alongside a sentinel) and is now gone.
      const storage = new FilesystemStorage(join(tempFortress.storagePath, "state"));
      await storage.write("_meta", "custody-sentinel", Buffer.from("planted-sentinel-ciphertext"));

      const before = await snapshotTree(tempFortress.storagePath);

      const out = new StringWritable();
      const err = new StringWritable();
      const code = await runExitCommand({
        argv: [EXIT_RECOVERY_VERB, "--fortress", tempFortress.storagePath],
        out,
        err,
        env: {
          SANCTUARY_PASSPHRASE: TEST_PASSPHRASE,
        },
      });
      // Tree-diff FIRST; see the fresh-fortress test above for why.
      const after = await snapshotTree(tempFortress.storagePath);
      expect(after).toBe(before);
      expect(code).toBe(1);
      // The SAME integrity guidance establishMaster's own resolver gives
      // for this exact condition (envelopeMissingButSentinelPresent,
      // core/master-custody.ts) - reused verbatim, not paraphrased.
      expect(err.text).toContain("custody sentinel exists but its custody envelope");
      expect(err.text).toContain("is missing or unreadable");
      // NOT the "no fortress" or "legacy migration" refusals - a sentinel
      // without an envelope is neither of those.
      expect(err.text).not.toContain("No fortress found at");
      expect(err.text).not.toContain("legacy (pre-envelope) custody");
    } finally {
      await tempFortress.cleanup();
    }
  });

  it("HIGH fix: refuses on a legacy (pre-envelope) custody fortress, naming which verb completes the migration, and creates NOTHING new on disk (no-diff)", async () => {
    const tempFortress = await createTempFortress("sanctuary-recover-legacy-nodiff");
    try {
      // Plant ONLY the legacy marker - no envelope, no other state -
      // simulating a pre-envelope fortress. `openFortressForRecoveryOnly`
      // refuses on this marker before ever parsing it, so a malformed
      // payload would still pass THIS test - but the MANUAL divergence
      // proof (see the file-level comment) reverts to the pre-fix code,
      // which DOES reach `deriveMasterKey(passphrase, params)`
      // (core/key-derivation.ts) on its way to the migration write this
      // test exists to detect. A fixture that is not real
      // KeyDerivationParams shape (real field names: alg/salt/m/t/p/l)
      // makes that reverted run fail on parameter validation instead of
      // on the tree-diff assertion, which is a false negative on the
      // negative control - so this uses REAL derivable params.
      const storage = new FilesystemStorage(join(tempFortress.storagePath, "state"));
      const { params: legacyKeyParams } = await deriveMasterKey(TEST_PASSPHRASE);
      await storage.write(
        "_meta",
        "key-params",
        Buffer.from(JSON.stringify(legacyKeyParams))
      );

      const before = await snapshotTree(tempFortress.storagePath);

      const out = new StringWritable();
      const err = new StringWritable();
      const code = await runExitCommand({
        argv: [EXIT_RECOVERY_VERB, "--fortress", tempFortress.storagePath],
        out,
        err,
        env: {
          SANCTUARY_PASSPHRASE: TEST_PASSPHRASE,
        },
      });
      // Tree-diff FIRST; see the fresh-fortress test above for why.
      const after = await snapshotTree(tempFortress.storagePath);
      expect(after).toBe(before);
      expect(code).toBe(1);
      expect(err.text).toContain("legacy (pre-envelope) custody");
      expect(err.text).toContain(`sanctuary exit ${EXIT_RECOVERY_VERB}`);
      expect(err.text).toContain("deliberately never migrates custody");
      // Names the verb(s) that legitimately perform the migration.
      expect(err.text).toContain("sanctuary exit export");
    } finally {
      await tempFortress.cleanup();
    }
  });

  it("refuses while the admission lock is held (envelope-based fortress), names the recover verb (not the old 'exit verify' hint), and creates NOTHING new on disk across the attempt (no-diff)", async () => {
    const tempFortress = await createTempFortress("sanctuary-recover-locked-nodiff");
    try {
      const storage = await bootstrapFortress(tempFortress.storagePath);

      const lockDir = storage.namespacePath(EXIT_IMPORT_JOURNAL_NAMESPACE);
      const lockPath = join(lockDir, "admission.lock");
      await mkdir(lockDir, { recursive: true, mode: 0o700 });
      const handle = await open(lockPath, "wx+", 0o600);
      await handle.writeFile(
        JSON.stringify({ owner: "rotate", pid: 999_999, acquired_at: new Date(0).toISOString() })
      );
      await handle.close();

      // Snapshot AFTER bootstrap/lock-plant setup - the window under test
      // is only the recover ATTEMPT itself. The journal directory already
      // exists here (the lock plant created it), so the LOW fix's
      // no-journal-dir fast path does not apply - this exercises the
      // ordinary lock-contention refusal.
      const before = await snapshotTree(tempFortress.storagePath);

      const out = new StringWritable();
      const err = new StringWritable();
      const code = await runExitCommand({
        argv: [EXIT_RECOVERY_VERB, "--fortress", tempFortress.storagePath],
        out,
        err,
        env: {
          SANCTUARY_PASSPHRASE: TEST_PASSPHRASE,
        },
      });
      // Tree-diff FIRST; see the fresh-fortress test above for why.
      const after = await snapshotTree(tempFortress.storagePath);
      expect(after).toBe(before);
      expect(code).toBe(1);
      expect(err.text).toContain(`sanctuary exit ${EXIT_RECOVERY_VERB}`);
      expect(err.text).not.toContain("sanctuary exit verify");
    } finally {
      await tempFortress.cleanup();
    }
  });

  it("HIGH fix (round 2, independent gate on #1304): a malformed sanctuary.json is never read or quarantined by recover, even while refusing on a held admission lock (no-diff, config file not renamed)", async () => {
    const tempFortress = await createTempFortress("sanctuary-recover-malformed-config-nodiff");
    try {
      const storage = await bootstrapFortress(tempFortress.storagePath);

      // `loadConfig` (server/src/config.ts) renames a malformed
      // sanctuary.json to `<path>.corrupted.<timestamp>` via
      // `quarantineConfigFile` - a write `recover` must never trigger.
      // Round 3 removed the only call to `loadConfig` (and to
      // `resolveStoragePath`) from `openFortressForRecoveryOnly`
      // entirely, so this is now true by construction rather than by an
      // ordering argument; this test remains as the regression pin.
      await writeFile(
        join(tempFortress.storagePath, "sanctuary.json"),
        "{ this is not valid json"
      );

      const lockDir = storage.namespacePath(EXIT_IMPORT_JOURNAL_NAMESPACE);
      const lockPath = join(lockDir, "admission.lock");
      await mkdir(lockDir, { recursive: true, mode: 0o700 });
      const handle = await open(lockPath, "wx+", 0o600);
      await handle.writeFile(
        JSON.stringify({ owner: "rotate", pid: 999_999, acquired_at: new Date(0).toISOString() })
      );
      await handle.close();

      // Snapshot AFTER bootstrap/config-plant/lock-plant setup - the
      // window under test is only the recover ATTEMPT itself. The
      // malformed sanctuary.json is already part of this snapshot (it
      // lives directly under the fortress root, which snapshotTree walks
      // recursively), so a quarantine-rename would show up as a diff.
      const before = await snapshotTree(tempFortress.storagePath);

      const out = new StringWritable();
      const err = new StringWritable();
      const code = await runExitCommand({
        argv: [EXIT_RECOVERY_VERB, "--fortress", tempFortress.storagePath],
        out,
        err,
        env: {
          SANCTUARY_PASSPHRASE: TEST_PASSPHRASE,
        },
      });
      // Tree-diff FIRST; see the fresh-fortress test above for why.
      const after = await snapshotTree(tempFortress.storagePath);
      expect(after).toBe(before);
      // Explicit, not just implied by the tree-diff: the exact file is
      // still exactly where it was, under its original name.
      expect(
        await stat(join(tempFortress.storagePath, "sanctuary.json"))
      ).toBeTruthy();
      expect(code).toBe(1);
      expect(err.text).toContain(`sanctuary exit ${EXIT_RECOVERY_VERB}`);
    } finally {
      await tempFortress.cleanup();
    }
  });

  it("LOW fix (round 3, independent gate on #1304): reports 'nothing to recover' on a bootstrapped fortress with NO journal directory at all, and creates NOTHING new on disk (no-diff)", async () => {
    const tempFortress = await createTempFortress("sanctuary-recover-no-journal-dir-nodiff");
    try {
      await bootstrapFortress(tempFortress.storagePath);
      // Custody establishment touches only `_meta`; the exit-import
      // journal namespace directory genuinely does not exist yet.
      const before = await snapshotTree(tempFortress.storagePath);
      expect(before).not.toContain("_exit_import_journal");

      const out = new StringWritable();
      const code = await runExitCommand({
        argv: [EXIT_RECOVERY_VERB, "--fortress", tempFortress.storagePath],
        out,
        err: new StringWritable(),
        env: {
          SANCTUARY_PASSPHRASE: TEST_PASSPHRASE,
        },
      });
      // Tree-diff FIRST; see the fresh-fortress test above for why. This
      // is the LOW fix's own proof: withPathLock's mkdir-before-O_EXCL
      // would otherwise leave a new, empty `_exit_import_journal`
      // directory behind on exactly this fortress shape.
      const after = await snapshotTree(tempFortress.storagePath);
      expect(after).toBe(before);
      expect(after).not.toContain("_exit_import_journal");
      expect(code).toBe(0);
      expect(out.text).toContain("nothing to recover");
    } finally {
      await tempFortress.cleanup();
    }
  });

  it("--json mode: 'nothing to recover' (no journal directory) reports {recovered: 0}", async () => {
    const tempFortress = await createTempFortress("sanctuary-recover-no-journal-dir-json");
    try {
      await bootstrapFortress(tempFortress.storagePath);

      const out = new StringWritable();
      const code = await runExitCommand({
        argv: [EXIT_RECOVERY_VERB, "--fortress", tempFortress.storagePath, "--json"],
        out,
        err: new StringWritable(),
        env: {
          SANCTUARY_PASSPHRASE: TEST_PASSPHRASE,
        },
      });
      expect(code).toBe(0);
      expect(JSON.parse(out.text)).toEqual({ recovered: 0 });
    } finally {
      await tempFortress.cleanup();
    }
  });

  it("WIRED CONSUMER: actually rolls back a planted interrupted-import journal entry and reports the count", async () => {
    const tempFortress = await createTempFortress("sanctuary-recover-planted");
    try {
      const storage = await bootstrapFortress(tempFortress.storagePath);

      // Plant a well-formed but interrupted-looking journal entry with an
      // EMPTY snapshot list, so restoring it is a trivial no-op success
      // (recovered++, no actual data to roll back) - this test's property
      // is that `recover` REACHES and CLEARS the journal, not the
      // snapshot-restore machinery itself (covered elsewhere). Writing
      // the entry also creates the journal directory, so the LOW fix's
      // no-journal-dir fast path does not short-circuit this test.
      const importId = "planted-recover-verb-import";
      const journalRecord = {
        import_id: importId,
        identity_id: "planted-identity-for-test",
        started_at: new Date().toISOString(),
        snapshots: [],
      };
      await storage.write(
        EXIT_IMPORT_JOURNAL_NAMESPACE,
        importId,
        Buffer.from(JSON.stringify(journalRecord) + "\n", "utf8")
      );
      expect(await storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(1);

      const out = new StringWritable();
      const code = await runExitCommand({
        argv: [EXIT_RECOVERY_VERB, "--fortress", tempFortress.storagePath],
        out,
        err: new StringWritable(),
        env: {
          SANCTUARY_PASSPHRASE: TEST_PASSPHRASE,
        },
      });
      expect(code).toBe(0);
      expect(out.text).toContain("recovered: 1 journal entry rolled back");

      const reopened = new FilesystemStorage(join(tempFortress.storagePath, "state"));
      expect(await reopened.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);
    } finally {
      await tempFortress.cleanup();
    }
  });

  it("printExitHelp documents the recover verb and its required --fortress flag", () => {
    const out = new StringWritable();
    printExitHelp(out);
    expect(out.text).toContain(`  ${EXIT_RECOVERY_VERB} --fortress <path>`);
    expect(out.text).toContain("REQUIRED");
  });

  it("STRUCTURAL PIN (parity): every known recovery-hint source file interpolates EXIT_RECOVERY_VERB, names the required --fortress flag, and none hardcodes the stale 'sanctuary exit verify ... to recover' literal", async () => {
    const HINT_FILES = [
      "src/storage/exit-import-journal.ts",
      "src/cli/doctor.ts",
      "src/exit/bundle.ts",
      "src/core/master-rotation.ts",
    ];
    const SERVER_ROOT = join(__dirname, "../..");
    for (const relPath of HINT_FILES) {
      const source = await readFile(join(SERVER_ROOT, relPath), "utf8");
      expect(source, `${relPath} must import/reference EXIT_RECOVERY_VERB`).toContain(
        "EXIT_RECOVERY_VERB"
      );
      // Round-3 parity: the hint text and the dispatch must agree that
      // --fortress is required - a hint naming the verb without the flag
      // sends an operator to a command that will itself refuse.
      expect(
        source,
        `${relPath} must name the required --fortress flag in its recovery hint`
      ).toContain("--fortress");
      expect(
        source,
        `${relPath} must not hardcode the stale "sanctuary exit verify ... to recover" hint`
      ).not.toMatch(/sanctuary exit verify[\s\S]{0,40}to recover/);
    }
  });

  it("STRUCTURAL PIN (parity): doctor's hint interpolates the ACTUAL storagePath it already has, not a placeholder", async () => {
    const source = await readFile(
      join(__dirname, "../../src/cli/doctor.ts"),
      "utf8"
    );
    // The one hint site with a real path in scope substitutes it; every
    // other hint site (deep library code with no path string handy) uses
    // the literal placeholder "<fortress path>" instead (checked via the
    // behavioral no-diff/refusal tests above, which read the real error
    // text those sites produce).
    expect(source).toContain("--fortress ${storagePath}");
  });
});
