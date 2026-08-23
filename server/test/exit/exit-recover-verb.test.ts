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
 * HIGH fix round (independent gate on #1304): the first cut of `recover`
 * opened via `openExitContext`, which always passed `bootstrap: true` to
 * `resolveCliMasterKey`. `establishMaster` can mint a brand-new custody
 * envelope on a virgin fortress via that flag, or migrate a legacy
 * (pre-envelope) fortress to an envelope regardless of that flag (the
 * legacy branches key off `_meta` markers, not `firstRun`) - both real
 * writes, and both happened before the exit-admission lock was ever
 * acquired. `recover` now opens through a dedicated
 * `openFortressForRecoveryOnly` that peeks at custody read-only first and
 * refuses by name - never bootstrapping or migrating - when no envelope is
 * present. This file's no-diff tests below snapshot the fortress directory
 * tree before and after a refused `recover` attempt and assert
 * byte-identical, which is what actually exercises this distinction - a
 * plain "did it print the right message" assertion alone would not.
 *
 * This file proves the fix is actually WIRED, not just documented:
 *  - `recover` is dispatched by `runExitCommand` and opens THIS fortress
 *    through `openFortressForRecoveryOnly`, so
 *    `recoverInterruptedExitImportsOrThrow` runs with the standard
 *    admission-lock handling (a real planted journal entry is rolled
 *    back, not just a documented promise that it would be);
 *  - it refuses while a live admission lock is held, exactly like
 *    export/import already do (same lock, same file), with NOTHING new
 *    on disk across the attempt;
 *  - it refuses on a fresh/virgin fortress (no custody envelope, no legacy
 *    markers) rather than silently bootstrapping one, with NOTHING on disk
 *    at all afterward;
 *  - it refuses on a legacy (pre-envelope) fortress rather than silently
 *    migrating it, naming the verb that legitimately performs that
 *    migration, with NOTHING new on disk;
 *  - every hint that used to hardcode `sanctuary exit verify` as the
 *    recovery verb now interpolates the ONE shared `EXIT_RECOVERY_VERB`
 *    constant, so this file also greps the known hint sites for the
 *    stale literal and fails if it ever reappears.
 */

import { afterEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdir, open, readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
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
        argv: [EXIT_RECOVERY_VERB],
        out,
        err,
        env: {
          SANCTUARY_STORAGE_PATH: tempFortress.storagePath,
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

  it("HIGH fix (independent gate on #1304): refuses on a fresh/virgin fortress (no custody envelope, no legacy markers) and creates NOTHING on disk (no-diff)", async () => {
    const tempFortress = await createTempFortress("sanctuary-recover-fresh-nodiff");
    try {
      const before = await snapshotTree(tempFortress.storagePath);
      expect(before).toBe("ABSENT");

      const out = new StringWritable();
      const err = new StringWritable();
      const code = await runExitCommand({
        argv: [EXIT_RECOVERY_VERB],
        out,
        err,
        env: {
          SANCTUARY_STORAGE_PATH: tempFortress.storagePath,
          SANCTUARY_PASSPHRASE: TEST_PASSPHRASE,
        },
      });
      expect(code).toBe(1);
      expect(err.text).toContain("No fortress found at");
      expect(err.text).toContain("Nothing to recover");
      expect(err.text).toContain(`sanctuary exit ${EXIT_RECOVERY_VERB}`);
      expect(err.text).toContain("deliberately never establishes custody");

      const after = await snapshotTree(tempFortress.storagePath);
      expect(after).toBe(before);
      expect(after).toBe("ABSENT");
    } finally {
      await tempFortress.cleanup();
    }
  });

  it("HIGH fix: refuses on a legacy (pre-envelope) custody fortress, naming which verb completes the migration, and creates NOTHING new on disk (no-diff)", async () => {
    const tempFortress = await createTempFortress("sanctuary-recover-legacy-nodiff");
    try {
      // Plant ONLY the legacy marker - no envelope, no other state -
      // simulating a pre-envelope fortress. The refusal is a truthy
      // read before any parse, so the payload need not be a real,
      // usable KeyDerivationParams for this test's purpose.
      const storage = new FilesystemStorage(join(tempFortress.storagePath, "state"));
      await storage.write(
        "_meta",
        "key-params",
        Buffer.from(
          JSON.stringify({
            algorithm: "argon2id",
            salt: "test-salt-not-real",
            iterations: 3,
            memory_kib: 65536,
            parallelism: 1,
          })
        )
      );

      const before = await snapshotTree(tempFortress.storagePath);

      const out = new StringWritable();
      const err = new StringWritable();
      const code = await runExitCommand({
        argv: [EXIT_RECOVERY_VERB],
        out,
        err,
        env: {
          SANCTUARY_STORAGE_PATH: tempFortress.storagePath,
          SANCTUARY_PASSPHRASE: TEST_PASSPHRASE,
        },
      });
      expect(code).toBe(1);
      expect(err.text).toContain("legacy (pre-envelope) custody");
      expect(err.text).toContain(`sanctuary exit ${EXIT_RECOVERY_VERB}`);
      expect(err.text).toContain("deliberately never migrates custody");
      // Names the verb(s) that legitimately perform the migration.
      expect(err.text).toContain("sanctuary exit export");

      const after = await snapshotTree(tempFortress.storagePath);
      expect(after).toBe(before);
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
      // is only the recover ATTEMPT itself.
      const before = await snapshotTree(tempFortress.storagePath);

      const out = new StringWritable();
      const err = new StringWritable();
      const code = await runExitCommand({
        argv: [EXIT_RECOVERY_VERB],
        out,
        err,
        env: {
          SANCTUARY_STORAGE_PATH: tempFortress.storagePath,
          SANCTUARY_PASSPHRASE: TEST_PASSPHRASE,
        },
      });
      expect(code).toBe(1);
      expect(err.text).toContain(`sanctuary exit ${EXIT_RECOVERY_VERB}`);
      expect(err.text).not.toContain("sanctuary exit verify");

      const after = await snapshotTree(tempFortress.storagePath);
      expect(after).toBe(before);
    } finally {
      await tempFortress.cleanup();
    }
  });

  it("reports 'nothing to recover' on an already-bootstrapped fortress with no interrupted import", async () => {
    const tempFortress = await createTempFortress("sanctuary-recover-bootstrapped-empty");
    try {
      await bootstrapFortress(tempFortress.storagePath);

      const out = new StringWritable();
      const code = await runExitCommand({
        argv: [EXIT_RECOVERY_VERB],
        out,
        err: new StringWritable(),
        env: {
          SANCTUARY_STORAGE_PATH: tempFortress.storagePath,
          SANCTUARY_PASSPHRASE: TEST_PASSPHRASE,
        },
      });
      expect(code).toBe(0);
      expect(out.text).toContain("nothing to recover");
    } finally {
      await tempFortress.cleanup();
    }
  });

  it("--json mode: 'nothing to recover' reports {recovered: 0}", async () => {
    const tempFortress = await createTempFortress("sanctuary-recover-bootstrapped-empty-json");
    try {
      await bootstrapFortress(tempFortress.storagePath);

      const out = new StringWritable();
      const code = await runExitCommand({
        argv: [EXIT_RECOVERY_VERB, "--json"],
        out,
        err: new StringWritable(),
        env: {
          SANCTUARY_STORAGE_PATH: tempFortress.storagePath,
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
      // snapshot-restore machinery itself (covered elsewhere).
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
        argv: [EXIT_RECOVERY_VERB],
        out,
        err: new StringWritable(),
        env: {
          SANCTUARY_STORAGE_PATH: tempFortress.storagePath,
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

  it("printExitHelp documents the recover verb", () => {
    const out = new StringWritable();
    printExitHelp(out);
    expect(out.text).toContain(`  ${EXIT_RECOVERY_VERB}`);
  });

  it("STRUCTURAL PIN: every known recovery-hint source file interpolates EXIT_RECOVERY_VERB and none hardcodes the stale 'sanctuary exit verify ... to recover' literal", async () => {
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
      expect(
        source,
        `${relPath} must not hardcode the stale "sanctuary exit verify ... to recover" hint`
      ).not.toMatch(/sanctuary exit verify[\s\S]{0,40}to recover/);
    }
  });
});
