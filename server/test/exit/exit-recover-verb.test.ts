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
 * This file proves the fix is actually WIRED, not just documented:
 *  - `recover` is dispatched by `runExitCommand` and opens THIS fortress
 *    through the exact `openExitContext` path every other verb uses, so
 *    `recoverInterruptedExitImportsOrThrow` runs with the standard
 *    admission-lock handling (a real planted journal entry is rolled
 *    back, not just a documented promise that it would be);
 *  - it refuses while a live admission lock is held, exactly like
 *    export/import already do (same lock, same file);
 *  - every hint that used to hardcode `sanctuary exit verify` as the
 *    recovery verb now interpolates the ONE shared `EXIT_RECOVERY_VERB`
 *    constant, so this file also greps the known hint sites for the
 *    stale literal and fails if it ever reappears.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdir, open, readFile } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
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

describe("sanctuary exit recover (F1, Exit V2 D1 operator finding, 2026-08-23)", () => {
  it("EXIT_RECOVERY_VERB is exactly \"recover\" (pin: every hint below interpolates this literal value)", () => {
    expect(EXIT_RECOVERY_VERB).toBe("recover");
  });

  it("is dispatched by name: 'Unknown exit command' is never returned for the recovery verb", async () => {
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
      expect(code).toBe(0);
    } finally {
      await tempFortress.cleanup();
    }
  });

  it("reports 'nothing to recover' on a fresh fortress with no interrupted import", async () => {
    const tempFortress = await createTempFortress("sanctuary-recover-empty");
    try {
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
    const tempFortress = await createTempFortress("sanctuary-recover-empty-json");
    try {
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
      // Bootstrap the fortress with a real identity, mirroring
      // fortress-open-recovery-wiring.test.ts's planted-journal setup.
      const storage = new FilesystemStorage(join(tempFortress.storagePath, "state"));
      const masterKey = await resolveCliMasterKey(storage, {
        passphrase: TEST_PASSPHRASE,
        bootstrap: true,
        storagePathHint: tempFortress.storagePath,
      });
      const auditLog = new AuditLog(storage, masterKey);
      const stateStore = new StateStore(storage, masterKey);
      const { tools, identityManager } = createL1Tools(
        stateStore,
        storage,
        masterKey,
        "passphrase",
        auditLog
      );
      await identityManager.load();
      const tool = tools.find((t) => t.name === "identity_create")!;
      await tool.handler({ label: "recover-verb-target" });
      await auditLog.flush();

      // Plant a well-formed but interrupted-looking journal entry with an
      // EMPTY snapshot list, so restoring it is a trivial no-op success
      // (recovered++, no actual data to roll back) - this test's property
      // is that `recover` REACHES and CLEARS the journal, not the
      // snapshot-restore machinery itself (covered elsewhere).
      const importId = "planted-recover-verb-import";
      const journalRecord = {
        import_id: importId,
        identity_id: identityManager.getPrimaryIdentityId() ?? "unknown",
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

  it("refuses while the admission lock is held, exactly like export/import, and the refusal names the recover verb (not the old 'exit verify' hint)", async () => {
    const tempFortress = await createTempFortress("sanctuary-recover-locked");
    try {
      const storage = new FilesystemStorage(join(tempFortress.storagePath, "state"));
      // Bootstrap custody so the fortress can open at all.
      await resolveCliMasterKey(storage, {
        passphrase: TEST_PASSPHRASE,
        bootstrap: true,
        storagePathHint: tempFortress.storagePath,
      });

      const lockDir = storage.namespacePath(EXIT_IMPORT_JOURNAL_NAMESPACE);
      const lockPath = join(lockDir, "admission.lock");
      await mkdir(lockDir, { recursive: true, mode: 0o700 });
      // Same plant shape exit-import-atomic-activation.test.ts uses for its
      // HIGH-B lock-refusal case: a dead pid, no auto-stale-break means
      // this must still refuse.
      const handle = await open(lockPath, "wx+", 0o600);
      await handle.writeFile(
        JSON.stringify({ owner: "rotate", pid: 999_999, acquired_at: new Date(0).toISOString() })
      );
      await handle.close();

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

      // Lock file untouched (NO auto-stale-break).
      const stillLocked = JSON.parse(await readFile(lockPath, "utf8"));
      expect(stillLocked.owner).toBe("rotate");
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
