import { describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stringToBytes, bytesToString, toBase64url } from "../../src/core/encoding.js";
import { hashToString } from "../../src/core/hashing.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  createExitAdmissionWriteGuard,
  MEMORY_PROVENANCE_SIGNER_PRUNE_COMPLETION_KEY,
  recoverInterruptedExitImports,
  runJournaledExitMemoryAdmission,
  runJournaledMemoryProvenanceSignerPrune,
} from "../../src/exit/bundle.js";
import {
  EXIT_IMPORT_JOURNAL_NAMESPACE,
  EXIT_IMPORT_JOURNAL_POSTIMAGE_NAMESPACE,
  withExitAdmissionLock,
} from "../../src/storage/exit-import-journal.js";

describe("C4 shared Exit memory-admission journal", () => {
  it("restores exact pre-images in reverse failure handling after a recorded write", async () => {
    const storage = new MemoryStorage();
    await storage.write("_known_signers", "memprov.restore", stringToBytes("before"));
    await expect(runJournaledExitMemoryAdmission({
      storage, importId: "memory-import-1", identityId: "identity",
      locations: [{ namespace: "_known_signers", key: "memprov.restore" }],
      operation: async ({ recordPostImage }) => {
        const after = stringToBytes("after");
        await storage.write("_known_signers", "memprov.restore", after);
        await recordPostImage("_known_signers", "memprov.restore", after);
        throw new Error("fault after provenance");
      },
    })).rejects.toThrow("fault after provenance");
    expect(bytesToString((await storage.read("_known_signers", "memprov.restore"))!)).toBe("before");
    expect(await storage.list("_exit_import_journal")).toHaveLength(0);

    await storage.write("_known_signers", "deleted-before-fault", stringToBytes("prior"));
    await expect(runJournaledExitMemoryAdmission({
      storage, importId: "memory-import-delete", identityId: "identity",
      locations: [{ namespace: "_known_signers", key: "deleted-before-fault" }],
      operation: async ({ recordPostImage }) => {
        await storage.delete("_known_signers", "deleted-before-fault");
        await recordPostImage("_known_signers", "deleted-before-fault", null);
        throw new Error("fault after delete");
      },
    })).rejects.toThrow("fault after delete");
    expect(bytesToString((await storage.read("_known_signers", "deleted-before-fault"))!)).toBe("prior");
  });

  it("refuses a diverged concurrent post-image as partial_scope", async () => {
    const storage = new MemoryStorage();
    await expect(runJournaledExitMemoryAdmission({
      storage, importId: "memory-import-2", identityId: "identity",
      locations: [{ namespace: "_known_signers", key: "memprov.key" }],
      operation: async ({ recordPostImage }) => {
        const ours = stringToBytes("ours");
        await storage.write("_known_signers", "memprov.key", ours);
        await recordPostImage("_known_signers", "memprov.key", ours);
        await storage.write("_known_signers", "memprov.key", stringToBytes("racer"));
        return "would-have-completed";
      },
    })).rejects.toMatchObject({ name: "ExitMemoryAdmissionPartialScopeError" });
    expect(bytesToString((await storage.read("_known_signers", "memprov.key"))!)).toBe("racer");
    expect(await storage.list("_exit_import_journal")).toHaveLength(1);
  });

  it("rejects a late undeclared write before it reaches storage", async () => {
    const base = new MemoryStorage();
    const guard = createExitAdmissionWriteGuard(base);
    await expect(runJournaledExitMemoryAdmission({
      storage: base, importId: "memory-import-late", identityId: "identity",
      locations: [{ namespace: "_sdw_document_corpus", key: "doc.declared" }],
      operation: async (journal) => {
        guard.activate([{ namespace: "_sdw_document_corpus", key: "doc.declared" }], journal.recordPostImage);
        try {
          await guard.storage.write("_sdw_document_corpus", "doc.undeclared", stringToBytes("late"));
        } finally { guard.deactivate(); }
      },
    })).rejects.toThrow(/undeclared late write/);
    expect(await base.read("_sdw_document_corpus", "doc.undeclared")).toBeNull();
  });

  it("restores every C4 fault boundary and serializes competing admissions", async () => {
    const locations = [
      { namespace: "_known_signers", key: "memprov.signer" },
      { namespace: "_known_signers", key: "boundary.chunk" },
      { namespace: "_known_signers", key: "boundary.provenance" },
      { namespace: "_known_signers", key: "boundary.status" },
      { namespace: "_known_signers", key: "boundary.document" },
      { namespace: "_known_signers", key: "boundary.lineage" },
    ];
    for (let boundary = 0; boundary < locations.length; boundary++) {
      const base = new MemoryStorage();
      const guard = createExitAdmissionWriteGuard(base);
      await expect(runJournaledExitMemoryAdmission({
        storage: base, importId: `fault-${boundary}`, identityId: "identity", locations,
        operation: async (journal) => {
          guard.activate(locations, journal.recordPostImage);
          try {
            for (let index = 0; index <= boundary; index++) {
              const loc = locations[index]!;
              await guard.storage.write(loc.namespace, loc.key, stringToBytes(`after-${index}`));
            }
            throw new Error(`fault-${boundary}`);
          } finally { guard.deactivate(); }
        },
      })).rejects.toThrow(`fault-${boundary}`);
      for (const loc of locations) expect(await base.read(loc.namespace, loc.key)).toBeNull();
    }

    const raceRoot = await mkdtemp(join(tmpdir(), "sanctuary-c4-race-"));
    const base = new FilesystemStorage(raceRoot);
    let active = 0;
    let maximum = 0;
    const run = (id: string) => runJournaledExitMemoryAdmission({
      storage: base, importId: id, identityId: "identity",
      locations: [{ namespace: "_known_signers", key: `race.${id}` }],
      operation: async ({ recordPostImage }) => {
        active++;
        maximum = Math.max(maximum, active);
        const bytes = stringToBytes(id);
        await base.write("_known_signers", `race.${id}`, bytes);
        await recordPostImage("_known_signers", `race.${id}`, bytes);
        await Promise.resolve();
        active--;
      },
    });
    const runReputationImport = () => withExitAdmissionLock(base, "import", async () => {
      active++;
      maximum = Math.max(maximum, active);
      await Promise.resolve();
      active--;
    });
    const runSignerPrune = () => withExitAdmissionLock(base, "memory_signer_prune", async () => {
      active++;
      maximum = Math.max(maximum, active);
      await Promise.resolve();
      active--;
    });
    try {
      // Memory-archive admission and the established reputation Exit import
      // owner share the same cross-process admission lock.
      await Promise.all([run("race-memory"), runReputationImport(), runSignerPrune()]);
      expect(maximum).toBe(1);
    } finally {
      await rm(raceRoot, { recursive: true, force: true });
    }
  });

  it("restores exact signer bytes at every prune post-image and delete boundary", async () => {
    for (const boundary of ["before-postimage", "after-postimage", "after-delete"] as const) {
      const storage = new MemoryStorage();
      const key = `memprov.${boundary}`;
      const before = stringToBytes(`before-${boundary}`);
      await storage.write("_known_signers", key, before);
      await expect(runJournaledMemoryProvenanceSignerPrune({
        storage,
        identityId: "identity",
        locations: [{ namespace: "_known_signers", key }],
        operation: async ({ recordPostImage }) => {
          if (boundary === "before-postimage") throw new Error(boundary);
          await recordPostImage("_known_signers", key, null);
          if (boundary === "after-postimage") throw new Error(boundary);
          await storage.delete("_known_signers", key, true);
          throw new Error(boundary);
        },
      })).rejects.toThrow(boundary);
      expect(await storage.read("_known_signers", key)).toEqual(before);
      expect(await storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);
      expect(await storage.list(EXIT_IMPORT_JOURNAL_POSTIMAGE_NAMESPACE)).toHaveLength(0);
    }
  });

  it("recovers an interrupted prune as rollback before activation and commit after activation", async () => {
    const importId = MEMORY_PROVENANCE_SIGNER_PRUNE_COMPLETION_KEY;
    const signerKey = "memprov.crash";
    const before = stringToBytes("exact-before-crash");
    const journal = (data: string | null) => ({
      import_id: importId,
      identity_id: "identity",
      started_at: "2026-08-25T00:00:00.000Z",
      snapshots: [
        { namespace: "_known_signers", key: signerKey, data },
        { namespace: "_exit_imports", key: importId, data: null },
      ],
    });
    const postImageKey = `${importId}:${hashToString(stringToBytes(
      `${"_known_signers".length}:_known_signers${signerKey}`,
    ))}`;

    const rollbackStorage = new MemoryStorage();
    await rollbackStorage.write("_known_signers", signerKey, before);
    await rollbackStorage.write(
      EXIT_IMPORT_JOURNAL_NAMESPACE,
      importId,
      stringToBytes(JSON.stringify(journal(toBase64url(before)))),
    );
    await rollbackStorage.write(
      EXIT_IMPORT_JOURNAL_POSTIMAGE_NAMESPACE,
      postImageKey,
      stringToBytes(JSON.stringify({ deleted: true })),
    );
    await rollbackStorage.delete("_known_signers", signerKey, true);
    const rollback = await recoverInterruptedExitImports(
      rollbackStorage,
      new AuditLog(rollbackStorage, new Uint8Array(32).fill(17)),
    );
    expect(rollback).toMatchObject({ recovered: 1, failed: [] });
    expect(await rollbackStorage.read("_known_signers", signerKey)).toEqual(before);

    const committedStorage = new MemoryStorage();
    await committedStorage.write(
      EXIT_IMPORT_JOURNAL_NAMESPACE,
      importId,
      stringToBytes(JSON.stringify(journal(toBase64url(before)))),
    );
    await committedStorage.write(
      EXIT_IMPORT_JOURNAL_POSTIMAGE_NAMESPACE,
      postImageKey,
      stringToBytes(JSON.stringify({ deleted: true })),
    );
    await committedStorage.write("_exit_imports", importId, stringToBytes(JSON.stringify({
      import_id: importId,
      activated_at: "2026-08-25T00:00:01.000Z",
    })));
    const committed = await recoverInterruptedExitImports(
      committedStorage,
      new AuditLog(committedStorage, new Uint8Array(32).fill(18)),
    );
    expect(committed).toMatchObject({ recovered: 1, failed: [] });
    expect(await committedStorage.read("_known_signers", signerKey)).toBeNull();
    expect(await committedStorage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);
    expect(await committedStorage.list(EXIT_IMPORT_JOURNAL_POSTIMAGE_NAMESPACE)).toHaveLength(0);

    // The next bounded prune clears the disposable fixed witness before
    // publishing its journal and leaves no per-run completion accumulation.
    await committedStorage.write("_known_signers", signerKey, before);
    await runJournaledMemoryProvenanceSignerPrune({
      storage: committedStorage,
      identityId: "identity",
      locations: [{ namespace: "_known_signers", key: signerKey }],
      operation: async () => "ok",
    });
    expect(await committedStorage.list("_exit_imports")).toHaveLength(0);
  });

  it("retains recovery evidence and surfaces partial_scope on prune divergence", async () => {
    const storage = new MemoryStorage();
    const key = "memprov.diverged";
    await storage.write("_known_signers", key, stringToBytes("before"));
    await expect(runJournaledMemoryProvenanceSignerPrune({
      storage,
      identityId: "identity",
      locations: [{ namespace: "_known_signers", key }],
      operation: async ({ recordPostImage }) => {
        await recordPostImage("_known_signers", key, null);
        await storage.delete("_known_signers", key, true);
        await storage.write("_known_signers", key, stringToBytes("racer"));
        throw new Error("fault after divergence");
      },
    })).rejects.toMatchObject({ name: "MemoryProvenanceSignerPrunePartialScopeError" });
    expect(bytesToString((await storage.read("_known_signers", key))!)).toBe("racer");
    expect(await storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(1);
    expect(await storage.list(EXIT_IMPORT_JOURNAL_POSTIMAGE_NAMESPACE)).toHaveLength(1);
  });
});
