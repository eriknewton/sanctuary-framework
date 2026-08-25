import { describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stringToBytes, bytesToString } from "../../src/core/encoding.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { createExitAdmissionWriteGuard, runJournaledExitMemoryAdmission } from "../../src/exit/bundle.js";
import { withExitAdmissionLock } from "../../src/storage/exit-import-journal.js";

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
    try {
      // Memory-archive admission and the established reputation Exit import
      // owner share the same cross-process admission lock.
      await Promise.all([run("race-memory"), runReputationImport()]);
      expect(maximum).toBe(1);
    } finally {
      await rm(raceRoot, { recursive: true, force: true });
    }
  });
});
