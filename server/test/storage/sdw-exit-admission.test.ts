import { afterEach, describe, expect, it, vi } from "vitest";
import { fork, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { lstat, readFile, readdir, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { createSdwFenceFixture, sdwDeferred } from "./sdw-journal-fixtures.js";
import {
  withExitAdmissionLock, withSdwJournalAdmission, EXIT_IMPORT_JOURNAL_NAMESPACE,
  EXIT_ADMISSION_LOCK_FILE, EXIT_ADMISSION_LOCK_TIMEOUT_MS, SDW_ROTATION_JOURNAL_KEY,
  ExitAdmissionLockError, type ExitAdmissionOwner,
} from "../../src/storage/exit-import-journal.js";
import { SDW_JOURNAL_NAMESPACES, SdwStorageError } from "../../src/storage/sdw-journal-contract.js";
import { CrossProcessLockError } from "../../src/storage/cross-process-lock.js";
import { ROTATION_JOURNAL_KEY, withCustodyWriteLock } from "../../src/core/master-custody.js";
import { isWellFormedExitImportJournalRecord, hasOversizedSnapshotsArray, MAX_EXIT_IMPORT_JOURNAL_LOCATIONS } from "../../src/storage/exit-import-journal-record.js";
import { STATE_ENVELOPE_PUBLIC_KEYS_KEY, STATE_ENVELOPE_VERSION_ANCHORS_KEY, isReservedNamespace } from "../../src/cognitive/state-store.js";
import { KNOWN_SIGNERS_NAMESPACE } from "../../src/reputation/known-signers-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";

const rigs: Awaited<ReturnType<typeof createSdwFenceFixture>>[] = [];
const children: ChildProcess[] = [];
async function rig() { const r = await createSdwFenceFixture(); rigs.push(r); return r; }
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(children.splice(0).map(async child => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    const done = new Promise<void>(resolve => child.once("close", () => resolve())); child.kill("SIGKILL"); await done;
  }));
  await Promise.all(rigs.splice(0).map(r => r.cleanup()));
});
const owners: ExitAdmissionOwner[] = ["import", "rotate", "resume", "memory_migration", "memory_archive_import", "memory_bad_signer", "memory_signer_prune"];
const record = (namespace: string, key = "entry") => ({ import_id: "import", identity_id: "identity", started_at: "2026-10-28", snapshots: [{ namespace, key, data: null }] });
async function journal(r: Awaited<ReturnType<typeof rig>>, value: unknown) {
  await r.storage.write(EXIT_IMPORT_JOURNAL_NAMESPACE, "import", Buffer.from(JSON.stringify(value)));
}
interface ChildEvent { event: string; namespace?: string; name?: string; reason?: string; status?: string; trace?: string[] }
function childProbe(root: string, mode: "engine" | "exit", custody = false) {
  const child = fork(fileURLToPath(new URL("./sdw-fence-child.ts", import.meta.url)), [root, mode, "import", custody ? "yes" : "no"],
    { execArgv: ["--import", import.meta.resolve("tsx")], stdio: ["ignore", "pipe", "pipe", "ipc"] });
  children.push(child);
  const events: ChildEvent[] = []; const waiters: { event: string; done: ReturnType<typeof sdwDeferred<ChildEvent>> }[] = [];
  let stderr = ""; child.stderr?.on("data", chunk => { stderr += String(chunk); });
  child.on("message", raw => {
    const message = raw as ChildEvent; events.push(message);
    for (const waiter of waiters) if (waiter.event === message.event) waiter.done.resolve(message);
  });
  child.on("error", error => { for (const waiter of waiters) waiter.done.reject(error); });
  const closed = new Promise<void>((resolve, reject) => child.once("close", code => {
    if (code === 0) resolve(); else reject(new Error(`child exit ${code}: ${stderr}`));
    for (const waiter of waiters) if (!events.some(event => event.event === waiter.event)) waiter.done.reject(new Error(`missing ${waiter.event}: ${stderr}`));
  }));
  // The bound reaps a child even if a failed assertion never reaches its result wait.
  const timer = setTimeout(() => child.kill("SIGKILL"), EXIT_ADMISSION_LOCK_TIMEOUT_MS * 2);
  void closed.finally(() => clearTimeout(timer)).catch(() => {});
  return { events, closed, async wait(event: string) {
    const existing = events.find(value => value.event === event); if (existing) return existing;
    const done = sdwDeferred<ChildEvent>(); waiters.push({ event, done }); return done.promise;
  } };
}

describe("Exit per-owner SDW admission", () => {
  it.each(owners)("%s: refuses pending, permits CLEAN/APPLIED/RETIRED", async owner => {
    const r = await rig();
    for (const state of ["BUILDING", "PREPARED", "COMMIT", "INVALID"] as const) {
      await r.publish(state); const callback = vi.fn(async () => {});
      await expect(withExitAdmissionLock(r.storage, owner, callback)).rejects.toBeInstanceOf(SdwStorageError);
      expect(callback).not.toHaveBeenCalled();
    }
    for (const state of ["CLEAN", "APPLIED", "RETIRED"] as const) {
      await r.publish(state); r.trace.length = 0;
      await withExitAdmissionLock(r.storage, owner, async () => { r.trace.push("3:corpus"); });
      expect(r.trace).toEqual(["3:corpus"]);
      expect(r.counters.fences).toBe(0);
    }
  });

  it("empty recovery passes invalid SDW without any SDW probe", async () => {
    const r = await rig(); await writeFile(r.journal, "invalid root");
    const paths = vi.spyOn(r.storage, "namespacePath");
    await expect(withExitAdmissionLock(r.storage, "recovery", async () => "empty")).resolves.toBe("empty");
    expect(paths.mock.calls.every(([ns]) => ns !== "_sdw_journal_v1")).toBe(true);
    expect(r.counters).toEqual({ observations: 0, fences: 0 });
    expect(await readFile(r.journal, "utf8")).toBe("invalid root");
  });

  it("scaffold_absence: valid non-SDW recovery leaves absent root and following ordinary read succeeds", async () => {
    const r = await rig(); await journal(r, record("notes"));
    await r.storage.write("notes", "entry", Buffer.from("ordinary"));
    await expect(withExitAdmissionLock(r.storage, "recovery", async () => "recover")).resolves.toBe("recover");
    await expect(lstat(r.journal)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(r.fence.read(SDW_JOURNAL_NAMESPACES[0], async () => "ordinary")).resolves.toBe("ordinary");
    expect(Buffer.from((await r.storage.read("notes", "entry"))!).toString()).toBe("ordinary");
    expect(r.counters.fences).toBe(0);
  });

  it("valid non-SDW recovery passes every pending state; SDW overlap and unclassifiable records refuse", async () => {
    const r = await rig();
    for (const state of ["BUILDING", "PREPARED", "COMMIT", "INVALID"] as const) {
      await r.publish(state); await journal(r, record("notes"));
      await expect(withExitAdmissionLock(r.storage, "recovery", async () => "pass")).resolves.toBe("pass");
      for (const value of [record("_sdw_document_corpus"), { ...record("notes"), snapshots: [null] }]) {
        await journal(r, value); const callback = vi.fn(async () => {});
        await expect(withExitAdmissionLock(r.storage, "recovery", callback)).rejects.toBeInstanceOf(SdwStorageError);
        expect(callback).not.toHaveBeenCalled();
      }
    }
    await journal(r, record("_sdw_document_corpus"));
    // Only the catalog is busy: the validated corpus recovery is unaffected.
    await r.publish("PREPARED", 1, 1);
    await expect(withExitAdmissionLock(r.storage, "recovery", async () => "unaffected")).resolves.toBe("unaffected");
    for (const state of ["CLEAN", "APPLIED", "RETIRED"] as const) {
      await r.publish(state); await journal(r, { malformed: true });
      await expect(withExitAdmissionLock(r.storage, "recovery", async () => "existing Exit checks")).resolves.toBe("existing Exit checks");
    }
  });

  it("shared parser exact field, base64 and full namespace membership parity", () => {
    const accepted = ["_exit_imports", "_exit_public_identities", "_exit_audit_receipts", "_exit_policy_sets", "_exit_commitments",
      "_exit_placeholder_metadata", "_reputation", KNOWN_SIGNERS_NAMESPACE, "_sdw_document_corpus", "notes", ""];
    for (const ns of accepted) expect(isWellFormedExitImportJournalRecord(record(ns))).toBe(true);
    for (const ns of [...SDW_JOURNAL_NAMESPACES.filter(ns => ns !== "_sdw_document_corpus"), "_sdw_memory_bad_signers", "_unknown"]) {
      expect(isReservedNamespace(ns)).toBe(true); expect(isWellFormedExitImportJournalRecord(record(ns))).toBe(false);
    }
    for (const key of [STATE_ENVELOPE_PUBLIC_KEYS_KEY, STATE_ENVELOPE_VERSION_ANCHORS_KEY]) expect(isWellFormedExitImportJournalRecord(record("_meta", key))).toBe(true);
    expect(isWellFormedExitImportJournalRecord(record("_meta", "other"))).toBe(false);
    expect(isWellFormedExitImportJournalRecord({ ...record("notes"), extra: true })).toBe(false);
    for (const data of [null, "", "YQ"]) expect(isWellFormedExitImportJournalRecord({ ...record("notes"), snapshots: [{ namespace: "notes", key: "k", data }] })).toBe(true);
    for (const data of ["YQ=", "@", 1]) expect(isWellFormedExitImportJournalRecord({ ...record("notes"), snapshots: [{ namespace: "notes", key: "k", data }] })).toBe(false);
    expect(hasOversizedSnapshotsArray({ snapshots: Array(MAX_EXIT_IMPORT_JOURNAL_LOCATIONS + 1) })).toBe(true);
    expect(SDW_ROTATION_JOURNAL_KEY).toBe(ROTATION_JOURNAL_KEY);
  });

  it("unknown direct owner defaults to import, metadata never grants engine authority", async () => {
    const r = await rig(); await r.publish("BUILDING");
    await expect(withExitAdmissionLock(r.storage, "sdw_journal" as ExitAdmissionOwner, async () => "bypass")).rejects.toMatchObject({ reason: "storage_recovery_pending" });
  });

  it.each(["exit", "rotation"] as const)("two-process %s journal prevents engine token and callback", async kind => {
    const r = await rig();
    await withExitAdmissionLock(r.storage, kind === "exit" ? "import" : "rotate", async () => {
      if (kind === "exit") await journal(r, record("notes"));
      else await r.storage.write("_meta", ROTATION_JOURNAL_KEY, Buffer.from("pending"));
    });
    const child = childProbe(r.root, "engine");
    expect(await child.wait("result")).toMatchObject({ status: "error", reason: "storage_recovery_pending", trace: [] });
    await child.closed; expect(child.events.some(event => event.event === "callback" || event.event === "token")).toBe(false);
    expect(r.counters.fences).toBe(0);
  });

  it.each([false, true])("exit_admission_both_orders custody=%s", async custody => {
    const r = await rig(); const held = sdwDeferred(); const release = sdwDeferred();
    const run = <T>(operation: () => Promise<T>) => custody ? withCustodyWriteLock(r.storage, operation) : operation();
    const holder = run(() => withSdwJournalAdmission(r.storage, token => r.fence.withEngine(token, "new", SDW_JOURNAL_NAMESPACES, undefined, async scope => {
      await scope.drainMutations(() => r.publish("BUILDING")); held.resolve(); await release.promise;
    })));
    await held.promise;
    const exit = childProbe(r.root, "exit", custody);
    try { expect((await exit.wait("contended")).namespace).toBe(custody ? "_meta" : EXIT_IMPORT_JOURNAL_NAMESPACE); }
    finally { release.resolve(); await holder; }
    expect(await exit.wait("result")).toMatchObject({ status: "error", reason: "storage_recovery_pending" });
    await exit.closed; expect(exit.events.some(event => event.event === "callback")).toBe(false);

    await r.publish("CLEAN"); const exitHeld = sdwDeferred(); const exitRelease = sdwDeferred();
    const exitHolder = run(() => withExitAdmissionLock(r.storage, "import", async () => { exitHeld.resolve(); await exitRelease.promise; }));
    await exitHeld.promise;
    // Admission contention is measured directly even when the holder nests under custody.
    const engine = childProbe(r.root, "engine");
    try {
      expect((await engine.wait("contended")).namespace).toBe(EXIT_IMPORT_JOURNAL_NAMESPACE);
      expect(await engine.wait("result")).toMatchObject({ status: "error", reason: "storage_busy" });
      expect(engine.events.some(event => event.event === "callback")).toBe(false); await engine.closed;
    } finally { exitRelease.resolve(); await exitHolder; }
    const continuing = childProbe(r.root, "engine", custody);
    expect(await continuing.wait("result")).toMatchObject({ status: "ok" }); await continuing.closed;
    expect(continuing.events.some(event => event.event === "callback")).toBe(true);
  }, EXIT_ADMISSION_LOCK_TIMEOUT_MS * 4);

  it("real custody -> admission -> non-creating preflight -> corpus -> fence -> namespace ordering", async () => {
    const r = await rig(); await r.publish("CLEAN");
    const trace = r.trace;
    const original = r.storage.withNamespaceLock.bind(r.storage);
    r.storage.withNamespaceLock = (ns, name, operation, options) => original(ns, name, async lease => {
      trace.push(ns === "_meta" ? "1:custody" : "2:admission"); return operation(lease);
    }, options);
    await withCustodyWriteLock(r.storage, async () => {
      await withExitAdmissionLock(r.storage, "import", async () => { trace.push("3:corpus"); });
      await withSdwJournalAdmission(r.storage, async token => {
        trace.push("3:corpus");
        await r.fence.withEngine(token, "new", SDW_JOURNAL_NAMESPACES, undefined, async scope => {
          await scope.drainMutations(async () => { trace.push("5:namespace-drained"); });
        });
      });
    });
    expect(trace).toEqual(["1:custody", "2:admission", "3:corpus", "2:admission", "3:corpus", "4:fence-enter", "5:namespace-drained", "4:fence-release"]);
  });

  it("long live holder is never expired or taken over; only actual contention gets storage_busy", async () => {
    const r = await rig(); const held = sdwDeferred(); const release = sdwDeferred();
    const holder = withExitAdmissionLock(r.storage, "import", async () => { held.resolve(); await release.promise; }); await held.promise;
    try {
      const onContended = vi.fn();
      const original = r.storage.withNamespaceLock.bind(r.storage);
      r.storage.withNamespaceLock = (ns, name, operation, options) => original(ns, name, operation, { ...options, onContended });
      // Hold beyond the real ten-second wait: neither age nor timeout grants takeover.
      await expect(withExitAdmissionLock(r.storage, "import", async () => "overlap")).rejects.toMatchObject({ reason: "storage_busy" });
      expect(onContended).toHaveBeenCalled();
      // A contender's zero acquisition timeout cannot expire the holder.
      for (let wave = 0; wave < 3; wave++) await expect(withSdwJournalAdmission(r.storage, async () => {})).rejects.toBeInstanceOf(ExitAdmissionLockError);
      expect((await readdir(join(r.root, EXIT_IMPORT_JOURNAL_NAMESPACE))).includes(EXIT_ADMISSION_LOCK_FILE)).toBe(true);
    } finally { release.resolve(); await holder; }
    for (const kind of ["io", "operation_aborted", "holder-lost", "capability", "scaffold-integrity", "poisoned", "contention"] as const) {
      const error = new CrossProcessLockError("protected failure", kind);
      await expect(withExitAdmissionLock(r.storage, "import", async () => { throw error; })).rejects.toBe(error);
    }
    r.storage.withNamespaceLock = async () => { throw new CrossProcessLockError("acquire I/O", "io"); };
    await expect(withExitAdmissionLock(r.storage, "import", async () => {})).rejects.toMatchObject({ kind: "io" });
  });

  it("non-filesystem behavior remains unchanged, missing trusted observer refuses existing state", async () => {
    const memory = new MemoryStorage(); await memory.write(EXIT_IMPORT_JOURNAL_NAMESPACE, "bad", Buffer.from("bad"));
    await expect(withExitAdmissionLock(memory, "import", async () => "unchanged")).resolves.toBe("unchanged");
    const r = await rig(); await mkdir(r.journal, { mode: 0o700 });
    const { FilesystemStorage } = await import("../../src/storage/filesystem.js");
    await expect(withExitAdmissionLock(new FilesystemStorage(r.root), "import", async () => "untrusted")).rejects.toMatchObject({ reason: "storage_capability_unavailable" });
  });
  it("present-root preflight does not create fence.lock or spawn a process", async () => {
    const r = await rig(); await r.publish("APPLIED");
    const before = await readdir(r.journal);
    const { default: processTools } = await import("node:child_process");
    const spawn = vi.spyOn(processTools, "spawn"); const fork = vi.spyOn(processTools, "fork");
    await withExitAdmissionLock(r.storage, "rotate", async () => {});
    expect(await readdir(r.journal)).toEqual(before);
    expect(r.counters.fences).toBe(0); expect(spawn).not.toHaveBeenCalled(); expect(fork).not.toHaveBeenCalled();
  });

});
