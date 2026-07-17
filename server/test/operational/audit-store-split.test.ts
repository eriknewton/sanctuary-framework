/**
 * F2 Option A — fortress audit store split by writer: migration orchestration
 * + daemon-namespace remapping + the honest dual-chain reader.
 *
 * `audit-log-store-split-boundary.test.ts` covers the lower-level `AuditLog`
 * load-path mechanism (skip + seed-override) this migration produces the
 * boundary record for.
 *
 * These tests run as a single (non-root) process, so they cannot reproduce
 * the actual cross-uid permission wall F2 describes. What they DO prove:
 *   - the migration is idempotent and crash-safe (simulated via partial-state
 *     fixtures, never real process kills);
 *   - the daemon namespace remap genuinely lands bytes under `_audit-daemon`
 *     on disk, distinct from `_audit`;
 *   - `verifyFortressAuditFullPicture` reports each chain's verdict honestly,
 *     including the `present_unreadable` state (reproduced here via a real
 *     chmod 0000 on the daemon namespace directory, which a non-root test
 *     process is genuinely denied by, exactly like a non-root operator on an
 *     armed box).
 * What only the armed-box Mini1 re-drill can prove: an ACTUAL root-owned
 * `_audit-daemon` directory (created by a real root-privileged daemon
 * process) being unreadable to the real operator uid, and the real
 * `sanctuary castle-wall daemon` startup path invoking this migration.
 */

import { chmod, mkdtemp, readFile, readdir, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  AuditLog,
  readAuditStoreSplitBoundary,
  deriveAuditStoreSplitBoundaryMacKey,
} from "../../src/operational/audit-log.js";
import {
  AUDIT_DAEMON_NAMESPACE,
  AUDIT_STORE_SPLIT_MIGRATION_OP,
  AuditStoreSplitMigrationError,
  DaemonAuditStorageAdapter,
  createDaemonAuditLog,
  daemonMigrationEstablished,
  errnoAccessReason,
  migrateFortressAuditStoreSplit,
  resolveDaemonStorePresence,
  verifyFortressAuditFullPicture,
  verifySealedLegacyPrefix,
} from "../../src/operational/audit-store-split.js";
import { generateRandomKey } from "../../src/core/random.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

describe("F2 Option A: fortress audit store split", () => {
  const dirs: string[] = [];

  afterEach(async () => {
    for (const d of dirs.splice(0)) {
      await chmod(d, 0o700).catch(() => undefined);
      const daemonDir = join(d, "state", AUDIT_DAEMON_NAMESPACE);
      await chmod(daemonDir, 0o700).catch(() => undefined);
      await rm(d, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  async function makeFortress() {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-audit-store-split-"));
    dirs.push(root);
    const statePath = join(root, "state");
    const storage = new FilesystemStorage(statePath);
    const masterKey = generateRandomKey();
    return { root, statePath, storage, masterKey };
  }

  describe("DaemonAuditStorageAdapter (namespace remap)", () => {
    it("remaps _audit -> _audit-daemon and _audit_checkpoints -> _audit-daemon_checkpoints, leaving the operator namespace untouched", async () => {
      const { statePath, storage } = await makeFortress();
      const adapter = new DaemonAuditStorageAdapter(storage);
      await adapter.write("_audit", "entry-1", new TextEncoder().encode("x"));

      const onDisk = await readdir(join(statePath, AUDIT_DAEMON_NAMESPACE));
      expect(onDisk.length).toBeGreaterThan(0);
      // Nothing landed in the real operator `_audit` directory.
      await expect(readdir(join(statePath, "_audit"))).rejects.toMatchObject({
        code: "ENOENT",
      });

      const read = await adapter.read("_audit", "entry-1");
      expect(new TextDecoder().decode(read!)).toBe("x");
    });

    it("remaps _meta (the chain-established marker) to its own dedicated namespace, never the real shared _meta", async () => {
      const { statePath, storage } = await makeFortress();
      const adapter = new DaemonAuditStorageAdapter(storage);
      await adapter.write("_meta", "audit-head-anchor-established-v1", new TextEncoder().encode("1"));

      await expect(readdir(join(statePath, "_meta"))).rejects.toMatchObject({
        code: "ENOENT",
      });
      const onDisk = await readdir(join(statePath, "_audit-daemon_meta"));
      expect(onDisk.length).toBeGreaterThan(0);
    });

    it("fails closed on any namespace it does not know how to remap", async () => {
      const { storage } = await makeFortress();
      const adapter = new DaemonAuditStorageAdapter(storage);
      await expect(
        adapter.write("_something_else", "k", new Uint8Array())
      ).rejects.toThrow(/refusing to touch unexpected namespace/);
      await expect(adapter.read("_identities", "k")).rejects.toThrow(
        /refusing to touch unexpected namespace/
      );
    });

    it("createDaemonAuditLog forces consultSplitBoundary: false regardless of caller config", async () => {
      const { storage, masterKey } = await makeFortress();
      // Passing a truthy override must be overridden back to false internally
      // (proven indirectly: the daemon log must ignore an operator-namespace
      // boundary even if one existed, since it never even reads that path).
      const log = createDaemonAuditLog(storage, masterKey, {
        consultSplitBoundary: true,
      });
      await log.appendCritical({
        layer: "l2",
        operation: "probe",
        identity_id: "id",
        result: "success",
      });
      await log.flush();
      await expect(log.getIntegrityFindings()).resolves.toEqual([]);
    });
  });

  describe("migrateFortressAuditStoreSplit", () => {
    it("migrates a fresh (empty) fortress: sealed_tip_sequence 0, one daemon genesis entry", async () => {
      const { storage, masterKey } = await makeFortress();
      const result = await migrateFortressAuditStoreSplit({ storage, masterKey });
      expect(result.status).toBe("migrated");
      if (result.status !== "migrated") throw new Error("unreachable");
      expect(result.boundary.sealed_tip_sequence).toBe(0);
      expect(result.boundary.daemon_namespace).toBe(AUDIT_DAEMON_NAMESPACE);

      const daemonLog = createDaemonAuditLog(storage, masterKey);
      const head = await daemonLog.getChainHead();
      expect(head.sequence).toBe(1);
      await expect(daemonLog.getIntegrityFindings()).resolves.toEqual([]);
    });

    it("migrates a populated fortress: boundary matches the operator chain's real tip", async () => {
      const { storage, masterKey } = await makeFortress();
      const operatorLog = new AuditLog(storage, masterKey);
      for (let i = 0; i < 5; i++) {
        await operatorLog.appendCritical({
          layer: "l1",
          operation: `op-${i}`,
          identity_id: "id-1",
          result: "success",
        });
      }
      await operatorLog.flush();
      const preHead = await operatorLog.getChainHead();
      expect(preHead.sequence).toBe(5);

      const result = await migrateFortressAuditStoreSplit({
        storage,
        masterKey,
        identityId: "castle-wall-daemon-test",
      });
      expect(result.status).toBe("migrated");
      if (result.status !== "migrated") throw new Error("unreachable");
      expect(result.boundary.sealed_tip_sequence).toBe(5);
      expect(result.boundary.sealed_tip_entry_hash).toBe(preHead.entry_hash);

      // The daemon genesis entry references the sealed tip.
      const daemonLog = createDaemonAuditLog(storage, masterKey);
      const daemonHead = await daemonLog.getChainHead();
      expect(daemonHead.sequence).toBe(1);

      // Operator's OWN AuditLog now loads clean and picks up right after the
      // sealed tip.
      const freshOperatorLog = new AuditLog(storage, masterKey);
      await expect(freshOperatorLog.getIntegrityFindings()).resolves.toEqual([]);
      const postHead = await freshOperatorLog.getChainHead();
      expect(postHead).toEqual(preHead);
    });

    it("is idempotent: a second call returns already-migrated with the identical boundary and does not double-append the daemon marker", async () => {
      const { storage, masterKey } = await makeFortress();
      const operatorLog = new AuditLog(storage, masterKey);
      await operatorLog.appendCritical({
        layer: "l1",
        operation: "op-0",
        identity_id: "id-1",
        result: "success",
      });
      await operatorLog.flush();

      const first = await migrateFortressAuditStoreSplit({ storage, masterKey });
      const second = await migrateFortressAuditStoreSplit({ storage, masterKey });
      expect(second.status).toBe("already-migrated");
      expect(second).toEqual({ status: "already-migrated", boundary: (first as any).boundary });

      const daemonLog = createDaemonAuditLog(storage, masterKey);
      const head = await daemonLog.getChainHead();
      expect(head.sequence).toBe(1); // NOT 2 — no duplicate marker.
    });

    it("crash-safety: a genesis entry already landed in the daemon chain (simulated crash between step 2 and step 3) is not duplicated on retry", async () => {
      const { statePath, storage, masterKey } = await makeFortress();
      const operatorLog = new AuditLog(storage, masterKey);
      await operatorLog.appendCritical({
        layer: "l1",
        operation: "op-0",
        identity_id: "id-1",
        result: "success",
      });
      await operatorLog.flush();
      const head = await operatorLog.getChainHead();

      // Simulate "step 2 already ran, process died before step 3 (the
      // boundary write)": manually land the daemon genesis entry, but write
      // NO boundary record.
      const daemonLog = createDaemonAuditLog(storage, masterKey);
      await daemonLog.appendCritical({
        layer: "l2",
        operation: AUDIT_STORE_SPLIT_MIGRATION_OP,
        identity_id: "castle-wall-daemon",
        result: "success",
        details: {
          legacy_namespace: "_audit",
          legacy_tip_sequence: head.sequence,
          legacy_tip_entry_hash: head.entry_hash,
          daemon_namespace: AUDIT_DAEMON_NAMESPACE,
        },
      });
      await daemonLog.flush();

      const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
      await expect(readAuditStoreSplitBoundary(statePath, macKey)).resolves.toEqual({
        status: "absent",
      });

      // Retry: must detect the pre-existing daemon entry, skip re-appending,
      // and proceed straight to committing the boundary.
      const result = await migrateFortressAuditStoreSplit({ storage, masterKey });
      expect(result.status).toBe("migrated");

      const finalDaemonLog = createDaemonAuditLog(storage, masterKey);
      const finalHead = await finalDaemonLog.getChainHead();
      expect(finalHead.sequence).toBe(1); // still exactly one marker entry
      await expect(finalDaemonLog.getIntegrityFindings()).resolves.toEqual([]);
    });

    it("refuses to overwrite a boundary record that fails MAC authentication", async () => {
      const { statePath, storage, masterKey } = await makeFortress();
      const wrongKey = deriveAuditStoreSplitBoundaryMacKey(generateRandomKey());
      const { writeAuditStoreSplitBoundary } = await import(
        "../../src/operational/audit-log.js"
      );
      await writeAuditStoreSplitBoundary(statePath, wrongKey, {
        sealed_tip_sequence: 0,
        sealed_base_sequence: 0,
        sealed_tip_entry_hash: "GENESIS",
        daemon_namespace: AUDIT_DAEMON_NAMESPACE,
      });

      await expect(
        migrateFortressAuditStoreSplit({ storage, masterKey })
      ).rejects.toThrow(AuditStoreSplitMigrationError);
    });

    it("refuses to seal a genuinely tampered pre-split chain", async () => {
      const { statePath, storage, masterKey } = await makeFortress();
      const operatorLog = new AuditLog(storage, masterKey);
      await operatorLog.appendCritical({
        layer: "l1",
        operation: "op-0",
        identity_id: "id-1",
        result: "success",
      });
      await operatorLog.flush();

      // Corrupt the one entry's content (flip a byte) — since this test runs
      // as a single non-root process, the migration CAN read the corrupted
      // file (proving the finding comes from genuine tamper detection, not
      // from a permission wall).
      const auditDir = join(statePath, "_audit");
      const files = (await readdir(auditDir)).filter((f) => f.startsWith("entry-"));
      expect(files.length).toBe(1);
      const filePath = join(auditDir, files[0]!);
      const { readFile, writeFile } = await import("node:fs/promises");
      const raw = JSON.parse(await readFile(filePath, "utf-8"));
      raw.entry_hash = "0".repeat(64);
      await writeFile(filePath, JSON.stringify(raw));

      await expect(
        migrateFortressAuditStoreSplit({ storage, masterKey })
      ).rejects.toThrow(AuditStoreSplitMigrationError);

      // No boundary was written — the legacy chain is untouched, not
      // silently sealed over a real problem.
      const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
      await expect(readAuditStoreSplitBoundary(statePath, macKey)).resolves.toEqual({
        status: "absent",
      });
    });
  });

  describe("verifyFortressAuditFullPicture", () => {
    it("fresh fortress: operator verified (empty), daemon absent", async () => {
      const { storage, masterKey } = await makeFortress();
      const report = await verifyFortressAuditFullPicture({ storage, masterKey });
      expect(report.operator.status).toBe("verified");
      expect(report.daemon.status).toBe("absent");
    });

    it("after migration, both chains readable at this (same-uid) privilege: both verified", async () => {
      const { storage, masterKey } = await makeFortress();
      const operatorLog = new AuditLog(storage, masterKey);
      await operatorLog.appendCritical({
        layer: "l1",
        operation: "op-0",
        identity_id: "id-1",
        result: "success",
      });
      await operatorLog.flush();
      await migrateFortressAuditStoreSplit({ storage, masterKey });

      const report = await verifyFortressAuditFullPicture({ storage, masterKey });
      expect(report.operator.status).toBe("verified");
      expect(report.daemon.status).toBe("verified");
    });

    it("no master key supplied: both chains report key_unavailable (daemon chain present)", async () => {
      const { storage, masterKey } = await makeFortress();
      await migrateFortressAuditStoreSplit({ storage, masterKey });
      const report = await verifyFortressAuditFullPicture({ storage });
      expect(report.operator.status).toBe("key_unavailable");
      expect(report.daemon.status).toBe("key_unavailable");
    });

    it("daemon chain present but unreadable at this privilege: reports present_unreadable, NEVER verified, NEVER silently skipped", async () => {
      const { statePath, storage, masterKey } = await makeFortress();
      await migrateFortressAuditStoreSplit({ storage, masterKey });

      const daemonDir = join(statePath, AUDIT_DAEMON_NAMESPACE);
      await chmod(daemonDir, 0o000);
      try {
        const report = await verifyFortressAuditFullPicture({ storage, masterKey });
        expect(report.operator.status).toBe("verified");
        // The contract: NEVER "verified" when this privilege genuinely could
        // not open the store, regardless of what prose the note uses.
        expect(report.daemon.status).toBe("present_unreadable");
        expect(report.daemon.status).not.toBe("verified");
        expect(report.daemon.finding_count).toBeUndefined();
      } finally {
        await chmod(daemonDir, 0o755);
      }
    });

    // BLOCKER-1(b)/(c): the operator report now attaches a `sealed_region`
    // verdict and reserves a bare "verified" for a fully-verified sealed region.
    it("after migration of a populated chain, operator status is verified WITH a sealed_region: verified verdict", async () => {
      const { storage, masterKey } = await makeFortress();
      const operatorLog = new AuditLog(storage, masterKey);
      for (let i = 0; i < 3; i++) {
        await operatorLog.appendCritical({
          layer: "l1",
          operation: `op-${i}`,
          identity_id: "id-1",
          result: "success",
        });
      }
      await operatorLog.flush();
      await migrateFortressAuditStoreSplit({ storage, masterKey });

      const report = await verifyFortressAuditFullPicture({ storage, masterKey });
      expect(report.operator.status).toBe("verified");
      expect(report.operator.sealed_region?.status).toBe("verified");
    });

    it("BLOCKER-1(c): an unreadable sealed region downgrades operator status to verified_suffix_only, never bare verified", async () => {
      const { statePath, storage, masterKey } = await makeFortress();
      const operatorLog = new AuditLog(storage, masterKey);
      for (let i = 0; i < 3; i++) {
        await operatorLog.appendCritical({
          layer: "l1",
          operation: `op-${i}`,
          identity_id: "id-1",
          result: "success",
        });
      }
      await operatorLog.flush();
      await migrateFortressAuditStoreSplit({ storage, masterKey });

      // Make the sealed entries unreadable (chmod the individual files, not the
      // dir, so the listing still succeeds and stays "complete").
      const auditDir = join(statePath, "_audit");
      const files = (await readdir(auditDir)).filter((f) => f.startsWith("entry-"));
      for (const f of files) await chmod(join(auditDir, f), 0o000);
      try {
        const report = await verifyFortressAuditFullPicture({ storage, masterKey });
        expect(report.operator.status).toBe("verified_suffix_only");
        expect(report.operator.status).not.toBe("verified");
        expect(report.operator.sealed_region?.status).toBe("unreadable");
      } finally {
        for (const f of files) await chmod(join(auditDir, f), 0o600).catch(() => undefined);
      }
    });

    it("BLOCKER-1(b): in-place content tampering of a sealed entry is caught by the crypto walk (operator status findings, sealed_region hash_mismatch)", async () => {
      const { statePath, storage, masterKey } = await makeFortress();
      const operatorLog = new AuditLog(storage, masterKey);
      for (let i = 0; i < 3; i++) {
        await operatorLog.appendCritical({
          layer: "l1",
          operation: `op-${i}`,
          identity_id: "id-1",
          result: "success",
        });
      }
      await operatorLog.flush();
      await migrateFortressAuditStoreSplit({ storage, masterKey });

      // Corrupt a sealed entry's payload but leave the stored entry_hash (so the
      // recompute mismatches). File still present → listing complete → the ONLY
      // detector is the crypto walk.
      const auditDir = join(statePath, "_audit");
      const files = (await readdir(auditDir)).filter((f) => f.startsWith("entry-")).sort();
      const target = join(auditDir, files[1]!); // a middle sealed entry
      const raw = JSON.parse(await readFile(target, "utf-8"));
      raw.encrypted_payload_bytes = raw.encrypted_payload_bytes + "AAAA";
      await writeFile(target, JSON.stringify(raw));

      const report = await verifyFortressAuditFullPicture({ storage, masterKey });
      expect(report.operator.status).toBe("findings");
      expect(report.operator.sealed_region?.status).toBe("hash_mismatch");
    });
  });

  describe("verifySealedLegacyPrefix (root sealed-prefix crypto verifier)", () => {
    async function migratedFortress(n: number) {
      const f = await makeFortress();
      const log = new AuditLog(f.storage, f.masterKey);
      for (let i = 0; i < n; i++) {
        await log.appendCritical({
          layer: "l1",
          operation: `op-${i}`,
          identity_id: "id-1",
          result: "success",
        });
      }
      await log.flush();
      await migrateFortressAuditStoreSplit({ storage: f.storage, masterKey: f.masterKey });
      return f;
    }

    it("not_present when there is no valid boundary", async () => {
      const { storage, masterKey } = await makeFortress();
      const log = new AuditLog(storage, masterKey);
      await log.appendCritical({ layer: "l1", operation: "x", identity_id: "id", result: "success" });
      await log.flush();
      const verdict = await verifySealedLegacyPrefix(storage, masterKey);
      expect(verdict.status).toBe("not_present");
    });

    it("empty when the migration sealed an empty chain", async () => {
      const { storage, masterKey } = await makeFortress();
      await migrateFortressAuditStoreSplit({ storage, masterKey });
      const verdict = await verifySealedLegacyPrefix(storage, masterKey);
      expect(verdict.status).toBe("empty");
    });

    it("verified when the sealed region is intact", async () => {
      const { storage, masterKey } = await migratedFortress(4);
      const verdict = await verifySealedLegacyPrefix(storage, masterKey);
      expect(verdict.status).toBe("verified");
      if (verdict.status === "verified") {
        expect(verdict.entries_verified).toBe(4);
        expect(verdict.sealed_tip_sequence).toBe(4);
      }
    });

    it("incomplete when a sealed entry is deleted", async () => {
      const { statePath, storage, masterKey } = await migratedFortress(4);
      const auditDir = join(statePath, "_audit");
      const files = (await readdir(auditDir)).filter((f) => f.startsWith("entry-")).sort();
      await unlink(join(auditDir, files[files.length - 1]!)); // delete the tip
      const verdict = await verifySealedLegacyPrefix(storage, masterKey);
      expect(verdict.status).toBe("incomplete");
    });

    it("hash_mismatch when a sealed entry's content is tampered in place", async () => {
      const { statePath, storage, masterKey } = await migratedFortress(4);
      const auditDir = join(statePath, "_audit");
      const files = (await readdir(auditDir)).filter((f) => f.startsWith("entry-")).sort();
      const target = join(auditDir, files[2]!);
      const raw = JSON.parse(await readFile(target, "utf-8"));
      raw.timestamp = "1999-01-01T00:00:00.000Z"; // covered by the entry hash
      await writeFile(target, JSON.stringify(raw));
      const verdict = await verifySealedLegacyPrefix(storage, masterKey);
      expect(verdict.status).toBe("hash_mismatch");
    });

    it("unreadable when a sealed entry cannot be read at this privilege", async () => {
      const { statePath, storage, masterKey } = await migratedFortress(3);
      const auditDir = join(statePath, "_audit");
      const files = (await readdir(auditDir)).filter((f) => f.startsWith("entry-"));
      for (const f of files) await chmod(join(auditDir, f), 0o000);
      try {
        const verdict = await verifySealedLegacyPrefix(storage, masterKey);
        expect(verdict.status).toBe("unreadable");
      } finally {
        for (const f of files) await chmod(join(auditDir, f), 0o600).catch(() => undefined);
      }
    });

    // BLOCKER-R1: deleting the LOWEST sealed entry (sequence == base) was the
    // first-round residual; the MAC'd sealed_base_sequence now catches it.
    it("BLOCKER-R1: incomplete when the LOWEST sealed entry is deleted (base residual closed)", async () => {
      const { statePath, storage, masterKey } = await migratedFortress(4);
      const auditDir = join(statePath, "_audit");
      const files = (await readdir(auditDir)).filter((f) => f.startsWith("entry-")).sort();
      await unlink(join(auditDir, files[0]!)); // delete the bottom (seq 1)
      const verdict = await verifySealedLegacyPrefix(storage, masterKey);
      expect(verdict.status).toBe("incomplete");
    });

    it("BLOCKER-R1: the migrated boundary records sealed_base_sequence = 1 for a genesis-based chain", async () => {
      const { storage, masterKey } = await migratedFortress(4);
      const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
      const statePath = storage.namespacePath("_audit").replace(/\/_audit$/, "");
      const boundary = await readAuditStoreSplitBoundary(statePath, macKey);
      expect(boundary.status).toBe("valid");
      if (boundary.status === "valid") {
        expect(boundary.boundary.sealed_base_sequence).toBe(1);
        expect(boundary.boundary.sealed_tip_sequence).toBe(4);
      }
    });
  });

  describe("BLOCKER-R2: boundary-loss fail-closed does not depend on the daemon namespace set", () => {
    async function migratedWithSuffix(operatorEntries: number, suffixEntries: number) {
      const f = await makeFortress();
      const op = new AuditLog(f.storage, f.masterKey);
      for (let i = 0; i < operatorEntries; i++) {
        await op.appendCritical({ layer: "l1", operation: `op-${i}`, identity_id: "id", result: "success" });
      }
      await op.flush();
      await migrateFortressAuditStoreSplit({ storage: f.storage, masterKey: f.masterKey });
      // Post-split operator suffix (writes a head anchor for the suffix).
      const suffix = new AuditLog(f.storage, f.masterKey);
      for (let i = 0; i < suffixEntries; i++) {
        await suffix.appendCritical({ layer: "l1", operation: `post-${i}`, identity_id: "id", result: "success" });
      }
      await suffix.flush();
      return f;
    }

    it("REQUIRED REPRO: delete _audit_migration + ALL _audit-daemon* namespaces + the sealed prefix -> split_boundary_missing and NO rotation anchor written", async () => {
      const { root, statePath, storage, masterKey } = await migratedWithSuffix(2, 2);

      // The attack: strip every co-deletable migration marker + the boundary +
      // the sealed prefix, leaving a contiguous above-genesis suffix.
      await rm(join(statePath, "_audit_migration"), { recursive: true, force: true });
      for (const ns of ["_audit-daemon", "_audit-daemon_checkpoints", "_audit-daemon_meta"]) {
        await rm(join(statePath, ns), { recursive: true, force: true });
      }
      const auditDir = join(statePath, "_audit");
      for (const fn of (await readdir(auditDir)).filter((x) => x.startsWith("entry-"))) {
        const seq = Number(/^entry-(\d{20})-/.exec(fn)?.[1] ?? "0");
        if (seq >= 1 && seq <= 2) await unlink(join(auditDir, fn)); // the sealed prefix
      }

      const reader = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
      const findings = await reader.getIntegrityFindings();
      // The durable `_meta` established marker (NOT co-deletable with the daemon
      // namespaces) makes this fail closed.
      expect(findings.some((x) => x.kind === "split_boundary_missing")).toBe(true);
      // No fresh rotation anchor was written to bless the truncated suffix.
      const anchor = await storage.read("_audit_checkpoints", "__rotation_anchor");
      expect(anchor).toBeNull();
      void root;
    });

    it("the durable _meta established marker survives daemon-namespace deletion (the whole point)", async () => {
      const { statePath, storage, masterKey } = await migratedWithSuffix(1, 1);
      for (const ns of ["_audit-daemon", "_audit-daemon_checkpoints", "_audit-daemon_meta"]) {
        await rm(join(statePath, ns), { recursive: true, force: true });
      }
      await rm(join(statePath, "_audit_migration"), { recursive: true, force: true });
      // The established marker in `_meta` is still present.
      expect(await storage.exists("_meta", "audit-store-split-established-v1")).toBe(true);
      void masterKey;
    });

    // F2 HIGH-1 (round 3): the marker read is TRI-STATE. A present-but-corrupt
    // established marker is NOT "absent"; it counts as migration evidence and
    // fails closed. This closes the "corrupt the last witness" fail-open where
    // an attacker who cannot delete the marker cleanly scribbles over it.
    it("REQUIRED REPRO (HIGH-1a): CORRUPT the _meta established marker (not deletable) -> still split_boundary_missing, NO anchor", async () => {
      const { statePath, storage, masterKey } = await migratedWithSuffix(2, 2);

      // Strip boundary + daemon namespaces + sealed prefix, as before.
      await rm(join(statePath, "_audit_migration"), { recursive: true, force: true });
      for (const ns of ["_audit-daemon", "_audit-daemon_checkpoints", "_audit-daemon_meta"]) {
        await rm(join(statePath, ns), { recursive: true, force: true });
      }
      const auditDir = join(statePath, "_audit");
      for (const fn of (await readdir(auditDir)).filter((x) => x.startsWith("entry-"))) {
        const seq = Number(/^entry-(\d{20})-/.exec(fn)?.[1] ?? "0");
        if (seq >= 1 && seq <= 2) await unlink(join(auditDir, fn));
      }
      // ALSO corrupt the established marker in place (bad MAC / bad JSON) rather
      // than deleting it: tri-state read must classify this as evidence.
      const markerDir = join(statePath, "_meta");
      const markerFile = (await readdir(markerDir)).find((x) =>
        x.startsWith("audit-store-split-established-v1"),
      );
      expect(markerFile).toBeDefined();
      await writeFile(join(markerDir, markerFile as string), "corrupt-not-json", "utf8");

      const reader = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
      const findings = await reader.getIntegrityFindings();
      expect(findings.some((x) => x.kind === "split_boundary_missing")).toBe(true);
      const anchor = await storage.read("_audit_checkpoints", "__rotation_anchor");
      expect(anchor).toBeNull();
    });

    // F2 HIGH-1 (round 3, part b): the irreducible residual. If the attacker
    // DOES manage to delete every witness (boundary + daemon namespaces + the
    // `_meta` marker) AND the sealed prefix, the surviving suffix starts above
    // genesis with no authenticated rotation anchor. That shape is ITSELF
    // evidence of a deleted prefix and is never TOFU-blessed: it fails closed
    // with `rotation_anchor_missing` and writes NO anchor.
    it("REQUIRED REPRO (HIGH-1b): DELETE the _meta marker too -> above-genesis suffix fails closed, NO anchor", async () => {
      const { statePath, storage, masterKey } = await migratedWithSuffix(2, 2);

      await rm(join(statePath, "_audit_migration"), { recursive: true, force: true });
      for (const ns of ["_audit-daemon", "_audit-daemon_checkpoints", "_audit-daemon_meta"]) {
        await rm(join(statePath, ns), { recursive: true, force: true });
      }
      await rm(join(statePath, "_meta"), { recursive: true, force: true });
      const auditDir = join(statePath, "_audit");
      for (const fn of (await readdir(auditDir)).filter((x) => x.startsWith("entry-"))) {
        const seq = Number(/^entry-(\d{20})-/.exec(fn)?.[1] ?? "0");
        if (seq >= 1 && seq <= 2) await unlink(join(auditDir, fn));
      }

      const reader = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
      const findings = await reader.getIntegrityFindings();
      // No witness survives, but the above-genesis suffix without an
      // authenticated anchor is itself the tell: fail closed, never self-heal.
      expect(findings.length).toBeGreaterThan(0);
      const anchor = await storage.read("_audit_checkpoints", "__rotation_anchor");
      expect(anchor).toBeNull();
    });
  });

  describe("resolveDaemonStorePresence (C1 marker-aware census/export chokepoint)", () => {
    it("absent on a genuinely fresh (never-migrated) fortress", async () => {
      const { storage, masterKey } = await makeFortress();
      expect(await resolveDaemonStorePresence(storage, masterKey)).toEqual({
        kind: "absent",
      });
      expect(await daemonMigrationEstablished(storage, masterKey)).toBe(false);
    });

    it("accessible on a migrated fortress with an intact daemon store", async () => {
      const { storage, masterKey } = await makeFortress();
      const auditLog = new AuditLog(storage, masterKey);
      await auditLog.appendCritical({
        layer: "l1",
        operation: "op",
        identity_id: "a",
        result: "success",
      });
      await auditLog.flush();
      await migrateFortressAuditStoreSplit({ storage, masterKey });
      expect(await daemonMigrationEstablished(storage, masterKey)).toBe(true);
      expect(await resolveDaemonStorePresence(storage, masterKey)).toEqual({
        kind: "accessible",
      });
    });

    it("missing (NOT absent) when the daemon store was deleted after migration", async () => {
      const { statePath, storage, masterKey } = await makeFortress();
      const auditLog = new AuditLog(storage, masterKey);
      await auditLog.appendCritical({
        layer: "l1",
        operation: "op",
        identity_id: "a",
        result: "success",
      });
      await auditLog.flush();
      await migrateFortressAuditStoreSplit({ storage, masterKey });
      await rm(join(statePath, AUDIT_DAEMON_NAMESPACE), {
        recursive: true,
        force: true,
      });
      // The established marker in _meta survives the daemon-dir deletion, so this
      // is evidence destruction, not a never-provisioned fortress.
      expect(await resolveDaemonStorePresence(storage, masterKey)).toEqual({
        kind: "missing",
      });
    });

    it("missing on a BOUNDARY-ONLY fortress (daemon dir AND _meta marker deleted, boundary survives)", async () => {
      const { statePath, storage, masterKey } = await makeFortress();
      const auditLog = new AuditLog(storage, masterKey);
      await auditLog.appendCritical({
        layer: "l1",
        operation: "op",
        identity_id: "a",
        result: "success",
      });
      await auditLog.flush();
      await migrateFortressAuditStoreSplit({ storage, masterKey });
      await rm(join(statePath, AUDIT_DAEMON_NAMESPACE), {
        recursive: true,
        force: true,
      });
      await storage.delete("_meta", "audit-store-split-established-v1");
      // The MAC'd boundary record alone still proves the migration ran.
      expect(await daemonMigrationEstablished(storage, masterKey)).toBe(true);
      expect(await resolveDaemonStorePresence(storage, masterKey)).toEqual({
        kind: "missing",
      });
    });

    it("present_unreadable with a privilege reason when the daemon dir is not listable", async () => {
      if (typeof process.getuid === "function" && process.getuid() === 0) {
        return; // root bypasses mode bits
      }
      const { statePath, storage, masterKey } = await makeFortress();
      const auditLog = new AuditLog(storage, masterKey);
      await auditLog.appendCritical({
        layer: "l1",
        operation: "op",
        identity_id: "a",
        result: "success",
      });
      await auditLog.flush();
      await migrateFortressAuditStoreSplit({ storage, masterKey });
      await chmod(join(statePath, AUDIT_DAEMON_NAMESPACE), 0o000);
      expect(await resolveDaemonStorePresence(storage, masterKey)).toEqual({
        kind: "present_unreadable",
        reason: "privilege",
      });
    });

    it("fail-closed: a present-but-UNVERIFIABLE boundary file (junk) on an otherwise-fresh fortress -> established -> missing", async () => {
      // Fix-4 raw-stat existence check: a boundary file that readAuditStoreSplitBoundary
      // would launder to `absent` (junk / unreadable) still counts as split
      // evidence, so the daemon store reads `missing` (fail closed), never a clean
      // `absent`. The disclosure wording hedges accordingly (see the pack tests).
      const { statePath, storage, masterKey } = await makeFortress();
      const { mkdir, writeFile } = await import("node:fs/promises");
      const { auditStoreSplitBoundaryPath } = await import(
        "../../src/operational/audit-log.js"
      );
      const boundaryPath = auditStoreSplitBoundaryPath(statePath);
      await mkdir(join(boundaryPath, ".."), { recursive: true });
      await writeFile(boundaryPath, "not-a-valid-boundary-record", "utf8");
      expect(await daemonMigrationEstablished(storage, masterKey)).toBe(true);
      expect(await resolveDaemonStorePresence(storage, masterKey)).toEqual({
        kind: "missing",
      });
    });

    it("errnoAccessReason classifies EACCES/EPERM as privilege, else io", () => {
      expect(errnoAccessReason(Object.assign(new Error("x"), { code: "EACCES" }))).toBe(
        "privilege"
      );
      expect(
        errnoAccessReason(
          Object.assign(new Error("x"), {
            cause: Object.assign(new Error("y"), { code: "EPERM" }),
          })
        )
      ).toBe("privilege");
      expect(errnoAccessReason(Object.assign(new Error("x"), { code: "EIO" }))).toBe("io");
    });
  });
});
