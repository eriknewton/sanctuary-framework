/**
 * F2 Option A — fortress audit store split-boundary regression tests
 * (`AuditLog`-level: the load-path skip + seed-override mechanism).
 *
 * These exercise the mechanism `operational/audit-log.ts` itself owns: given
 * a valid split-boundary record, `ensureLoaded()` never attempts to read the
 * sealed legacy region and seeds the chain walk from the boundary instead of
 * genesis. `operational/audit-store-split.test.ts` covers the higher-level
 * migration orchestration and the daemon-namespace remapping.
 *
 * Requires a REAL filesystem-backed `FilesystemStorage` (not `MemoryStorage`):
 * the split-boundary record lives outside the `StorageBackend` contract, at a
 * raw path derived from `FilesystemStorageCapabilities.namespacePath`, which
 * `MemoryStorage` does not implement.
 */

import {
  chmod,
  mkdtemp,
  readFile,
  readdir,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  AuditLog,
  writeAuditStoreSplitBoundary,
  readAuditStoreSplitBoundary,
  deriveAuditStoreSplitBoundaryMacKey,
} from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

describe("AuditLog split-boundary consultation (F2 Option A)", () => {
  const dirs: string[] = [];

  afterEach(async () => {
    for (const d of dirs.splice(0)) {
      // A test may have chmod'd a subdirectory to 0000; restore write/exec
      // before recursive removal so cleanup itself does not fail.
      await chmod(d, 0o700).catch(() => undefined);
      await rm(d, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  async function makeFortress() {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-audit-split-boundary-"));
    dirs.push(root);
    const statePath = join(root, "state");
    const masterKey = generateRandomKey();
    return { statePath, masterKey };
  }

  async function appendN(log: AuditLog, n: number, prefix = "op"): Promise<void> {
    for (let i = 0; i < n; i++) {
      await log.appendCritical({
        layer: "l1",
        operation: `${prefix}-${i}`,
        identity_id: "id-1",
        result: "success",
        details: { i },
      });
    }
    await log.flush();
  }

  it("no boundary file: behavior is unchanged (control case)", async () => {
    const { statePath, masterKey } = await makeFortress();
    const storage = new FilesystemStorage(statePath);
    const log = new AuditLog(storage, masterKey);
    await appendN(log, 3);
    await expect(log.getIntegrityFindings()).resolves.toEqual([]);
    const head = await log.getChainHead();
    expect(head.sequence).toBe(3);
  });

  // BLOCKER-1 (adversarial gate 2026-07-14) REGRESSION: this REPLACES the
  // former "deletion is clean" test, which encoded the evidence-suppression
  // vector the gate flagged. Deleting sealed legacy entries under a valid
  // boundary MUST now surface a `sealed_prefix_incomplete` finding (detected
  // from the directory LISTING, so it works even when the entries would be
  // unreadable). The boundary is a floor, not a waiver.
  it("BLOCKER-1: deleting sealed legacy entries under a valid boundary yields a sealed_prefix_incomplete finding (deletion is NOT clean)", async () => {
    const { statePath, masterKey } = await makeFortress();
    const storage = new FilesystemStorage(statePath);

    const legacy = new AuditLog(storage, masterKey);
    await appendN(legacy, 3);
    const head = await legacy.getChainHead();
    expect(head.sequence).toBe(3);

    const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
    await writeAuditStoreSplitBoundary(statePath, macKey, {
      sealed_tip_sequence: head.sequence,
      sealed_tip_entry_hash: head.entry_hash,
      daemon_namespace: "_audit-daemon",
    });

    // Intact sealed region loads clean (skip works, region complete).
    const before = new AuditLog(storage, masterKey);
    await expect(before.getIntegrityFindings()).resolves.toEqual([]);

    // Delete every sealed entry. A directory-write-capable attacker can do this
    // without the master key.
    const auditDir = join(statePath, "_audit");
    const files = (await readdir(auditDir)).filter((f) => f.startsWith("entry-"));
    expect(files.length).toBe(3);
    for (const f of files) {
      await unlink(join(auditDir, f)).catch(() => undefined);
    }

    // Now the sealed prefix is gone: a finding, never a clean load.
    const after = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const findings = await after.getIntegrityFindings();
    expect(findings.some((f) => f.kind === "sealed_prefix_incomplete")).toBe(true);
  });

  // BLOCKER-1 REGRESSION: deleting only the TOP sealed entry (truncation of the
  // sealed prefix's tip) is also detected via the listing completeness check.
  it("BLOCKER-1: deleting the top sealed entry yields a sealed_prefix_incomplete finding (highest present < tip)", async () => {
    const { statePath, masterKey } = await makeFortress();
    const storage = new FilesystemStorage(statePath);
    const legacy = new AuditLog(storage, masterKey);
    await appendN(legacy, 3);
    const head = await legacy.getChainHead();

    const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
    await writeAuditStoreSplitBoundary(statePath, macKey, {
      sealed_tip_sequence: head.sequence,
      sealed_tip_entry_hash: head.entry_hash,
      daemon_namespace: "_audit-daemon",
    });

    // Delete only the sequence-3 (tip) entry.
    const auditDir = join(statePath, "_audit");
    const files = (await readdir(auditDir)).filter((f) => f.startsWith("entry-"));
    const topFile = files.sort()[files.length - 1]!;
    await unlink(join(auditDir, topFile));

    const after = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const findings = await after.getIntegrityFindings();
    const f = findings.find((x) => x.kind === "sealed_prefix_incomplete");
    expect(f).toBeDefined();
    expect(f!.actual).toBe(2);
    expect(f!.expected).toBe(3);
  });

  // The skip itself (unreadable-but-present sealed entries load clean) is
  // proven by the chmod-fidelity test below; the intact-and-present happy path:
  it("a valid boundary with an intact sealed region loads clean and continues the chain from the sealed tip", async () => {
    const { statePath, masterKey } = await makeFortress();
    const storage = new FilesystemStorage(statePath);
    const legacy = new AuditLog(storage, masterKey);
    await appendN(legacy, 3);
    const head = await legacy.getChainHead();

    const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
    await writeAuditStoreSplitBoundary(statePath, macKey, {
      sealed_tip_sequence: head.sequence,
      sealed_tip_entry_hash: head.entry_hash,
      daemon_namespace: "_audit-daemon",
    });

    const sealed = new AuditLog(storage, masterKey);
    await expect(sealed.getIntegrityFindings()).resolves.toEqual([]);
    expect(await sealed.getChainHead()).toEqual(head);

    await sealed.appendCritical({
      layer: "l1",
      operation: "post-split-1",
      identity_id: "id-1",
      result: "success",
    });
    await sealed.flush();
    expect((await sealed.getChainHead()).sequence).toBe(4);
    await expect(sealed.getIntegrityFindings()).resolves.toEqual([]);
  });

  it("F2 repro fidelity: chmod 0000 (EACCES, not delete) on the legacy entries is what a root-owned/operator-unreadable file actually looks like, and the boundary skips it the same way", async () => {
    const { statePath, masterKey } = await makeFortress();
    const storage = new FilesystemStorage(statePath);

    const legacy = new AuditLog(storage, masterKey);
    await appendN(legacy, 3);
    const head = await legacy.getChainHead();

    // Simulate root-owned/operator-unreadable entries via chmod 0000 (EACCES
    // on read), NOT deletion — this is the ACTUAL F2 mechanism (the drill's
    // 1612 root-owned entries were never missing, just permission-denied).
    // A non-root test process is genuinely denied by this, exactly like a
    // real non-root operator on an armed box.
    const auditDir = join(statePath, "_audit");
    const files = (await readdir(auditDir)).filter((f) => f.startsWith("entry-"));
    expect(files.length).toBe(3);
    for (const f of files) {
      await chmod(join(auditDir, f), 0o000);
    }

    try {
      // Control: without a boundary, a fresh instance hits real EACCES
      // reads and reports `entry_unreadable` for each (the exact F2
      // symptom: `AuditIntegrityError` on `ensureLoaded`/mint).
      const noBoundary = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
      const controlFindings = await noBoundary.getIntegrityFindings();
      expect(controlFindings.length).toBeGreaterThan(0);
      // At least one genuine `entry_unreadable` (EACCES) finding; the
      // permission-denied reads may also cascade into sequence-gap findings
      // for the forward hash-chain walk, which is fine — the point is that,
      // WITHOUT the boundary, the chmod'd entries are actually attempted and
      // actually fail.
      expect(controlFindings.some((f) => f.kind === "entry_unreadable")).toBe(true);

      // Seal the (now permission-denied) legacy region.
      const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
      await writeAuditStoreSplitBoundary(statePath, macKey, {
        sealed_tip_sequence: head.sequence,
        sealed_tip_entry_hash: head.entry_hash,
        daemon_namespace: "_audit-daemon",
      });

      // A fresh instance never attempts the permission-denied reads at all
      // (never even calls storage.read on them), so it loads clean — this
      // is exactly what unblocks file-grant mint on an armed box.
      const sealed = new AuditLog(storage, masterKey);
      await expect(sealed.getIntegrityFindings()).resolves.toEqual([]);
      await sealed.appendCritical({
        layer: "l1",
        operation: "mint-durable-audit-write",
        identity_id: "id-1",
        result: "success",
      });
      await expect(sealed.flush()).resolves.toBeUndefined();
    } finally {
      for (const f of files) {
        await chmod(join(auditDir, f), 0o600).catch(() => undefined);
      }
    }
  });

  it("chainedEntries.length === 0 immediately after sealing is NOT reported as truncation", async () => {
    const { statePath, masterKey } = await makeFortress();
    const storage = new FilesystemStorage(statePath);
    const legacy = new AuditLog(storage, masterKey);
    await appendN(legacy, 2);
    const head = await legacy.getChainHead();

    const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
    await writeAuditStoreSplitBoundary(statePath, macKey, {
      sealed_tip_sequence: head.sequence,
      sealed_tip_entry_hash: head.entry_hash,
      daemon_namespace: "_audit-daemon",
    });

    // No post-split entry has been written yet: chainedEntries above the
    // boundary is empty. This must be the expected steady state, not a
    // truncation finding.
    const fresh = new AuditLog(storage, masterKey);
    await expect(fresh.getIntegrityFindings()).resolves.toEqual([]);
  });

  // BLOCKER-2 (adversarial gate 2026-07-14) REGRESSION: this REPLACES the former
  // "tampered boundary degrades to absent / no findings" test, which let a
  // present-but-invalid boundary fail open. A present-but-invalid (wrong-key /
  // MAC-mismatch) boundary MUST now surface a `split_boundary_invalid` finding
  // (fail closed), and it must NOT filter the sealed region.
  it("BLOCKER-2: a present-but-invalid (wrong-key MAC) boundary yields a split_boundary_invalid finding", async () => {
    const { statePath, masterKey } = await makeFortress();
    const storage = new FilesystemStorage(statePath);
    const legacy = new AuditLog(storage, masterKey);
    await appendN(legacy, 2);
    const head = await legacy.getChainHead();

    const wrongKey = deriveAuditStoreSplitBoundaryMacKey(generateRandomKey());
    await writeAuditStoreSplitBoundary(statePath, wrongKey, {
      sealed_tip_sequence: head.sequence,
      sealed_tip_entry_hash: head.entry_hash,
      daemon_namespace: "_audit-daemon",
    });

    const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
    await expect(readAuditStoreSplitBoundary(statePath, macKey)).resolves.toEqual({
      status: "invalid",
    });

    const reader = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const findings = await reader.getIntegrityFindings();
    expect(findings.some((f) => f.kind === "split_boundary_invalid")).toBe(true);
  });

  // BLOCKER-2 REGRESSION: marker-stripping (the envelope's marker key removed)
  // reads as `absent` from readAuditStoreSplitBoundary. On a fortress with a
  // daemon migration marker present, that absent-after-migration MUST fail
  // closed as `split_boundary_missing`.
  it("BLOCKER-2: an absent boundary WITH a daemon migration marker yields split_boundary_missing", async () => {
    const { statePath, masterKey } = await makeFortress();
    const storage = new FilesystemStorage(statePath);
    const legacy = new AuditLog(storage, masterKey);
    await appendN(legacy, 2);

    // Simulate "migration ran (daemon namespace exists) but the boundary was
    // deleted": write a daemon entry, write NO boundary.
    await storage.write(
      "_audit-daemon",
      "entry-00000000000000000001-1-0",
      new TextEncoder().encode("{}"),
    );

    const reader = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const findings = await reader.getIntegrityFindings();
    expect(findings.some((f) => f.kind === "split_boundary_missing")).toBe(true);
  });

  // BLOCKER-2 REGRESSION: the combined attack — delete the boundary AND the
  // sealed prefix, leaving a contiguous post-split suffix — must NOT be laundered
  // into an authenticated rotation cut (TOFU suppressed).
  it("BLOCKER-2: boundary deletion + sealed prefix deletion does not TOFU-bless the surviving suffix", async () => {
    const { statePath, masterKey } = await makeFortress();
    const storage = new FilesystemStorage(statePath);

    // Build: 2 sealed entries + a valid boundary + 2 post-split entries.
    const pre = new AuditLog(storage, masterKey);
    await appendN(pre, 2);
    const head = await pre.getChainHead();
    const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
    await writeAuditStoreSplitBoundary(statePath, macKey, {
      sealed_tip_sequence: head.sequence,
      sealed_tip_entry_hash: head.entry_hash,
      daemon_namespace: "_audit-daemon",
    });
    const post = new AuditLog(storage, masterKey);
    await post.appendCritical({ layer: "l1", operation: "p1", identity_id: "id-1", result: "success" });
    await post.appendCritical({ layer: "l1", operation: "p2", identity_id: "id-1", result: "success" });
    await post.flush();
    // A daemon marker exists (migration ran).
    await storage.write(
      "_audit-daemon",
      "entry-00000000000000000001-1-0",
      new TextEncoder().encode("{}"),
    );

    // Attack: delete the boundary record AND the sealed prefix (seq 1,2),
    // leaving only the contiguous suffix (seq 3,4).
    await rm(join(statePath, "_audit_migration"), { recursive: true, force: true });
    const auditDir = join(statePath, "_audit");
    for (const f of (await readdir(auditDir)).filter((x) => x.startsWith("entry-"))) {
      const seq = Number(/^entry-(\d{20})-/.exec(f)?.[1] ?? "0");
      if (seq <= 2) await unlink(join(auditDir, f));
    }

    const reader = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const findings = await reader.getIntegrityFindings();
    // Fail closed: the missing boundary is flagged AND the suffix is not
    // silently re-anchored as a legitimate rotation.
    expect(findings.some((f) => f.kind === "split_boundary_missing")).toBe(true);
    expect(
      findings.some(
        (f) => f.kind === "rotation_anchor_missing" || f.kind === "sequence_gap_or_reorder"
      )
    ).toBe(true);
    // And no fresh rotation anchor was written to bless the truncation.
    const anchor = await storage.read("_audit_checkpoints", "__rotation_anchor");
    expect(anchor).toBeNull();
  });

  it("consultSplitBoundary: false is the actual filter gate (reads sealed content the default instance skips)", async () => {
    const { statePath, masterKey } = await makeFortress();
    const storage = new FilesystemStorage(statePath);
    const legacy = new AuditLog(storage, masterKey);
    await appendN(legacy, 2);
    const head = await legacy.getChainHead();

    const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
    await writeAuditStoreSplitBoundary(statePath, macKey, {
      sealed_tip_sequence: head.sequence,
      sealed_tip_entry_hash: head.entry_hash,
      daemon_namespace: "_audit-daemon",
    });

    // Corrupt a sealed entry's CONTENT in place (file still present, so the
    // listing-completeness check passes; only reading the content reveals it).
    const auditDir = join(statePath, "_audit");
    const files = (await readdir(auditDir)).filter((f) => f.startsWith("entry-")).sort();
    const target = join(auditDir, files[0]!);
    const raw = JSON.parse(await readFile(target, "utf-8"));
    raw.entry_hash = "0".repeat(64);
    await writeFile(target, JSON.stringify(raw));

    // Default (consults the boundary): SKIPS the sealed content, so the routine
    // load stays clean (the in-place tamper is caught by the crypto verifier /
    // audit-store-status, not the routine load — documented M-2 behavior).
    const sealed = new AuditLog(storage, masterKey);
    await expect(sealed.getIntegrityFindings()).resolves.toEqual([]);

    // consultSplitBoundary: false: reads the sealed content and DOES see the
    // corruption, proving the flag is the actual filter gate, not a no-op.
    const unsealed = new AuditLog(storage, masterKey, {
      integrityMode: "lenient",
      consultSplitBoundary: false,
    });
    const findings = await unsealed.getIntegrityFindings();
    expect(findings.length).toBeGreaterThan(0);
  });

  it("present-but-unreadable boundary file (permission-denied at this privilege) degrades to absent, never throws", async () => {
    const { statePath, masterKey } = await makeFortress();
    const storage = new FilesystemStorage(statePath);
    const legacy = new AuditLog(storage, masterKey);
    await appendN(legacy, 1);
    const head = await legacy.getChainHead();

    const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
    await writeAuditStoreSplitBoundary(statePath, macKey, {
      sealed_tip_sequence: head.sequence,
      sealed_tip_entry_hash: head.entry_hash,
      daemon_namespace: "_audit-daemon",
    });

    const boundaryDir = join(statePath, "_audit_migration");
    await chmod(boundaryDir, 0o000);
    try {
      // A non-root reader cannot open the file: readAuditStoreSplitBoundary
      // must degrade to "absent", never throw.
      await expect(
        readAuditStoreSplitBoundary(statePath, macKey)
      ).resolves.toEqual({ status: "absent" });

      // The chain itself is fully intact, so ensureLoaded still succeeds
      // (it just re-walks the whole, still-valid legacy region).
      const reader = new AuditLog(storage, masterKey);
      await expect(reader.getIntegrityFindings()).resolves.toEqual([]);
    } finally {
      await chmod(boundaryDir, 0o755);
    }
  });
});
