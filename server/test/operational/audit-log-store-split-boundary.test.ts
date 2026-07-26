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
import {
  verifySealedLegacyPrefix,
  verifyFortressAuditFullPicture,
} from "../../src/operational/audit-store-split.js";
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
      sealed_base_sequence: head.sequence === 0 ? 0 : 1,
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
      sealed_base_sequence: head.sequence === 0 ? 0 : 1,
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
      sealed_base_sequence: head.sequence === 0 ? 0 : 1,
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
        sealed_base_sequence: head.sequence === 0 ? 0 : 1,
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
      sealed_base_sequence: head.sequence === 0 ? 0 : 1,
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
      sealed_base_sequence: head.sequence === 0 ? 0 : 1,
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
      sealed_base_sequence: head.sequence === 0 ? 0 : 1,
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

  // BLOCKER-R1 (adversarial re-gate 2026-07-14): the former version of this test
  // asserted the default instance stays clean on in-place sealed-content tamper
  // and STOPPED THERE, which encoded the false-safe the gate flagged. The
  // routine-load SKIP is intended (it must not read unreadable root-owned
  // entries), BUT that skip MUST be backed by a shipped detector. This test now
  // proves both halves: the routine load skips (by design), AND the shipped
  // crypto verifier `verifySealedLegacyPrefix` DETECTS the in-place tamper. The
  // CLI-level guarantee (audit-findings does not print "verifies clean") is in
  // test/cli/castle-wall-audit-regate-repros.test.ts.
  it("BLOCKER-R1: in-place sealed-content tamper is SKIPPED by the routine load but CAUGHT by the shipped crypto verifier", async () => {
    const { statePath, masterKey } = await makeFortress();
    const storage = new FilesystemStorage(statePath);
    const legacy = new AuditLog(storage, masterKey);
    await appendN(legacy, 2);
    const head = await legacy.getChainHead();

    const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
    await writeAuditStoreSplitBoundary(statePath, macKey, {
      sealed_tip_sequence: head.sequence,
      sealed_base_sequence: head.sequence === 0 ? 0 : 1,
      sealed_tip_entry_hash: head.entry_hash,
      daemon_namespace: "_audit-daemon",
    });

    // Corrupt a sealed entry's CONTENT in place (file still present, so the
    // listing-completeness check passes; only reading the content reveals it).
    const auditDir = join(statePath, "_audit");
    const files = (await readdir(auditDir)).filter((f) => f.startsWith("entry-")).sort();
    const target = join(auditDir, files[0]!);
    const raw = JSON.parse(await readFile(target, "utf-8"));
    raw.encrypted_payload_bytes = raw.encrypted_payload_bytes + "AAAA";
    await writeFile(target, JSON.stringify(raw));

    // (1) Routine load consults the boundary and SKIPS the sealed content, so
    // getIntegrityFindings() stays [] (this keeps strict-mode ensureLoaded from
    // throwing on every migrated fortress — the F2 fix). This is intended, but
    // is NOT the whole story:
    const sealed = new AuditLog(storage, masterKey);
    await expect(sealed.getIntegrityFindings()).resolves.toEqual([]);

    // (2) THE INVERSION: the shipped crypto verifier reads the sealed content
    // and DETECTS the tamper. So the tamper is never actually undetected.
    const verdict = await verifySealedLegacyPrefix(storage, masterKey);
    expect(verdict.status).toBe("hash_mismatch");

    // (3) consultSplitBoundary: false also reads the content (proving the flag
    // is the real filter gate, not a no-op).
    const unsealed = new AuditLog(storage, masterKey, {
      integrityMode: "lenient",
      consultSplitBoundary: false,
    });
    expect((await unsealed.getIntegrityFindings()).length).toBeGreaterThan(0);
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
      sealed_base_sequence: head.sequence === 0 ? 0 : 1,
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

// F2 Option A — the SECOND contaminated namespace the #929 split missed.
//
// Drill Leg 1 (2026-07-15, Mini1 armed box): #929 sealed the legacy `_audit`
// ENTRIES but left the legacy `_audit_checkpoints` namespace (rotation
// checkpoints + `__head_anchor`) untouched. A pre-split ROOT daemon wrote those
// files root-owned 0600, so on an armed box the operator uid's `readCheckpoints`
// / `loadHeadAnchor` read threw EACCES, `file-grant mint` failed closed on
// `_audit_checkpoints/audit-checkpoint-...enc`, and 10659 green tests coexisted
// with a broken armed box because NO fixture had a pre-contaminated checkpoint
// store. This is that fixture: root-ownership is simulated with `chmod 0o000`
// (EACCES on read for the non-root test process), the same fidelity the sealed-
// ENTRY tests above use. The fix has the operator's load consult the split
// boundary for the checkpoint namespace exactly as it does for entries, without
// weakening the integrity check.
describe("F2 Option A: root-contaminated _audit_checkpoints under a valid boundary (drill Leg 1)", () => {
  const dirs: string[] = [];

  afterEach(async () => {
    for (const d of dirs.splice(0)) {
      await chmod(d, 0o700).catch(() => undefined);
      await rm(d, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  /** Build an armed-box-shaped fortress: real rotation checkpoints in
   * `_audit_checkpoints`, a root-owned `__head_anchor`, and a valid boundary
   * sealing the whole chain at its tip. Returns handles + the checkpoint dir. */
  async function buildArmedCheckpointFortress() {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-f2-checkpoints-"));
    dirs.push(root);
    const statePath = join(root, "state");
    const masterKey = generateRandomKey();
    const storage = new FilesystemStorage(statePath);

    // Small checkpoint interval so appends produce real `audit-checkpoint-*`
    // files (the sealed-region checkpoints the drill found root-owned).
    const legacy = new AuditLog(storage, masterKey, { checkpointInterval: 2 });
    for (let i = 0; i < 6; i++) {
      await legacy.appendCritical({
        layer: "l1",
        operation: `pre-split-${i}`,
        identity_id: "id-1",
        result: "success",
        details: { i },
      });
    }
    await legacy.flush();
    const head = await legacy.getChainHead();
    expect(head.sequence).toBe(6);

    // Each `appendCritical` already wrote a VALID `__head_anchor` (the drill's
    // root-owned `__head_anchor.enc`), so the checkpoint namespace holds both
    // rotation checkpoints and a real head anchor to contaminate below.

    const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
    await writeAuditStoreSplitBoundary(statePath, macKey, {
      sealed_tip_sequence: head.sequence,
      sealed_base_sequence: 1,
      sealed_tip_entry_hash: head.entry_hash,
      daemon_namespace: "_audit-daemon",
    });

    const checkpointDir = join(statePath, "_audit_checkpoints");
    const checkpointFiles = await readdir(checkpointDir);
    // Sanity: the fixture actually has checkpoint content to contaminate.
    expect(checkpointFiles.length).toBeGreaterThan(1);

    return { statePath, masterKey, storage, head, checkpointDir, checkpointFiles };
  }

  it("does NOT fail the operator load/mint closed (the exact Leg 1 unblock)", async () => {
    const { masterKey, storage, checkpointDir, checkpointFiles } =
      await buildArmedCheckpointFortress();

    // Root-own every checkpoint + head-anchor file (EACCES on read at the
    // operator uid), the state the pre-split root daemon left behind.
    for (const f of checkpointFiles) {
      await chmod(join(checkpointDir, f), 0o000);
    }
    try {
      // CONTROL: with the boundary IGNORED (consultSplitBoundary: false, the
      // pre-fix behavior for the checkpoint namespace), the operator actually
      // attempts the permission-denied reads and surfaces a storage finding.
      const unsealed = new AuditLog(storage, masterKey, {
        integrityMode: "lenient",
        consultSplitBoundary: false,
      });
      const controlFindings = await unsealed.getIntegrityFindings();
      expect(
        controlFindings.some((f) => f.kind === "storage_unavailable"),
      ).toBe(true);

      // THE FIX: an operator instance that consults the boundary skips the
      // sealed-region checkpoints + head anchor it cannot read, so the load is
      // clean AND a durable append (the exact audit write `file-grant mint`
      // makes) succeeds in STRICT mode instead of throwing AuditIntegrityError.
      const operator = new AuditLog(storage, masterKey, {
        integrityMode: "strict",
      });
      await expect(operator.getIntegrityFindings()).resolves.toEqual([]);
      await operator.appendCritical({
        layer: "l1",
        operation: "mint-durable-audit-write",
        identity_id: "id-1",
        result: "success",
      });
      await expect(operator.flush()).resolves.toBeUndefined();
      expect((await operator.getChainHead()).sequence).toBe(7);
    } finally {
      for (const f of checkpointFiles) {
        await chmod(join(checkpointDir, f), 0o600).catch(() => undefined);
      }
    }
  });

  it("still fails closed on an unreadable checkpoint ABOVE the sealed tip (integrity check NOT weakened)", async () => {
    const { statePath, masterKey, storage } = await buildArmedCheckpointFortress();

    // Write two post-split entries so a checkpoint lands ABOVE the sealed tip
    // (seq 6): the checkpoint at seq 8 anchors the operator's own suffix, not
    // the sealed region, so it must NOT be skipped when unreadable.
    const pre = new AuditLog(storage, masterKey, { checkpointInterval: 2 });
    await pre.appendCritical({ layer: "l1", operation: "post-1", identity_id: "id-1", result: "success" });
    await pre.appendCritical({ layer: "l1", operation: "post-2", identity_id: "id-1", result: "success" });
    await pre.flush();

    const checkpointDir = join(statePath, "_audit_checkpoints");
    const checkpointDirFiles = await readdir(checkpointDir);
    // Find the highest-sequence checkpoint file (the seq-8 suffix checkpoint) by
    // reading each record's checkpoint_sequence.
    let topFile: string | undefined;
    let topSeq = -1;
    for (const f of checkpointDirFiles) {
      const raw = await readFile(join(checkpointDir, f), "utf-8").catch(() => "");
      try {
        const rec = JSON.parse(raw);
        if (
          rec &&
          rec.checkpoint_kind === "audit-checkpoint" &&
          typeof rec.checkpoint_sequence === "number" &&
          rec.checkpoint_sequence > topSeq
        ) {
          topSeq = rec.checkpoint_sequence;
          topFile = f;
        }
      } catch {
        // Not a checkpoint record (e.g. __head_anchor); ignore.
      }
    }
    expect(topFile).toBeDefined();
    expect(topSeq).toBeGreaterThan(6); // above the sealed tip

    await chmod(join(checkpointDir, topFile!), 0o000);
    try {
      // An unreadable checkpoint ABOVE the sealed tip is a genuine problem, not
      // sealed-region contamination: the load must surface a finding (fail
      // closed), never silently skip it.
      const operator = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
      const findings = await operator.getIntegrityFindings();
      expect(findings.some((f) => f.kind === "storage_unavailable")).toBe(true);
    } finally {
      await chmod(join(checkpointDir, topFile!), 0o600).catch(() => undefined);
    }
  });

  it("reconciles the secondary finding: an armed operator gets verified_suffix_only, not findings", async () => {
    const { statePath, masterKey, storage, checkpointDir, checkpointFiles } =
      await buildArmedCheckpointFortress();

    // Root-own BOTH the sealed entries AND the checkpoints + head anchor, the
    // full armed-box state. With the sealed entries unreadable, the sealed-
    // region crypto walk returns `unreadable`, which is what should drive the
    // operator verdict to `verified_suffix_only` (amber) once the checkpoint
    // contamination no longer manufactures spurious `findings`. #929's PR body
    // predicted this amber; Leg 1 found `findings` instead, because the
    // checkpoint reads failed first.
    const auditDir = join(statePath, "_audit");
    const entryFiles = (await readdir(auditDir)).filter((f) => f.startsWith("entry-"));
    for (const f of entryFiles) await chmod(join(auditDir, f), 0o000);
    for (const f of checkpointFiles) await chmod(join(checkpointDir, f), 0o000);
    try {
      const report = await verifyFortressAuditFullPicture({ storage, masterKey });
      expect(report.operator.status).toBe("verified_suffix_only");
      expect(report.operator.sealed_region?.status).toBe("unreadable");
    } finally {
      for (const f of entryFiles) await chmod(join(auditDir, f), 0o600).catch(() => undefined);
      for (const f of checkpointFiles) await chmod(join(checkpointDir, f), 0o600).catch(() => undefined);
    }
  });

  // Finding 1 (adversarial gate 2026-07-15): the head-anchor `unreadable_sealed`
  // suppression must NOT launder a post-split tail truncation. If a suffix
  // survives, the operator's OWN anchor is readable; an unreadable one is tamper.
  it("Finding 1: an unreadable head anchor with a surviving post-split suffix FAILS CLOSED", async () => {
    const { statePath, masterKey, storage } = await buildArmedCheckpointFortress();

    // Operator writes a post-split suffix (entries above the sealed tip 6); this
    // also writes an operator-owned, readable `__head_anchor` at the suffix head.
    const operator = new AuditLog(storage, masterKey, { checkpointInterval: 100 });
    await operator.appendCritical({ layer: "l1", operation: "s1", identity_id: "id-1", result: "success" });
    await operator.appendCritical({ layer: "l1", operation: "s2", identity_id: "id-1", result: "success" });
    await operator.flush();
    expect((await operator.getChainHead()).sequence).toBeGreaterThan(6);

    // Attacker makes the operator's OWN head anchor unreadable (0000) to try to
    // force a lower-floor heal, while the suffix still survives.
    const headAnchorFile = (await readdir(join(statePath, "_audit_checkpoints"))).find(
      (f) => f.includes("head") || f.includes("anchor"),
    );
    // Fall back: chmod every checkpoint file (the head anchor is among them).
    const cpDir = join(statePath, "_audit_checkpoints");
    const cpFiles = await readdir(cpDir);
    for (const f of cpFiles) await chmod(join(cpDir, f), 0o000);
    try {
      const reader = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
      const findings = await reader.getIntegrityFindings();
      expect(findings.some((f) => f.kind === "tail_anchor_invalid")).toBe(true);
      void headAnchorFile;
    } finally {
      for (const f of cpFiles) await chmod(join(cpDir, f), 0o600).catch(() => undefined);
    }
  });

  // Finding 1 (full-suffix-erasure variant): even with NO surviving suffix, a
  // fortress that ONCE established a post-split suffix (marker set) whose suffix
  // + suffix checkpoints were erased and whose anchor was hidden must FAIL
  // CLOSED via the operator-provenance suffix-established marker.
  it("Finding 1: full-suffix erasure with a hidden anchor FAILS CLOSED via the suffix-established marker", async () => {
    const { statePath, masterKey, storage } = await buildArmedCheckpointFortress();

    // Establish a post-split suffix (writes the operator-provenance
    // AUDIT_POST_SPLIT_SUFFIX_ESTABLISHED marker in _meta).
    const operator = new AuditLog(storage, masterKey, { checkpointInterval: 2 });
    for (let i = 0; i < 4; i++) {
      await operator.appendCritical({ layer: "l1", operation: `s-${i}`, identity_id: "id-1", result: "success" });
    }
    await operator.flush();

    // Attacker erases the ENTIRE post-split suffix (entries AND checkpoints above
    // the sealed tip 6) and hides the head anchor (unreadable), so the surviving
    // store looks exactly like a fresh just-migrated box.
    const auditDir = join(statePath, "_audit");
    for (const f of (await readdir(auditDir)).filter((x) => x.startsWith("entry-"))) {
      const seq = Number(/^entry-(\d{20})-/.exec(f)?.[1] ?? "0");
      if (seq > 6) await unlink(join(auditDir, f));
    }
    const cpDir = join(statePath, "_audit_checkpoints");
    for (const f of await readdir(cpDir)) {
      const raw = await readFile(join(cpDir, f), "utf-8").catch(() => "");
      let isSuffixCheckpoint = false;
      try {
        const rec = JSON.parse(raw);
        isSuffixCheckpoint =
          rec?.checkpoint_kind === "audit-checkpoint" &&
          typeof rec.checkpoint_sequence === "number" &&
          rec.checkpoint_sequence > 6;
      } catch {
        // __head_anchor / non-record: hide it (unreadable), do not delete.
      }
      if (isSuffixCheckpoint) {
        await unlink(join(cpDir, f));
      } else {
        await chmod(join(cpDir, f), 0o000); // hide the head anchor + sealed cps
      }
    }
    try {
      const reader = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
      const findings = await reader.getIntegrityFindings();
      // The suffix-established marker (untouched, operator-owned in _meta) proves
      // a suffix existed, so the hidden anchor + erased suffix is caught.
      expect(findings.some((f) => f.kind === "tail_anchor_invalid")).toBe(true);
    } finally {
      for (const f of await readdir(cpDir).catch(() => [])) {
        await chmod(join(cpDir, f), 0o600).catch(() => undefined);
      }
    }
  });
});
