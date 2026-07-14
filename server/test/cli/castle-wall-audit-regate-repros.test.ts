/**
 * F2 second adversarial fix round (Codex re-gate, 2026-07-14) — CLI repros.
 *
 * BLOCKER-R1: `castle-wall audit-findings` must NOT print "chain verifies
 *   clean" on a tampered/deleted sealed legacy entry (the routine diagnostic
 *   was reporting clean because it skips sealed content). Includes the
 *   lowest-sealed-entry deletion variant (the residual the first round left).
 * HIGH-R3: daemon-chain deletion under a valid boundary must be a FINDING, not
 *   "absent"; `audit-chain export` must still refuse without --operator-only;
 *   `doctor` must NOT return an OK audit-chain check.
 * HIGH-R4: a readable-but-tampered daemon chain must set `complete:false` and
 *   surface the daemon integrity findings in `audit-verify --json`.
 *
 * Single-process tests: cross-uid is simulated where needed via chmod; the
 * armed-box drill still owes the real root/operator split (see the PR body).
 */

import { chmod, mkdtemp, readFile, readdir, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";

import {
  runAuditFindings,
  runAuditStoreStatus,
  runAuditVerify,
  runProvisionPin,
} from "../../src/cli/castle-wall.js";
import { parseExportArgs, runExport } from "../../src/cli/audit-chain-export.js";
import { runDoctorChecks } from "../../src/cli/doctor.js";
import {
  createDaemonAuditLog,
  migrateFortressAuditStoreSplit,
  AUDIT_DAEMON_NAMESPACE,
} from "../../src/operational/audit-store-split.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

class CaptureStream extends Writable {
  chunks: string[] = [];
  override _write(chunk: unknown, _enc: BufferEncoding, cb: (e?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    cb();
  }
  text(): string {
    return this.chunks.join("");
  }
}

const PASSPHRASE = "test-f2-regate-repros-passphrase";

describe("F2 re-gate repros (round 2)", () => {
  const tempDirs: string[] = [];
  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await chmod(join(dir, "state", AUDIT_DAEMON_NAMESPACE), 0o700).catch(() => undefined);
      const auditDir = join(dir, "state", "_audit");
      for (const f of await readdir(auditDir).catch(() => [] as string[])) {
        await chmod(join(auditDir, f), 0o600).catch(() => undefined);
      }
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  const ENV = (fortressPath: string) => ({
    SANCTUARY_STORAGE_PATH: fortressPath,
    SANCTUARY_PASSPHRASE: PASSPHRASE,
  });

  /** Provision a fortress, seed `operatorEntries` operator `_audit` entries,
   * migrate (sealing them), then land `daemonEntries` daemon enforcement
   * events. Returns paths + master key. */
  async function seededMigratedFortress(opts: {
    operatorEntries: number;
    daemonEntries?: number;
  }) {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-regate-"));
    tempDirs.push(fortressPath);
    const code = await runProvisionPin([], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env: ENV(fortressPath),
    });
    expect(code).toBe(0);

    const statePath = join(fortressPath, "state");
    const storage = new FilesystemStorage(statePath);
    const { masterKey } = await establishMaster({ storage, passphrase: PASSPHRASE });

    // Seed operator entries BEFORE migration so the sealed region is non-empty.
    const opLog = new AuditLog(storage, masterKey);
    for (let i = 0; i < opts.operatorEntries; i++) {
      await opLog.appendCritical({
        layer: "l1",
        operation: `seed-${i}`,
        identity_id: "op",
        result: "success",
      });
    }
    await opLog.flush();

    await migrateFortressAuditStoreSplit({ storage, masterKey });

    if (opts.daemonEntries && opts.daemonEntries > 0) {
      const daemonLog = createDaemonAuditLog(storage, masterKey);
      for (let i = 0; i < opts.daemonEntries; i++) {
        await daemonLog.appendCritical({
          layer: "l1",
          operation: i % 2 === 0 ? "egress_allowed" : "egress_blocked",
          identity_id: "castle-wall-daemon",
          result: "success",
          details: { host: `h${i}.example` },
        });
      }
      await daemonLog.flush();
    }
    return { fortressPath, statePath, storage, masterKey };
  }

  function sealedEntryFiles(statePath: string): Promise<string[]> {
    return readdir(join(statePath, "_audit")).then((fs) =>
      fs.filter((f) => f.startsWith("entry-")).sort(),
    );
  }

  // ── BLOCKER-R1 ─────────────────────────────────────────────────────────
  it("BLOCKER-R1: audit-findings does NOT report 'verifies clean' when a sealed entry is corrupted in place", async () => {
    const { fortressPath, statePath } = await seededMigratedFortress({ operatorEntries: 3 });
    const auditDir = join(statePath, "_audit");
    const files = await sealedEntryFiles(statePath);
    // Corrupt a middle sealed entry's content in place (file still present).
    const target = join(auditDir, files[1]!);
    const raw = JSON.parse(await readFile(target, "utf-8"));
    raw.encrypted_payload_bytes = raw.encrypted_payload_bytes + "AAAA";
    await writeFile(target, JSON.stringify(raw));

    const out = new CaptureStream();
    const err = new CaptureStream();
    const code = await runAuditFindings(["--fortress", fortressPath], {
      out,
      err,
      env: ENV(fortressPath),
    });
    expect(code).toBe(0);
    const combined = out.text() + err.text();
    expect(combined).not.toMatch(/verifies clean/i);
    expect(combined).toMatch(/sealed/i);
  });

  it("BLOCKER-R1: audit-findings does NOT report 'verifies clean' when the LOWEST sealed entry is deleted", async () => {
    const { fortressPath, statePath } = await seededMigratedFortress({ operatorEntries: 4 });
    const files = await sealedEntryFiles(statePath);
    // Delete the LOWEST sealed entry (sequence 1) — the first-round residual.
    await unlink(join(statePath, "_audit", files[0]!));

    const out = new CaptureStream();
    const err = new CaptureStream();
    const code = await runAuditFindings(["--fortress", fortressPath], {
      out,
      err,
      env: ENV(fortressPath),
    });
    expect(code).toBe(0);
    expect(out.text() + err.text()).not.toMatch(/verifies clean/i);
  });

  it("BLOCKER-R1: audit-findings DOES report 'verifies clean' on an intact migrated fortress (no false alarm)", async () => {
    const { fortressPath } = await seededMigratedFortress({ operatorEntries: 3 });
    const out = new CaptureStream();
    const code = await runAuditFindings(["--fortress", fortressPath], {
      out,
      err: new CaptureStream(),
      env: ENV(fortressPath),
    });
    expect(code).toBe(0);
    expect(out.text()).toMatch(/verifies clean/i);
  });

  // ── HIGH-R3 ────────────────────────────────────────────────────────────
  it("HIGH-R3: daemon-chain deletion under a valid boundary → audit-store-status reports daemon 'missing' (not absent)", async () => {
    const { fortressPath, statePath } = await seededMigratedFortress({
      operatorEntries: 2,
      daemonEntries: 2,
    });
    // Delete the whole daemon namespace (evidence destruction), boundary intact.
    await rm(join(statePath, AUDIT_DAEMON_NAMESPACE), { recursive: true, force: true });

    const out = new CaptureStream();
    const code = await runAuditStoreStatus(["--fortress", fortressPath], {
      out,
      err: new CaptureStream(),
      env: ENV(fortressPath),
    });
    expect(code).toBe(0);
    const report = JSON.parse(out.text());
    expect(report.daemon.status).toBe("missing");
    expect(report.daemon.status).not.toBe("absent");
  });

  it("HIGH-R3: audit-chain export still refuses without --operator-only after the daemon namespace is deleted", async () => {
    const { fortressPath, statePath } = await seededMigratedFortress({
      operatorEntries: 2,
      daemonEntries: 2,
    });
    await rm(join(statePath, AUDIT_DAEMON_NAMESPACE), { recursive: true, force: true });
    await expect(
      runExport(parseExportArgs(["--fortress", fortressPath], {})),
    ).rejects.toThrow(/INCOMPLETE|--operator-only|daemon/);
  });

  // F2 MEDIUM-1 (round 3, 2026-07-14) SUPERSEDES the round-2 assertion here.
  // Round 2 made doctor never-OK on ANY migrated fortress because the
  // single-chain export verify could not cover the daemon chain. Round 3 gave
  // doctor the chain-aware full-picture verifier, so with the master key it CAN
  // fully verify: a CLEAN migrated fortress is now legitimately OK, and it only
  // stays not-OK when it cannot verify (no key -> WARN) or finds tamper (FAIL,
  // covered by the doctor MEDIUM-1 test).
  it("MEDIUM-1: doctor is OK on a fully-verified migrated fortress WITH the key, and WARN without it", async () => {
    const { fortressPath } = await seededMigratedFortress({
      operatorEntries: 2,
      daemonEntries: 1,
    });
    const withKey = await runDoctorChecks({
      env: ENV(fortressPath),
      storagePath: fortressPath,
      platform: process.platform,
      nodeVersion: process.version,
    });
    const withKeyCheck = withKey.find((c) => c.name === "audit chain");
    expect(withKeyCheck).toBeDefined();
    expect(withKeyCheck!.status).toBe("OK");

    // Without the master key doctor cannot re-verify the sealed region or the
    // daemon chain, so it must WARN (point at audit-store-status), never OK.
    const noKey = await runDoctorChecks({
      env: {},
      storagePath: fortressPath,
      platform: process.platform,
      nodeVersion: process.version,
    });
    const noKeyCheck = noKey.find((c) => c.name === "audit chain");
    expect(noKeyCheck!.status).toBe("WARN");
  });

  // ── HIGH-R4 ────────────────────────────────────────────────────────────
  it("HIGH-R4: a readable-but-tampered daemon chain sets complete:false and surfaces daemon findings in audit-verify --json", async () => {
    const { fortressPath, statePath } = await seededMigratedFortress({
      operatorEntries: 1,
      daemonEntries: 4,
    });
    // Corrupt one _audit-daemon entry envelope (readable, but breaks the chain).
    const daemonDir = join(statePath, AUDIT_DAEMON_NAMESPACE);
    const daemonFiles = (await readdir(daemonDir)).filter((f) => f.startsWith("entry-")).sort();
    const target = join(daemonDir, daemonFiles[daemonFiles.length - 1]!);
    const raw = JSON.parse(await readFile(target, "utf-8"));
    raw.entry_hash = "0".repeat(64); // hash no longer matches the content
    await writeFile(target, JSON.stringify(raw));

    const out = new CaptureStream();
    const code = await runAuditVerify(["--fortress", fortressPath, "--json"], {
      out,
      err: new CaptureStream(),
      env: ENV(fortressPath),
    });
    expect(code).toBe(0);
    const report = JSON.parse(out.text());
    expect(report.complete).toBe(false);
    expect(report.daemon_chain).toBe("tampered");
    expect(Array.isArray(report.daemon_integrity_findings)).toBe(true);
    expect(report.daemon_integrity_findings.length).toBeGreaterThan(0);
  });
});
