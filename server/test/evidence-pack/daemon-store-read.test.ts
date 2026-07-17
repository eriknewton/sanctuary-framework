/**
 * Sanctuary MCP Server - Law-firm Evidence Pack: WATCH-1 daemon-store read
 * (round-5 two-family gate regression).
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Integration coverage for `readDaemonStore` over a REAL split fortress on
 * disk (temp dir, never host state). The round-5 gate found (Codex HIGH /
 * Claude-family MED, convergent) that a readable-but-TAMPERED daemon store was
 * mislabeled `present_unreadable` ("not readable at this privilege"), which in
 * a law-firm artifact misdirects an auditor away from tamper evidence and
 * suggests a futile remedy (root hits the same integrity failure). This file
 * pins the four honest states end-to-end:
 *   absent  -> fresh fortress, no split;
 *   included -> split fortress, daemon chain intact (entries + counts);
 *   present_tampered -> daemon entry tampered in place (strict-mode
 *     AuditIntegrityError), NOT the privilege excuse;
 *   present_unreadable -> daemon dir unreadable at this uid (skipped as root).
 */

import { chmod, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { AuditLog } from "../../src/operational/audit-log.js";
import {
  AUDIT_DAEMON_NAMESPACE,
  migrateFortressAuditStoreSplit,
} from "../../src/operational/audit-store-split.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import type { StoredIdentity } from "../../src/core/identity.js";
import { readDaemonStore, deriveAuditReadOutcome } from "../../src/evidence-pack/cli.js";
import { buildEvidencePack } from "../../src/evidence-pack/generate.js";

/** A throwaway fortress identity for signing a fixture pack, encrypted under the
 * SAME master key `buildEvidencePack` will use to decrypt it for signing. */
function fixtureSigner(masterKey: Uint8Array): StoredIdentity {
  const { storedIdentity } = createIdentity(
    "acme-law",
    derivePurposeKey(masterKey, "identity-encryption"),
    "pw"
  );
  return storedIdentity;
}

const dirs: string[] = [];

afterEach(async () => {
  for (const d of dirs.splice(0)) {
    await chmod(join(d, "state", AUDIT_DAEMON_NAMESPACE), 0o700).catch(() => undefined);
    await rm(d, { recursive: true, force: true }).catch(() => undefined);
  }
});

async function freshFortress() {
  const root = await mkdtemp(join(tmpdir(), "sanctuary-ep-daemon-"));
  dirs.push(root);
  const statePath = join(root, "state");
  const storage = new FilesystemStorage(statePath);
  const masterKey = generateRandomKey();
  return { root, statePath, storage, masterKey };
}

/** A fortress that has run the F2 split (daemon genesis entry exists). */
async function splitFortress() {
  const f = await freshFortress();
  const auditLog = new AuditLog(f.storage, f.masterKey);
  await auditLog.appendCritical({
    layer: "l1",
    operation: "pre-split-op",
    identity_id: "agent-a",
    result: "success",
  });
  await auditLog.flush();
  await migrateFortressAuditStoreSplit({ storage: f.storage, masterKey: f.masterKey });
  return f;
}

describe("WATCH-1 round-5: readDaemonStore four honest states over a real on-disk fortress", () => {
  it("absent on a fresh (never-split) fortress", async () => {
    const f = await freshFortress();
    const result = await readDaemonStore(f.storage, f.masterKey);
    expect(result.status).toBe("absent");
  });

  it("included on a split fortress with an intact daemon chain, with real entries + counts", async () => {
    const f = await splitFortress();
    const result = await readDaemonStore(f.storage, f.masterKey);
    expect(result.status).toBe("included");
    if (result.status === "included") {
      // The split migration writes the daemon genesis marker entry.
      expect(result.entries.length).toBeGreaterThanOrEqual(1);
      expect(result.windowedTotal).toBe(result.entries.length);
    }
  });

  it("present_tampered (NOT present_unreadable) when a readable daemon entry is tampered in place", async () => {
    const f = await splitFortress();
    const daemonDir = join(f.statePath, AUDIT_DAEMON_NAMESPACE);
    const files = (await readdir(daemonDir)).filter((n) => n.startsWith("entry-")).sort();
    expect(files.length).toBeGreaterThanOrEqual(1);
    const target = join(daemonDir, files[0]!);
    const raw = JSON.parse(await readFile(target, "utf-8"));
    raw.timestamp = "1999-01-01T00:00:00.000Z"; // covered by the entry hash
    await writeFile(target, JSON.stringify(raw));

    const result = await readDaemonStore(f.storage, f.masterKey);
    // Tamper evidence, never the futile "re-run as root" privilege excuse.
    expect(result.status).toBe("present_tampered");
  });

  it("present_unreadable when the daemon directory is not listable at this uid", async () => {
    if (typeof process.getuid === "function" && process.getuid() === 0) {
      return; // root bypasses mode bits; the privilege case is untestable as root
    }
    const f = await splitFortress();
    const daemonDir = join(f.statePath, AUDIT_DAEMON_NAMESPACE);
    await chmod(daemonDir, 0o000);
    const result = await readDaemonStore(f.storage, f.masterKey);
    expect(result.status).toBe("present_unreadable");
    // G-3: a directory unreadable at this uid is a PRIVILEGE limitation (re-run
    // as root reads it), never an I/O error.
    if (result.status === "present_unreadable") {
      expect(result.unreadable_reason).toBe("privilege");
    }
  });

  it("C1: 'missing' (NOT 'absent') when a migrated fortress's daemon store was DELETED", async () => {
    const f = await splitFortress();
    // The migration wrote a valid boundary + established marker (in _meta) and a
    // daemon chain. Deleting only the daemon namespace leaves the marker behind,
    // so the store is now provably DESTROYED, not never-provisioned.
    await rm(join(f.statePath, AUDIT_DAEMON_NAMESPACE), {
      recursive: true,
      force: true,
    });
    const result = await readDaemonStore(f.storage, f.masterKey);
    // The pre-fix code returned "absent" here (a fresh fortress) -- the hole.
    expect(result.status).toBe("missing");
  });

  it("C1: a fresh (never-migrated) fortress with no daemon dir stays 'absent', not 'missing'", async () => {
    // Guard the fix does not over-fire: with NO migration marker, an absent
    // daemon directory is a genuinely fresh fortress.
    const f = await freshFortress();
    const result = await readDaemonStore(f.storage, f.masterKey);
    expect(result.status).toBe("absent");
  });

  it("C1: a deleted daemon store surfaces as 'missing' in the SIGNED manifest coverage", async () => {
    const f = await splitFortress();
    await rm(join(f.statePath, AUDIT_DAEMON_NAMESPACE), {
      recursive: true,
      force: true,
    });
    const daemon = await readDaemonStore(f.storage, f.masterKey);
    const outcome = deriveAuditReadOutcome({
      entries: [],
      windowedTotal: 0,
      retentionConfig: { maxEntries: 100, maxTotalSizeBytes: 1024 },
      usage: { entryCount: 0, totalSizeBytes: 0, everPruned: false },
      daemon,
    });
    expect(outcome.status).toBe("populated");
    if (outcome.status === "populated") {
      expect(outcome.value.retention.daemon_store.status).toBe("missing");
    }

    const pack = buildEvidencePack(
      {
        firm_name: "Acme Law",
        quarter: { year: 2026, quarter: 3 },
        generated_at_override: "2026-08-01T00:00:00.000Z",
      },
      { audit: outcome, signer: fixtureSigner(f.masterKey), masterKey: f.masterKey }
    );
    // The daemon-store status is carried into the SIGNED manifest coverage, so a
    // reader of `shortfall: ...` is never left believing a fresh census.
    expect(
      pack.manifest.coverage.determinable &&
        pack.manifest.coverage.daemon_store.status
    ).toBe("missing");
    // And the rendered report raises the evidence-destruction alarm, never a
    // silent operator-only census.
    const report = pack.files.find((x) => x.filename.endsWith(".md"))!;
    expect(report.content).toContain("ENFORCEMENT-CENSUS NOTICE");
    expect(report.content).toMatch(/writer-split evidence is present/i);
    // Hedged, not over-definite: never asserts the migration definitively "ran
    // and provisioned" (the presence check is fail-closed on a raw stat).
    expect(report.content).not.toMatch(/ran the audit-store writer split and provisioned/i);
    // A missing store is not a privilege limit: never advise the futile root re-run.
    expect(report.content).not.toMatch(/re-run .*as root/i);
  });
});
