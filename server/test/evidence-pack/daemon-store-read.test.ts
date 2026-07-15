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
import { readDaemonStore } from "../../src/evidence-pack/cli.js";

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
});
