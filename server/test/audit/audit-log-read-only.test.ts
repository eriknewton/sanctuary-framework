/**
 * The read-only AuditLog configuration, tested at the unit level: each of its
 * two enforcement sites is killed by its own assertion, because the two are
 * deliberately redundant and an integration test over the pair cannot tell
 * which one fired.
 *
 *  - The recovery-batch suppression is proven by the ABSENCE of the
 *    signing-control write-failure channel on a load whose recovery condition
 *    is armed (fixture-sanity asserted first, so the absence is not vacuous):
 *    if the suppression is lost, the batch runs, the write path refuses, and
 *    the failure channel fires — observable here through the anomaly
 *    subscriber, while the fortress tree stays unchanged (which is why the
 *    tree-hash integration test alone cannot see it).
 *
 *  - The write-path refusal is proven with a deliberately WRITABLE backend:
 *    an append on a read-only instance must reject and create nothing, which
 *    shows the refusal is the AuditLog's own and not inherited from a
 *    storage decorator.
 */

import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  AuditLog,
  type AuditIntegrityAnomalyEvent,
} from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { ReadOnlyStorageGuard } from "../../src/storage/read-only-guard.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  AUDIT_SIGNING_HEAD_KEY,
  AUDIT_SIGNING_LATCH_V2_KEY,
  CHECKPOINT_NAMESPACE,
  appendCriticalEntries,
  seedStoredIdentity,
} from "../helpers/signing-fixture.js";

describe("AuditLog readOnly configuration", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  /** A filesystem store with signed checkpoints whose latch AND head control
   *  records have been deleted — the state that arms both recovery legs. */
  async function tamperedSignedStore(): Promise<{
    storage: FilesystemStorage;
    masterKey: Uint8Array;
  }> {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-audit-readonly-"));
    tempDirs.push(dir);
    const storage = new FilesystemStorage(join(dir, "state"));
    const masterKey = generateRandomKey();
    const { storedIdentity } = await seedStoredIdentity(storage, masterKey);
    const writer = new AuditLog(storage, masterKey, { checkpointInterval: 1 });
    await appendCriticalEntries(writer, 3, storedIdentity.identity_id);
    await storage.delete(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_LATCH_V2_KEY);
    await storage.delete(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_HEAD_KEY);
    return { storage, masterKey };
  }

  it("suppresses the recovery batch itself: the write-failure channel is never reached on an armed read-only load", async () => {
    const { storage, masterKey } = await tamperedSignedStore();

    const events: AuditIntegrityAnomalyEvent[] = [];
    const reader = new AuditLog(new ReadOnlyStorageGuard(storage), masterKey, {
      integrityMode: "lenient",
      readOnly: true,
      integrityAnomalySubscribers: [
        (event) => {
          events.push(event);
        },
      ],
    });
    const findings = await reader.getIntegrityFindings();

    // Fixture sanity FIRST: the recovery condition must actually be armed, or
    // the absence asserted below proves nothing.
    const kinds = findings.map((finding) => finding.kind);
    expect(kinds).toContain("checkpoint_signing_floor_recovered");
    expect(kinds).toContain("checkpoint_signing_head_recovered");

    // The kill: if the suppression at the recovery call site is lost, the
    // batch runs into the write path's refusal and the failure channel fires
    // with this exact variant — while the fortress tree stays byte-identical,
    // which is why no tree-hash assertion can stand in for this one.
    const writeFailureEvents = events.filter((event) =>
      event.findings.some(
        (finding) => finding.variant === "control-record-write-failed"
      )
    );
    expect(writeFailureEvents).toEqual([]);
  });

  it("refuses the cross-process write path outright, independent of any storage decorator", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-audit-readonly-append-"));
    tempDirs.push(dir);
    const statePath = join(dir, "state");
    // A WRITABLE backend on purpose: this proves the refusal belongs to the
    // AuditLog's own write path, so a read-only instance stays read-only even
    // when composed without a guard. If the refusal is lost, this append
    // SUCCEEDS and the assertions below fail on both the resolved promise and
    // the files it created.
    const log = new AuditLog(new FilesystemStorage(statePath), generateRandomKey(), {
      readOnly: true,
    });

    await expect(
      log.appendCritical({
        layer: "l1",
        operation: "read-only-refusal-probe",
        identity_id: "operator",
        result: "success",
      })
    ).rejects.toThrow(/read-only/);

    // Refused BEFORE the raw-filesystem preamble: nothing was created at all,
    // not even the namespace directories.
    await expect(readdir(statePath)).rejects.toThrow();
  });
});
