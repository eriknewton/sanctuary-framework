/**
 * Reset-history marker idempotent consumption (full-sweep #75).
 *
 * Verifies that a `.consumed` sentinel prevents duplicate audit entries
 * when the marker delete fails after a successful flush. The sentinel
 * is written BEFORE the marker is deleted; if the process crashes between
 * those two operations, the next boot sees `.consumed` and skips
 * re-emission.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  consumeResetHistoryMarker,
  RECOVERED_FROM_RESET_OPERATION,
  RESET_HISTORY_FILENAME,
  type ResetHistoryMarker,
} from "../../src/audit/reset-history.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

function makeMarkerLine(overrides: Partial<ResetHistoryMarker> = {}): string {
  const marker: ResetHistoryMarker = {
    started_at: "2026-05-11T10:00:00.000Z",
    completed_at: "2026-05-11T10:00:01.000Z",
    recovery_mode: "nuke",
    fortress_name: "fortress-idempotent",
    storage_path: "/var/sanctuary/fortress-idempotent",
    keychain_cleared: true,
    ...overrides,
  };
  return JSON.stringify(marker) + "\n";
}

function newAuditLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

describe("consumeResetHistoryMarker idempotent consumption (#75)", () => {
  let storageRoot: string;

  beforeEach(() => {
    storageRoot = mkdtempSync(join(tmpdir(), "sanctuary-reset-idempotent-"));
  });

  afterEach(() => {
    rmSync(storageRoot, { recursive: true, force: true });
  });

  it("normal consumption writes .consumed sentinel, then cleans up both files", async () => {
    const markerPath = join(storageRoot, RESET_HISTORY_FILENAME);
    writeFileSync(markerPath, makeMarkerLine(), { mode: 0o600 });

    const auditLog = newAuditLog();
    const result = await consumeResetHistoryMarker({
      storagePath: storageRoot,
      auditLog,
    });

    expect(result.emitted).toBe(1);
    // Both the marker and the sentinel should be cleaned up
    expect(existsSync(markerPath)).toBe(false);
    expect(existsSync(markerPath + ".consumed")).toBe(false);

    const entries = (await auditLog.query({ limit: 100 })).entries;
    expect(entries).toHaveLength(1);
    expect(entries[0]!.operation).toBe(RECOVERED_FROM_RESET_OPERATION);
  });

  it("skips re-emission when .consumed sentinel exists (simulated crash after flush)", async () => {
    const markerPath = join(storageRoot, RESET_HISTORY_FILENAME);
    const consumedPath = markerPath + ".consumed";

    // Simulate a crash: marker still exists, but .consumed sentinel also exists
    // (meaning a prior boot successfully flushed audit entries but failed to
    // delete the marker).
    writeFileSync(markerPath, makeMarkerLine(), { mode: 0o600 });
    writeFileSync(consumedPath, "", { mode: 0o600 });

    const auditLog = newAuditLog();
    const result = await consumeResetHistoryMarker({
      storagePath: storageRoot,
      auditLog,
    });

    // No duplicate entries emitted
    expect(result.emitted).toBe(0);
    // Both files cleaned up
    expect(existsSync(markerPath)).toBe(false);
    expect(existsSync(consumedPath)).toBe(false);

    const entries = (await auditLog.query({ limit: 100 })).entries;
    expect(entries).toHaveLength(0);
  });
});
