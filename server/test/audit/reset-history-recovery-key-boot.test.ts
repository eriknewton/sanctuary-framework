/**
 * S0 (writer/reader schema parity): a successful recovery-key rekey writes a
 * `.reset-history.log` marker with `recovery_mode: "recovery-key"`. The BOOT
 * reader (`parseResetHistory`) must accept exactly what the writer
 * (`writeResetMarker`) persists, or the next server boot refuses to start with
 * `ResetHistoryMalformedError` — a boot brick (AGENTS rule 11).
 *
 * This test feeds the REAL writer's on-disk output to the REAL boot parser, not
 * a bespoke re-encode, and proves the guard still fails on a genuinely unknown
 * mode (a planted divergence), so the parity is verified in both directions.
 */

import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { writeResetMarker } from "../../src/cli/reset-passphrase.js";
import {
  parseResetHistory,
  ResetHistoryMalformedError,
  RESET_HISTORY_RECOVERY_MODES,
  RESET_HISTORY_FILENAME,
} from "../../src/audit/reset-history.js";

describe("reset-history recovery-key boot parity (S0)", () => {
  const cleanup: string[] = [];
  afterEach(async () => {
    await Promise.all(
      cleanup.splice(0).map((p) => rm(p, { recursive: true, force: true })),
    );
  });

  async function tempStorage(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "reset-history-s0-"));
    cleanup.push(dir);
    return dir;
  }

  it("the boot parser accepts the exact marker the recovery-key rekey writes", async () => {
    const storagePath = await tempStorage();
    // The REAL writer, with the mode a successful recovery-key rekey records.
    await writeResetMarker(storagePath, {
      started_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      recovery_mode: "recovery-key",
      fortress_name: "fortress-s0",
      storage_path: storagePath,
      keychain_cleared: false,
    });

    // The REAL boot parser, on the exact bytes the writer left on disk.
    const raw = await readFile(join(storagePath, RESET_HISTORY_FILENAME), "utf-8");
    const parsed = parseResetHistory(raw, RESET_HISTORY_FILENAME);

    expect(parsed.markers).toHaveLength(1);
    expect(parsed.markers[0]!.recovery_mode).toBe("recovery-key");
  });

  it("the shared enum still lists recovery-key (writer and reader share it)", () => {
    expect(RESET_HISTORY_RECOVERY_MODES).toContain("recovery-key");
    expect(RESET_HISTORY_RECOVERY_MODES).toContain("nuke");
  });

  it("PLANTED DIVERGENCE: an unknown mode still fails the boot parser closed", async () => {
    const storagePath = await tempStorage();
    // A marker whose mode is NOT in the shared enum must still be rejected, so
    // the parity check is a real guard, not a blanket accept-anything.
    const line =
      JSON.stringify({
        schema: "sanctuary.reset-marker.v1",
        authoritative: false,
        started_at: "2026-09-03T00:00:00.000Z",
        completed_at: "2026-09-03T00:00:01.000Z",
        recovery_mode: "teleport",
        fortress_name: "fortress-s0",
        storage_path: storagePath,
        keychain_cleared: false,
      }) + "\n";
    const path = join(storagePath, RESET_HISTORY_FILENAME);
    await writeFile(path, line, { mode: 0o600 });

    expect(() => parseResetHistory(line, path)).toThrow(ResetHistoryMalformedError);
  });
});
