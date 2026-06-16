/**
 * Reset-history continuity (v1.0.2 item a) — parser + consumer tests.
 *
 * Covers the gap closed by appending `fortress_recovered_from_reset`
 * audit entries on the first fortress-unlock after `reset-passphrase --nuke`
 * leaves a `.reset-history.log` marker. See server/src/audit/reset-history.ts.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  existsSync,
  readFileSync,
  mkdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  parseResetHistory,
  consumeResetHistoryMarker,
  ResetHistoryMalformedError,
  RECOVERED_FROM_RESET_OPERATION,
  RESET_HISTORY_FILENAME,
  type ResetHistoryMarker,
} from "../../src/audit/reset-history.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateRandomKey } from "../../src/core/random.js";
import { hashToString } from "../../src/core/hashing.js";
import { stringToBytes } from "../../src/core/encoding.js";

function makeMarkerLine(overrides: Partial<ResetHistoryMarker> = {}): string {
  const marker: ResetHistoryMarker = {
    started_at: "2026-04-24T22:00:00.000Z",
    completed_at: "2026-04-24T22:00:01.000Z",
    recovery_mode: "nuke",
    fortress_name: "fortress-alpha",
    storage_path: "/var/sanctuary/fortress-alpha",
    keychain_cleared: true,
    ...overrides,
  };
  return JSON.stringify(marker) + "\n";
}

describe("parseResetHistory", () => {
  const path = "/tmp/.reset-history.log";

  it("parses a single NDJSON line into one marker and computes the file hash", () => {
    const content = makeMarkerLine();
    const result = parseResetHistory(content, path);
    expect(result.markers).toHaveLength(1);
    expect(result.markers[0]!.recovery_mode).toBe("nuke");
    expect(result.markers[0]!.fortress_name).toBe("fortress-alpha");
    expect(result.markerHash).toBe(hashToString(stringToBytes(content)));
  });

  it("parses multiple NDJSON lines (iterative resets) in order", () => {
    const a = makeMarkerLine({ fortress_name: "first" });
    const b = makeMarkerLine({ fortress_name: "second" });
    const c = makeMarkerLine({ fortress_name: "third" });
    const content = a + b + c;
    const result = parseResetHistory(content, path);
    expect(result.markers.map((m) => m.fortress_name)).toEqual([
      "first",
      "second",
      "third",
    ]);
  });

  it("tolerates blank lines between entries", () => {
    const content = "\n" + makeMarkerLine() + "\n\n" + makeMarkerLine() + "\n";
    const result = parseResetHistory(content, path);
    expect(result.markers).toHaveLength(2);
  });

  it("treats an empty file as zero markers", () => {
    const result = parseResetHistory("", path);
    expect(result.markers).toHaveLength(0);
    expect(result.markerHash).toBe(hashToString(stringToBytes("")));
  });

  it("throws ResetHistoryMalformedError on non-JSON line", () => {
    const content = makeMarkerLine() + "not-json\n";
    expect(() => parseResetHistory(content, path)).toThrowError(
      ResetHistoryMalformedError
    );
    try {
      parseResetHistory(content, path);
    } catch (err) {
      expect(err).toBeInstanceOf(ResetHistoryMalformedError);
      expect((err as ResetHistoryMalformedError).lineNumber).toBe(2);
      expect((err as ResetHistoryMalformedError).markerPath).toBe(path);
    }
  });

  it("throws when a required field is missing", () => {
    const broken =
      JSON.stringify({
        started_at: "x",
        completed_at: "x",
        recovery_mode: "nuke",
        fortress_name: "x",
        storage_path: "x",
        // keychain_cleared missing
      }) + "\n";
    expect(() => parseResetHistory(broken, path)).toThrowError(
      /missing required field "keychain_cleared"/
    );
  });

  it("throws when a field has the wrong type", () => {
    const broken =
      JSON.stringify({
        started_at: "x",
        completed_at: "x",
        recovery_mode: "nuke",
        fortress_name: 42, // should be string
        storage_path: "x",
        keychain_cleared: true,
      }) + "\n";
    expect(() => parseResetHistory(broken, path)).toThrowError(
      /fortress_name.*string/
    );
  });

  it("throws when recovery_mode is not in the allowed set", () => {
    const broken = makeMarkerLine().replace(`"recovery_mode":"nuke"`, `"recovery_mode":"banana"`);
    expect(() => parseResetHistory(broken, path)).toThrowError(
      /recovery_mode must be one of/
    );
  });

  it("throws when a top-level array is supplied instead of an object", () => {
    const content = JSON.stringify(["not", "an", "object"]) + "\n";
    expect(() => parseResetHistory(content, path)).toThrowError(
      /expected a JSON object/
    );
  });
});

describe("consumeResetHistoryMarker", () => {
  let storageRoot: string;

  beforeEach(() => {
    storageRoot = mkdtempSync(join(tmpdir(), "sanctuary-reset-history-"));
  });

  afterEach(() => {
    rmSync(storageRoot, { recursive: true, force: true });
  });

  function newAuditLog(): AuditLog {
    return new AuditLog(new MemoryStorage(), generateRandomKey());
  }

  it("no marker present is a no-op (covers fresh-wrap regression risk)", async () => {
    const auditLog = newAuditLog();
    const result = await consumeResetHistoryMarker({
      storagePath: storageRoot,
      auditLog,
    });
    expect(result.emitted).toBe(0);
    expect(result.markerHash).toBeUndefined();
    const entries = (await auditLog.query({ limit: 100 })).entries;
    expect(entries).toHaveLength(0);
  });

  it("emits one fortress_recovered_from_reset entry per marker line and consumes the marker", async () => {
    const markerPath = join(storageRoot, RESET_HISTORY_FILENAME);
    const a = makeMarkerLine({ fortress_name: "first" });
    const b = makeMarkerLine({ fortress_name: "second" });
    const content = a + b;
    writeFileSync(markerPath, content, { mode: 0o600 });

    const auditLog = newAuditLog();
    const result = await consumeResetHistoryMarker({
      storagePath: storageRoot,
      auditLog,
    });
    expect(result.emitted).toBe(2);
    expect(result.markerHash).toBe(hashToString(stringToBytes(content)));
    expect(existsSync(markerPath)).toBe(false);

    const entries = (await auditLog.query({ limit: 100 })).entries;
    expect(entries).toHaveLength(2);
    for (const e of entries) {
      expect(e.layer).toBe("l2");
      expect(e.operation).toBe(RECOVERED_FROM_RESET_OPERATION);
      expect(e.identity_id).toBe("system");
      expect(e.result).toBe("success");
      expect(e.details!.reset_marker_total).toBe(2);
      expect(e.details!.reset_marker_hash).toBe(result.markerHash);
    }
    const indices = entries
      .map((e) => e.details!.reset_marker_index as number)
      .sort();
    expect(indices).toEqual([0, 1]);
    const fortressNames = entries
      .map((e) => e.details!.fortress_name as string)
      .sort();
    expect(fortressNames).toEqual(["first", "second"]);
  });

  it("re-running on a fortress with no marker is idempotent and does not duplicate entries", async () => {
    const markerPath = join(storageRoot, RESET_HISTORY_FILENAME);
    writeFileSync(markerPath, makeMarkerLine(), { mode: 0o600 });

    const auditLog = newAuditLog();
    const first = await consumeResetHistoryMarker({
      storagePath: storageRoot,
      auditLog,
    });
    expect(first.emitted).toBe(1);
    expect(existsSync(markerPath)).toBe(false);

    const second = await consumeResetHistoryMarker({
      storagePath: storageRoot,
      auditLog,
    });
    expect(second.emitted).toBe(0);

    const entries = (await auditLog.query({ limit: 100 })).entries;
    expect(entries).toHaveLength(1);
  });

  it("malformed marker throws ResetHistoryMalformedError, preserves the marker, and writes no audit entries", async () => {
    const markerPath = join(storageRoot, RESET_HISTORY_FILENAME);
    writeFileSync(markerPath, makeMarkerLine() + "not-json\n", { mode: 0o600 });

    const auditLog = newAuditLog();
    await expect(
      consumeResetHistoryMarker({ storagePath: storageRoot, auditLog })
    ).rejects.toBeInstanceOf(ResetHistoryMalformedError);

    expect(existsSync(markerPath)).toBe(true);
    const entries = (await auditLog.query({ limit: 100 })).entries;
    expect(entries).toHaveLength(0);
  });

  it("entries survive a fresh AuditLog opening the same storage with the same master key", async () => {
    const storagePath = join(storageRoot, "fortress");
    mkdirSync(storagePath, { recursive: true, mode: 0o700 });
    writeFileSync(join(storagePath, RESET_HISTORY_FILENAME), makeMarkerLine(), {
      mode: 0o600,
    });

    const masterKey = generateRandomKey();
    const filesystem = new FilesystemStorage(join(storagePath, "state"));
    const writer = new AuditLog(filesystem, masterKey);
    const result = await consumeResetHistoryMarker({
      storagePath,
      auditLog: writer,
    });
    expect(result.emitted).toBe(1);

    const reader = new AuditLog(new FilesystemStorage(join(storagePath, "state")), masterKey);
    const entries = (await reader.query({ limit: 100 })).entries;
    expect(entries).toHaveLength(1);
    expect(entries[0]!.operation).toBe(RECOVERED_FROM_RESET_OPERATION);
    expect(entries[0]!.details!.reset_marker_hash).toBe(result.markerHash);
  });

  it("preserves the verbatim marker hash so a verifier holding the original file can prove correspondence", async () => {
    const markerPath = join(storageRoot, RESET_HISTORY_FILENAME);
    const content = makeMarkerLine() + makeMarkerLine({ fortress_name: "B" });
    writeFileSync(markerPath, content);
    // Stash the bytes before they get consumed and the marker is deleted.
    const archivedBytes = readFileSync(markerPath);
    const archivedHash = hashToString(archivedBytes);

    const auditLog = newAuditLog();
    const result = await consumeResetHistoryMarker({
      storagePath: storageRoot,
      auditLog,
    });
    expect(result.markerHash).toBe(archivedHash);
    const entries = (await auditLog.query({ limit: 100 })).entries;
    for (const e of entries) {
      expect(e.details!.reset_marker_hash).toBe(archivedHash);
    }
  });
});
