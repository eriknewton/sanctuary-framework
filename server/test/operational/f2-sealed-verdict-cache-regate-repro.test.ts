/**
 * F2 BLOCKER-1 residual (adversarial re-gate round 4, 2026-07-14; fixed round 5,
 * 2026-07-15) PROMOTED REGRESSION.
 *
 * Round 3 collapsed the cleanliness decision into ONE chokepoint
 * (`AuditLog.getAuditChainVerdict()`), and `f2-blocker1-no-false-green.test.ts`
 * proves a FRESH reader flips to `findings` over an in-place sealed tamper.
 * Round 4 (Codex + Opus) found the residual this file guards: the sealed-region
 * verdict was MEMOIZED on a metadata fingerprint (count + size/mtime), which the
 * exact in-place sealed-tamper adversary can FORGE — a same-length ciphertext
 * byte-flip preserves size and `utimes` restores mtime — so a LONG-LIVED
 * `AuditLog` instance (the process-lifetime instance the MCP server / dashboard
 * hold) served a STALE `verified` from cache after a real sealed tamper.
 *
 * The fix makes the memo key CONTENT-authenticated: `sealedRegionFingerprint`
 * reads the same stored envelope bytes the verifier reads, so any in-place edit
 * flips the digest and forces a re-walk. This test exercises the SAME instance
 * across the tamper (the fresh-reader test does not), warming the cache to
 * `verified` first, then a size+mtime-preserving in-place tamper, and asserts
 * the SAME instance now returns `findings`. Against the pre-fix metadata
 * fingerprint this test fails (stale `verified` from cache); post-fix it passes.
 */

import { mkdtemp, open, readdir, rm, utimes } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { AuditLog } from "../../src/operational/audit-log.js";
import { migrateFortressAuditStoreSplit } from "../../src/operational/audit-store-split.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateRandomKey } from "../../src/core/random.js";

const dirs: string[] = [];

afterEach(async () => {
  for (const d of dirs.splice(0)) {
    await rm(d, { recursive: true, force: true }).catch(() => undefined);
  }
});

/**
 * Build a migrated fortress: a boundary-sealed prefix + an intact post-split
 * suffix, plus ONE long-lived `AuditLog` instance (the process-lifetime
 * instance the stale-cache exploit needs).
 */
async function migratedFortress() {
  const root = await mkdtemp(join(tmpdir(), "sanctuary-f2-sealedcache-"));
  dirs.push(root);
  const statePath = join(root, "state");
  const storage = new FilesystemStorage(statePath);
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);

  // Pre-split history (becomes the sealed prefix).
  for (let i = 0; i < 4; i++) {
    await auditLog.appendCritical({
      layer: "l1",
      operation: `pre-split-op-${i}`,
      identity_id: "agent-a",
      result: "success",
    });
  }
  await auditLog.flush();

  // Seal the prefix behind the boundary.
  await migrateFortressAuditStoreSplit({ storage, masterKey });

  // Intact post-split suffix so the routine chain is clean.
  await auditLog.appendCritical({
    layer: "l1",
    operation: "post-split-op",
    identity_id: "agent-a",
    result: "success",
  });
  await auditLog.flush();

  return { statePath, storage, masterKey, auditLog };
}

/** A whole-second epoch that round-trips exactly through `utimes` (sub-ms
 * precision does not survive `utimes`, so a whole second is what lets the
 * tamper leave size AND mtime byte-identical to the warm-call snapshot — the
 * precondition the forgeable metadata fingerprint required). */
const PINNED_EPOCH_SEC = 1_700_000_000;

/** Locate a mid-prefix sealed entry and pin its mtime to {@link PINNED_EPOCH_SEC}
 * BEFORE the cache is warmed, so the post-tamper mtime restore is exact. */
async function pinSealedEntry(statePath: string): Promise<string> {
  const auditDir = join(statePath, "_audit");
  const files = (await readdir(auditDir)).filter((f) => f.startsWith("entry-")).sort();
  const target = join(auditDir, files[1]!); // a mid-prefix sealed entry
  await utimes(target, PINNED_EPOCH_SEC, PINNED_EPOCH_SEC);
  return target;
}

/**
 * Tamper the sealed entry IN PLACE preserving byte length, then restore the
 * pinned mtime — the exact adversary the metadata fingerprint could not see.
 * Flips one character inside the base64 `encrypted_payload_bytes` value via a
 * raw-text replacement (JSON re-serialization is avoided so every other byte is
 * identical). Asserts size AND mtime are byte-identical to the warm snapshot, so
 * the old `tip:count:newest:sizeSum:mtimeAgg` fingerprint would be UNCHANGED.
 */
async function tamperSealedEntryPreservingMetadata(target: string): Promise<void> {
  // One FileHandle for the whole check-tamper-recheck sequence, so every
  // operation acts on the same open file (no path re-resolution between the
  // stat and the write; CodeQL js/file-system-race).
  const fh = await open(target, "r+");
  try {
    const before = await fh.stat();
    const rawText = await fh.readFile("utf-8");
    const parsed = JSON.parse(rawText) as { encrypted_payload_bytes: string };
    const payload = parsed.encrypted_payload_bytes;
    const idx = Math.floor(payload.length / 2);
    const flipped = payload[idx] === "A" ? "B" : "A";
    const tamperedPayload = payload.slice(0, idx) + flipped + payload.slice(idx + 1);
    const tamperedText = rawText.replace(payload, tamperedPayload);
    expect(tamperedText.length).toBe(rawText.length);
    await fh.write(tamperedText, 0, "utf-8");
    await fh.utimes(PINNED_EPOCH_SEC, PINNED_EPOCH_SEC);
    const after = await fh.stat();
    expect(after.size).toBe(before.size);
    expect(after.mtimeMs).toBe(before.mtimeMs);
  } finally {
    await fh.close();
  }
}

describe("F2 sealed-verdict cache: a stale `verified` does not survive a size+mtime-preserving in-place sealed tamper", () => {
  it("the SAME long-lived AuditLog instance flips from cached `verified` to `findings` after the tamper", async () => {
    const f = await migratedFortress();
    const target = await pinSealedEntry(f.statePath);

    // Warm the memo on the long-lived instance: caches sealed `verified`.
    const warm = await f.auditLog.getAuditChainVerdict();
    expect(warm.status).toBe("verified");

    await tamperSealedEntryPreservingMetadata(target);

    // SAME instance: a metadata fingerprint would serve the stale `verified`.
    const after = await f.auditLog.getAuditChainVerdict();
    expect(after.status).toBe("findings");
    expect(after.sealed_region.status).toBe("hash_mismatch");
  });

  it("a fresh reader over the same on-disk tamper also reports `findings` (authoritative path)", async () => {
    const f = await migratedFortress();
    const target = await pinSealedEntry(f.statePath);
    await tamperSealedEntryPreservingMetadata(target);

    const fresh = await new AuditLog(f.storage, f.masterKey).getAuditChainVerdict();
    expect(fresh.status).toBe("findings");
    expect(fresh.sealed_region.status).toBe("hash_mismatch");
  });
});
