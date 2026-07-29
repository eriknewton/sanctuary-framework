/**
 * Durable persistence + fail-closed rehydrate for the OPTIONAL M-of-N guardian
 * revocation requirement (competitor-readiness item 6: "no single person can
 * kill the fleet" MUST survive a restart).
 *
 * Invariants under test:
 *   - a configured requirement round-trips through the durable sync-state record
 *     (encrypt -> restart -> decrypt) and rehydrates the SAME roster;
 *   - a requirement whose fortress-master-signed roster VERIFIES against the
 *     pinned master rehydrates as enforceable;
 *   - a requirement whose roster does NOT verify (at-rest tamper / wrong
 *     fortress) rehydrates as `invalid` (fail-closed), NEVER silently as "none"
 *     (which would drop the fleet back to single-operator kill);
 *   - a record with NO requirement rehydrates as "none" (legacy single-operator);
 *   - the field is additive: a pre-item-6 record (no field) decodes to "none".
 *
 * Real crypto throughout: rosters are signed by a real fortress-master
 * (@noble/curves Ed25519) via issueGuardianRoster; nothing is mocked.
 */

import { describe, expect, it } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import { issueGuardianRoster } from "../../src/mesh/guardian/guardian-roster.js";
import { generateFortressMaster } from "../../src/mesh/trust-root.js";
import type {
  GuardianIdentity,
  GuardianRoster,
} from "../../src/mesh/guardian/types.js";
import type { FortressMasterPublicKey } from "../../src/mesh/types.js";
import {
  FederationSyncStateStore,
  emptyFederationSyncState,
  type FederationSyncStateSnapshot,
} from "../../src/v1/federation-sync-state-store.js";
import type { GuardianRevocationRequirement } from "../../src/v1/federation-revocation-guardian-gate.js";
import {
  decodeGuardianRevocationRequirement,
  encodeGuardianRevocationRequirement,
  verifyLoadedGuardianRevocationRequirement,
} from "../../src/v1/federation-guardian-revocation-policy.js";

// ── fixtures ─────────────────────────────────────────────────────────────────

function masterKey(): Uint8Array {
  return new Uint8Array(32).fill(9);
}

function buildGuardians(count: number): GuardianIdentity[] {
  const out: GuardianIdentity[] = [];
  for (let i = 0; i < count; i++) {
    const kp = generateKeypair();
    out.push({
      guardian_id: `guardian-${i}`,
      public_key: toBase64url(kp.publicKey),
      kind: "human",
      invited_at: new Date().toISOString(),
    });
  }
  return out;
}

function buildFixture(): {
  master: FortressMasterPublicKey;
  roster: GuardianRoster;
} {
  const fm = generateFortressMaster();
  const roster = issueGuardianRoster({
    m: 3,
    n: 5,
    guardians: buildGuardians(5),
    fortress_id: fm.public.fortress_id,
    version: 1,
    master_private_key: fm.private_key,
  });
  return { master: fm.public, roster };
}

function snapshotWith(
  requirement: GuardianRevocationRequirement | null,
  generation = 1,
): FederationSyncStateSnapshot {
  return {
    ...emptyFederationSyncState(),
    guardianRevocationRequirement: requirement,
    guardianRevocationRequirementGeneration: generation,
  };
}

// ── round-trip through the durable record ────────────────────────────────────

describe("guardian revocation requirement: durable persistence round-trip", () => {
  it("survives a simulated restart (encrypt -> new store over same storage -> decrypt)", async () => {
    const { roster } = buildFixture();
    const storage = new MemoryStorage();
    await new FederationSyncStateStore({ storage, masterKey: masterKey() }).persist(
      snapshotWith({ roster }),
    );

    // Fresh store instance, same on-disk bytes: the restart case.
    const afterRestart = await new FederationSyncStateStore({
      storage,
      masterKey: masterKey(),
    }).load();

    expect(afterRestart.guardianRevocationRequirement).not.toBeNull();
    expect(afterRestart.guardianRevocationRequirement!.roster.master_signature).toBe(
      roster.master_signature,
    );
    expect(afterRestart.guardianRevocationRequirement!.roster.m).toBe(3);
    expect(afterRestart.guardianRevocationRequirement!.roster.guardians).toHaveLength(5);
  });

  it("a record with NO requirement rehydrates as null (legacy single-operator)", async () => {
    const storage = new MemoryStorage();
    await new FederationSyncStateStore({ storage, masterKey: masterKey() }).persist(
      snapshotWith(null),
    );
    const loaded = await new FederationSyncStateStore({
      storage,
      masterKey: masterKey(),
    }).load();
    expect(loaded.guardianRevocationRequirement).toBeNull();
  });

  it("clearing the requirement (null) supersedes a previously-persisted one", async () => {
    const { roster } = buildFixture();
    const storage = new MemoryStorage();
    const store = new FederationSyncStateStore({ storage, masterKey: masterKey() });
    await store.persist(snapshotWith({ roster }, 1));
    // Operator disables the requirement at a HIGHER generation: null must win.
    await store.persist(snapshotWith(null, 2));
    const loaded = await store.load();
    expect(loaded.guardianRevocationRequirement).toBeNull();
    expect(loaded.guardianRevocationRequirementGeneration).toBe(2);
  });
});

// ── stale lower-generation write cannot clobber a fresher requirement ─────────

describe("guardian revocation requirement: generation counter blocks stale clobber", () => {
  it("a stale write (lower generation, null) does NOT overwrite a higher-generation requirement", async () => {
    const { roster } = buildFixture();
    const storage = new MemoryStorage();
    const store = new FederationSyncStateStore({ storage, masterKey: masterKey() });

    // The dashboard sets a requirement at generation 5 (already on disk).
    await store.persist(snapshotWith({ roster }, 5));

    // A STALE writer (the rotate-root CLI) loaded the blob BEFORE the set (it
    // carries generation 0, no requirement) and persists that stale snapshot.
    // Model it directly: a snapshot with null + generation 0.
    await store.persist(snapshotWith(null, 0));

    const loaded = await store.load();
    // The fresher generation-5 requirement MUST survive the stale null persist.
    expect(loaded.guardianRevocationRequirement).not.toBeNull();
    expect(loaded.guardianRevocationRequirement!.roster.master_signature).toBe(
      roster.master_signature,
    );
    expect(loaded.guardianRevocationRequirementGeneration).toBe(5);
  });

  it("a stale write (lower generation, OLD roster) does NOT overwrite a newer roster", async () => {
    const older = buildFixture();
    const newer = buildFixture();
    const storage = new MemoryStorage();
    const store = new FederationSyncStateStore({ storage, masterKey: masterKey() });

    // Newer roster committed at generation 9.
    await store.persist(snapshotWith({ roster: newer.roster }, 9));
    // Stale writer carrying the OLD roster at a lower generation 3.
    await store.persist(snapshotWith({ roster: older.roster }, 3));

    const loaded = await store.load();
    // The generation-9 roster (newer) MUST survive; the stale roster loses.
    expect(loaded.guardianRevocationRequirement!.roster.master_signature).toBe(
      newer.roster.master_signature,
    );
    expect(loaded.guardianRevocationRequirementGeneration).toBe(9);
  });

  it("a higher-generation write DOES supersede an older one (both directions work)", async () => {
    const { roster } = buildFixture();
    const storage = new MemoryStorage();
    const store = new FederationSyncStateStore({ storage, masterKey: masterKey() });

    // Requirement at generation 2, then cleared at generation 3 (higher wins).
    await store.persist(snapshotWith({ roster }, 2));
    await store.persist(snapshotWith(null, 3));
    let loaded = await store.load();
    expect(loaded.guardianRevocationRequirement).toBeNull();
    expect(loaded.guardianRevocationRequirementGeneration).toBe(3);

    // Re-enabled at generation 4 (higher still wins).
    await store.persist(snapshotWith({ roster }, 4));
    loaded = await store.load();
    expect(loaded.guardianRevocationRequirement).not.toBeNull();
    expect(loaded.guardianRevocationRequirementGeneration).toBe(4);
  });
});

// ── fail-closed verification on load ─────────────────────────────────────────

describe("guardian revocation requirement: fail-closed verification", () => {
  it("verifies to `verified` when the roster signature matches the pinned master", () => {
    const { master, roster } = buildFixture();
    const persisted = encodeGuardianRevocationRequirement({ roster });
    const decoded = decodeGuardianRevocationRequirement(persisted);
    const loaded = verifyLoadedGuardianRevocationRequirement(decoded, master);
    expect(loaded.kind).toBe("verified");
  });

  it("resolves to `invalid` (NOT none) when the persisted roster was tampered", () => {
    const { master, roster } = buildFixture();
    const persisted = encodeGuardianRevocationRequirement({ roster });
    // Tamper: raise M so the signed body no longer matches master_signature.
    persisted.roster.m = 1;
    const decoded = decodeGuardianRevocationRequirement(persisted);
    const loaded = verifyLoadedGuardianRevocationRequirement(decoded, master);
    // Fail-closed: must be `invalid`, never `none` (which would silently drop to
    // single-operator kill).
    expect(loaded.kind).toBe("invalid");
  });

  it("resolves to `invalid` when the roster is for a DIFFERENT fortress", () => {
    const a = buildFixture();
    const b = buildFixture();
    const persisted = encodeGuardianRevocationRequirement({ roster: a.roster });
    const decoded = decodeGuardianRevocationRequirement(persisted);
    // Verify a's roster against b's pinned master: cross-operator isolation.
    const loaded = verifyLoadedGuardianRevocationRequirement(decoded, b.master);
    expect(loaded.kind).toBe("invalid");
  });

  it("resolves to `none` when nothing was persisted (absent field)", () => {
    const { master } = buildFixture();
    const decoded = decodeGuardianRevocationRequirement(undefined);
    const loaded = verifyLoadedGuardianRevocationRequirement(decoded, master);
    expect(loaded.kind).toBe("none");
  });

  it("throws on a present-but-structurally-malformed persisted requirement", () => {
    expect(() =>
      decodeGuardianRevocationRequirement({ v: 1, roster: { m: "nope" } }),
    ).toThrow();
    expect(() =>
      decodeGuardianRevocationRequirement({ v: 2, roster: {} }),
    ).toThrow();
  });
});
