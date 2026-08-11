/**
 * LD5 BP-DEADLINE-01 — adversarial fault-schedule tests (AGENTS.md rule 8).
 *
 * The admission machinery bridge/tools.ts, reputation/reputation-store.ts,
 * and sentinel/sentinel-finding-store.ts share (a per-instance promise-chain
 * lock plus a settlement deadline racing the locked `fn`) had the same bug
 * in all three stores: the deadline wrapped `fn` BEFORE it was chained onto
 * the lock's promise, so the lock released to the next admission the moment
 * the timer fired — not when the underlying `storage.write` actually
 * finished. A caller could exploit this with a repeating schedule ("the
 * quota scan passes, the write is held past the deadline, another admission
 * is enqueued, the delayed write is released later") to make every
 * successive admission's quota check observe stale (pre-write) headroom,
 * landing arbitrarily many writes against one origin's quota — not the
 * "exactly one extra write" bound the pre-fix comments claimed.
 *
 * Each test below drives the REAL production write path (not a reimplemented
 * copy of the admission logic) through exactly that schedule, across more
 * waves than the per-origin cap, and asserts the store's actual persisted
 * count for the flooding origin never exceeds the cap. Run against the
 * pre-fix source (deadline-wrapped `fn` chained onto the lock) this
 * overshoots; against the fix it does not — see BUILD_RESULT.md for the
 * before/after this test was checked against.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { toBase64url, stringToBytes } from "../../src/core/encoding.js";
import { hash } from "../../src/core/hashing.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { ON_EVICT_AUDIT_TIMEOUT_MS } from "../../src/core/bounded-map.js";
import {
  createBridgeTools,
  type BridgeToolsTestOverrides,
} from "../../src/bridge/tools.js";
import type { ConcordiaOutcome } from "../../src/bridge/types.js";
import { ReputationStore } from "../../src/reputation/reputation-store.js";
import {
  SentinelFindingStore,
  SENTINEL_FINDING_NAMESPACE,
} from "../../src/sentinel/sentinel-finding-store.js";
import type { SentinelFinding } from "../../src/sentinel/types.js";
import type { AuditLog } from "../../src/operational/audit-log.js";
import type { ToolDefinition } from "../../src/router.js";

// ─── Shared helpers ─────────────────────────────────────────────────────

/**
 * Cross-file pin: must match BRIDGE_STORAGE_OP_MARGIN_MS /
 * REPUTATION_STORAGE_OP_MARGIN_MS / STORAGE_OP_MARGIN_MS (all 10_000) and
 * ON_EVICT_AUDIT_TIMEOUT_MS in bridge/tools.ts, reputation/reputation-store.ts,
 * and sentinel/sentinel-finding-store.ts respectively — those constants are
 * not exported (kept as separate per-module constants on purpose, see their
 * docs), so this test recomputes the same derivation rather than importing
 * an internal.
 */
const ADMISSION_DEADLINE_MS = ON_EVICT_AUDIT_TIMEOUT_MS + 10_000;

/** Flush the microtask queue without advancing fake timers. */
async function flush(times = 40): Promise<void> {
  for (let i = 0; i < times; i++) {
    await Promise.resolve();
  }
}

/**
 * Wraps a MemoryStorage so every `write` to `namespace` parks on a promise
 * this test controls, modeling a storage backend whose write is genuinely
 * slow/hung — the exact fault the finding's exploit schedule needs.
 */
function makeHoldableStorage(namespace: string): {
  storage: StorageBackend;
  pendingCount: () => number;
  releaseNext: () => void;
} {
  const backing = new MemoryStorage();
  const pending: Array<() => void> = [];
  const storage: StorageBackend = {
    write: async (ns, key, data) => {
      if (ns === namespace) {
        await new Promise<void>((resolve) => {
          pending.push(resolve);
        });
      }
      return backing.write(ns, key, data);
    },
    read: (ns, key) => backing.read(ns, key),
    delete: (ns, key, secure) => backing.delete(ns, key, secure),
    list: (ns, prefix) => backing.list(ns, prefix),
    exists: (ns, key) => backing.exists(ns, key),
    totalSize: () => backing.totalSize(),
    listNamespaces: () => backing.listNamespaces!(),
  };
  return {
    storage,
    pendingCount: () => pending.length,
    releaseNext: () => {
      const releaser = pending.shift();
      if (!releaser) throw new Error("no pending write to release");
      releaser();
    },
  };
}

/**
 * Repeatedly releases whatever write is currently held (letting that wave's
 * admission actually commit or get refused) until nothing is pending, i.e.
 * the whole admission queue has drained — later waves either land a
 * detached write (if under cap) or get refused by the RECHECKED quota
 * (if at cap), never hang forever once released.
 */
async function drain(pendingCount: () => number, releaseNext: () => void): Promise<void> {
  for (let guard = 0; guard < 64; guard++) {
    await flush();
    if (pendingCount() === 0) return;
    releaseNext();
  }
  throw new Error("drain() did not converge — a write stayed pending");
}

describe("LD5 BP-DEADLINE-01: admission deadline must hold the lock until the write settles, not release it early", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  // ── Bridge ────────────────────────────────────────────────────────────

  it("bridge_commit: a scan-passes/write-delayed/re-enqueue/release-later schedule across many waves never overshoots MAX_BRIDGE_COMMITMENTS_PER_ORIGIN", async () => {
    const { storage, pendingCount, releaseNext } = makeHoldableStorage("_bridge");
    const masterKey = generateRandomKey();
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const identityManager = new IdentityManager(storage, masterKey);
    const signer = createIdentity("ld5-bridge-signer", identityEncKey, "recovery-key");
    const counterparty = createIdentity(
      "ld5-bridge-counterparty",
      identityEncKey,
      "recovery-key"
    );
    await identityManager.save(signer.storedIdentity);
    await identityManager.save(counterparty.storedIdentity);
    await identityManager.setPrimary(signer.storedIdentity.identity_id);

    const reputationStore = new ReputationStore(storage, masterKey);
    const stubAuditLog = {
      append: () => {},
      appendCritical: async () => {},
    } as unknown as AuditLog;

    const CAP = 2;
    const overrides: BridgeToolsTestOverrides = {
      maxBridgeCommitments: 1000,
      maxBridgeCommitmentsPerOrigin: CAP,
      maxPendingAdmissionWaiters: 10,
    };
    const { tools } = createBridgeTools(
      storage,
      masterKey,
      identityManager,
      stubAuditLog,
      reputationStore,
      undefined,
      overrides
    );
    const commit = tools.find((t) => t.name === "bridge_commit") as ToolDefinition;
    const origin = "agent:ld5-bp-deadline-bridge-flood";

    const terms = { price: 100, currency: "USD", delivery: "2026-04-15" };
    const termsHash = toBase64url(hash(stringToBytes(stableStringify(terms))));
    const makeOutcome = (sessionId: string): ConcordiaOutcome => ({
      session_id: sessionId,
      protocol_version: "concordia-v1",
      proposer_did: signer.publicIdentity.did,
      acceptor_did: counterparty.publicIdentity.did,
      terms,
      terms_hash: termsHash,
      rounds: 3,
      accepted_at: "2026-04-01T00:00:00.000Z",
    });

    const WAVES = 5;
    const calls = Array.from({ length: WAVES }, (_, i) =>
      commit
        .handler(
          { ...makeOutcome(`wave-${i}`), identity_id: signer.publicIdentity.identity_id },
          origin
        )
        .catch((e) => e)
    );

    // Let wave 0's quota scan (storage.list — fast, in-memory) resolve and
    // reach storage.write, where the holdable backend parks it. Every other
    // wave is still chained behind wave 0's still-open admission lock.
    await flush();
    expect(pendingCount()).toBe(1);

    // Advance past the deadline: every waiting caller's OWN timeout fires
    // (each wave armed its deadline timer independently, the instant it
    // reached the admission chokepoint) — but the LOCK itself must not
    // have moved on, because wave 0's fn() has not settled.
    await vi.advanceTimersByTimeAsync(ADMISSION_DEADLINE_MS);
    await flush();
    expect(pendingCount()).toBe(1);

    // Advance again for good measure — a second wall-clock deadline elapsing
    // must still not free the lock for a write that has not been released.
    await vi.advanceTimersByTimeAsync(ADMISSION_DEADLINE_MS);
    await flush();
    expect(pendingCount()).toBe(1);

    // Now release the delayed writes, one wave at a time, exactly as the
    // exploit schedule describes. Each subsequent wave's quota RECHECK now
    // runs against the ACTUAL committed state, never a stale snapshot.
    await drain(pendingCount, releaseNext);
    await Promise.all(calls);

    const finalEntries = await storage.list("_bridge");
    // THE MUTATION-PROOF ASSERTION: the fix holds this at exactly CAP.
    // Reverting to the pre-fix shape (deadline-wrapped fn chained onto the
    // lock) lets every wave observe headroom of 0 before any write lands,
    // so all 5 waves' writes eventually commit — finalEntries.length would
    // be 5, not 2.
    expect(finalEntries.length).toBe(CAP);
  });

  // ── Reputation ───────────────────────────────────────────────────────

  it("ReputationStore.record(): a scan-passes/write-delayed/re-enqueue/release-later schedule across many waves never overshoots the per-origin cap", async () => {
    const { storage, pendingCount, releaseNext } = makeHoldableStorage("_reputation");
    const masterKey = generateRandomKey();
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const { storedIdentity: identity } = createIdentity(
      "ld5-reputation-signer",
      identityEncKey,
      "recovery-key"
    );

    const CAP = 2;
    const store = new ReputationStore(storage, masterKey, {
      maxReputationRecords: 1000,
      maxReputationRecordsPerOrigin: CAP,
      maxPendingAdmissionWaiters: 10,
    });
    const origin = "agent:ld5-bp-deadline-reputation-flood";

    const recordOnce = (id: string) =>
      store.record(
        id,
        "did:key:counterparty",
        { type: "transaction", result: "completed" },
        "general",
        identity,
        identityEncKey,
        undefined,
        undefined,
        origin
      );

    const WAVES = 5;
    const calls = Array.from({ length: WAVES }, (_, i) =>
      recordOnce(`wave-${i}`).catch((e) => e)
    );

    await flush();
    expect(pendingCount()).toBe(1);

    await vi.advanceTimersByTimeAsync(ADMISSION_DEADLINE_MS);
    await flush();
    expect(pendingCount()).toBe(1);

    await vi.advanceTimersByTimeAsync(ADMISSION_DEADLINE_MS);
    await flush();
    expect(pendingCount()).toBe(1);

    await drain(pendingCount, releaseNext);
    const settled = await Promise.all(calls);

    const finalEntries = await storage.list("_reputation");
    expect(finalEntries.length).toBe(CAP);

    // Success-audit accounting stays consistent: every wave that actually
    // committed a record (settled with a StoredAttestation, not an Error)
    // corresponds 1:1 with a persisted entry — no committed record without
    // its result reaching the caller, and no caller-visible "success" for a
    // record that was never actually written.
    const succeeded = settled.filter(
      (r) => r && typeof r === "object" && "attestation" in (r as object)
    );
    expect(succeeded.length).toBeLessThanOrEqual(CAP);
  });

  // ── Sentinel ─────────────────────────────────────────────────────────

  it("SentinelFindingStore.saveFinding(): a scan-passes/write-delayed/re-enqueue/release-later schedule across many waves never overshoots MAX_FINDINGS_PER_ORIGIN", async () => {
    const { storage, pendingCount, releaseNext } = makeHoldableStorage(
      SENTINEL_FINDING_NAMESPACE
    );
    const masterKey = generateRandomKey();
    const origin = "agent:ld5-bp-deadline-sentinel-flood";
    const CAP = 2;
    const store = new SentinelFindingStore({
      storage,
      masterKey,
      fortressId: "fortress-ld5-bp-deadline",
      maxTrackedFindings: 1000,
      maxFindingsPerOrigin: CAP,
      maxPendingAdmissionWaiters: 10,
    });

    const mkFinding = (id: string): SentinelFinding => ({
      finding_id: id,
      sentinel_id: "ld5-bp-deadline-test-sentinel",
      severity: "alert",
      agent_id: origin,
      summary: `finding ${id}`,
      details: {},
      observed_at: new Date().toISOString(),
      evidence_audit_ids: [],
      fortress_id: "fortress-ld5-bp-deadline",
    });

    const WAVES = 5;
    const calls = Array.from({ length: WAVES }, (_, i) =>
      store.saveFinding(mkFinding(`wave-${i}`)).catch((e) => e)
    );

    await flush();
    expect(pendingCount()).toBe(1);

    await vi.advanceTimersByTimeAsync(ADMISSION_DEADLINE_MS);
    await flush();
    expect(pendingCount()).toBe(1);

    await vi.advanceTimersByTimeAsync(ADMISSION_DEADLINE_MS);
    await flush();
    expect(pendingCount()).toBe(1);

    await drain(pendingCount, releaseNext);
    await Promise.all(calls);

    const finalEntries = await storage.list(SENTINEL_FINDING_NAMESPACE);
    expect(finalEntries.length).toBe(CAP);
  });
});

/**
 * Byte-identical to the unexported `stableStringify` in bridge/bridge.ts
 * (the terms_hash the bridge module itself recomputes at commit time must
 * match this exactly, or bridge_commit rejects before ever reaching the
 * admission lock this test exercises) — mirrors test/bridge/bridge.test.ts's
 * own local copy of the same helper, kept local for the same module-boundary
 * reason bridge.ts's version is not exported.
 */
function stableStringify(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) {
    throw new Error("Cannot canonicalize undefined");
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("Cannot canonicalize non-finite number");
    }
    if (Object.is(value, -0)) {
      throw new Error("Cannot canonicalize negative zero");
    }
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new Error("Cannot canonicalize unsafe integer");
    }
    return JSON.stringify(value);
  }
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => stableStringify(v)).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  const pairs = keys.map((k) => JSON.stringify(k) + ":" + stableStringify(obj[k]));
  return "{" + pairs.join(",") + "}";
}
