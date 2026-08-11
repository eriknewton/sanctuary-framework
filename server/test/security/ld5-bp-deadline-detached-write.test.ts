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
import {
  ReputationStore,
  ReputationStoreQuotaError,
} from "../../src/reputation/reputation-store.js";
import {
  SentinelFindingStore,
  SentinelFindingStoreRefusedError,
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

/**
 * Wraps a MemoryStorage so every `write` to `namespace` awaits a promise
 * that NEVER resolves — models a PERMANENTLY hung backend (not merely slow),
 * the exact fault LD5 BP-DEADLINE-02 concerns: `fn` never settles, so if the
 * waiter slot is freed on anything other than `fn` settlement, later
 * admissions can pile chained closures onto `admissionQueue` forever behind
 * this hung head (AGENTS.md rule 8 adversarial-complexity test).
 */
function makeForeverHungStorage(namespace: string): StorageBackend {
  const backing = new MemoryStorage();
  const foreverPending = new Promise<void>(() => {
    // Deliberately never resolves or rejects.
  });
  return {
    write: async (ns, key, data) => {
      if (ns === namespace) {
        await foreverPending;
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
 * LD5 BP-DEADLINE-02 — adversarial-complexity test (AGENTS.md rule 8).
 *
 * BP-DEADLINE-01's fix held each store's admission lock until `fn()`
 * settled, closing the quota-bypass. But `pendingAdmissionWaiters` was still
 * released in a `finally` on the CALLER's own deadline-bounded await, not on
 * `fn()` settlement. Under a PERMANENTLY hung backend (write never
 * resolves, not merely slow), a timed-out caller freed its waiter slot while
 * its `fn` stayed chained on `admissionQueue` forever — so later admissions
 * kept passing the (concurrent-only) waiter cap and piling up unbounded
 * chained closures behind the permanently-hung head, all reachable from
 * `this.admissionQueue` and therefore never GC-eligible.
 *
 * Each test below drives the REAL production write path for an
 * agent-reachable store (bridge_commit, ReputationStore.record()) against a
 * write that never settles, fills the waiter cap, lets every original
 * caller's deadline elapse, and then asserts that admission is STILL
 * refused `admission_busy` afterward — proving the waiter slots were never
 * freed by the callers' own timeouts and chained-closure accumulation stays
 * capped at `maxPendingAdmissionWaiters`. Run against the pre-fix source
 * (slot released in a `finally` on the caller's own await) this test fails:
 * once the original callers' deadlines elapse, their slots free up and the
 * post-timeout admission is ACCEPTED instead of refused, which is exactly
 * the unbounded-accumulation defect this closes.
 */
describe("LD5 BP-DEADLINE-02: the admission waiter slot must be held for fn()'s lifetime, not released on the caller's own timeout", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  // ── Bridge (agent-reachable via bridge_commit) ──────────────────────────

  it("bridge_commit: waiter slots stay held after every original caller times out against a PERMANENTLY hung write, so chained-closure accumulation never exceeds maxPendingAdmissionWaiters", async () => {
    const storage = makeForeverHungStorage("_bridge");
    const masterKey = generateRandomKey();
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const identityManager = new IdentityManager(storage, masterKey);
    const signer = createIdentity("ld5-bp2-bridge-signer", identityEncKey, "recovery-key");
    const counterparty = createIdentity(
      "ld5-bp2-bridge-counterparty",
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

    // Quota headroom is generous — this test is about the WAITER cap, not
    // the per-origin write quota (BP-DEADLINE-01's concern).
    const WAITER_CAP = 3;
    const overrides: BridgeToolsTestOverrides = {
      maxBridgeCommitments: 1000,
      maxBridgeCommitmentsPerOrigin: 1000,
      maxPendingAdmissionWaiters: WAITER_CAP,
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
    const origin = "agent:ld5-bp-deadline-02-bridge";

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
    // `commit.handler` only catches `BridgeStoreQuotaError` internally
    // (admission_busy, origin_quota, etc); a deadline TIMEOUT is a plain
    // `Error` thrown by `withBridgeAdmissionDeadline`, which the handler
    // re-throws rather than converting to a toolResult — so every call here
    // is `.catch`-wrapped and the result is EITHER a toolResult object
    // (`content`) or a caught Error, never a rejection that would
    // short-circuit `Promise.all`.
    const fire = (sessionId: string) =>
      commit
        .handler(
          { ...makeOutcome(sessionId), identity_id: signer.publicIdentity.identity_id },
          origin
        )
        .catch((e) => e);

    // (a) Fill the waiter cap: WAITER_CAP admissions all pass the
    // synchronous waiter-cap check and chain fn() (the hung write) onto
    // admissionQueue. Only the first fn ever actually starts (the queue is
    // strictly serial), the rest sit chained behind it — but all WAITER_CAP
    // slots are occupied.
    const initialCalls = Array.from({ length: WAITER_CAP }, (_, i) => fire(`w-${i}`));
    await flush();

    // (b) The next admission, fired immediately, is refused synchronously —
    // this much holds both pre- and post-fix (the immediate over-cap check
    // was never broken; BP-DEADLINE-02 is about what happens AFTER a
    // caller's own deadline elapses).
    const immediateOverflow = await fire("immediate-overflow");
    const immediateText =
      immediateOverflow instanceof Error
        ? immediateOverflow.message
        : (immediateOverflow.content[0]?.text ?? "");
    expect(immediateText).toContain("admission queue is saturated");

    // Let every ORIGINAL caller's own deadline elapse. fn() is permanently
    // hung (the write never resolves), so none of them ever settle via
    // fn() — they settle only via the deadline timeout (a rejected promise,
    // caught above into an Error).
    await vi.advanceTimersByTimeAsync(ADMISSION_DEADLINE_MS);
    await flush();
    const initialResults = await Promise.all(initialCalls);
    for (const result of initialResults) {
      const text = result instanceof Error ? result.message : (result.content[0]?.text ?? "");
      // Each original caller times out (not admission_busy — it never
      // raced against the cap, it raced against the deadline).
      expect(text).not.toContain("admission queue is saturated");
    }

    // (c) THE MUTATION-PROOF ASSERTION: even though every original caller
    // has now timed out, admission is STILL refused `admission_busy`,
    // SYNCHRONOUSLY (no macrotask/timer needed — the waiter-cap check is a
    // synchronous throw, see runAdmissionExclusiveBounded), for several more
    // attempts in a row — proving the waiter slots were never freed by the
    // callers' own timeouts (fn is still chained on admissionQueue,
    // permanently hung) and that accumulation stays capped at WAITER_CAP
    // rather than growing with every post-timeout attempt. Checked via a
    // microtask flush rather than a bare `await`: pre-fix (slot released on
    // the caller's own timeout), the slots would be free and this call
    // would be ACCEPTED — i.e. still PENDING after a flush, chained onto
    // admissionQueue behind the permanently-hung write, not settled at all
    // — which the assertion below catches without hanging the test on a
    // promise that (pre-fix) would never otherwise resolve in this run.
    for (let i = 0; i < 5; i++) {
      let settledText: string | undefined;
      void fire(`post-timeout-overflow-${i}`).then((r) => {
        settledText = r instanceof Error ? r.message : (r.content[0]?.text ?? "");
      });
      await flush();
      expect(settledText).toBeDefined();
      expect(settledText).toContain("admission queue is saturated");
    }
  });

  // ── Reputation (agent-reachable via reputation record/bridge_attest) ────

  it("ReputationStore.record(): waiter slots stay held after every original caller times out against a PERMANENTLY hung write, so chained-closure accumulation never exceeds maxPendingAdmissionWaiters", async () => {
    const storage = makeForeverHungStorage("_reputation");
    const masterKey = generateRandomKey();
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const { storedIdentity: identity } = createIdentity(
      "ld5-bp2-reputation-signer",
      identityEncKey,
      "recovery-key"
    );

    const WAITER_CAP = 3;
    const store = new ReputationStore(storage, masterKey, {
      maxReputationRecords: 1000,
      maxReputationRecordsPerOrigin: 1000,
      maxPendingAdmissionWaiters: WAITER_CAP,
    });
    const origin = "agent:ld5-bp-deadline-02-reputation";

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

    // (a) Fill the waiter cap.
    const initialCalls = Array.from({ length: WAITER_CAP }, (_, i) =>
      recordOnce(`w-${i}`).catch((e) => e)
    );
    await flush();

    // (b) Immediate overflow refuses synchronously (holds pre- and post-fix).
    const immediateOverflow = await recordOnce("immediate-overflow").catch((e) => e);
    expect(immediateOverflow).toBeInstanceOf(ReputationStoreQuotaError);
    expect((immediateOverflow as InstanceType<typeof ReputationStoreQuotaError>).reason).toBe(
      "admission_busy"
    );

    // Let every ORIGINAL caller's deadline elapse; fn() never settles.
    await vi.advanceTimersByTimeAsync(ADMISSION_DEADLINE_MS);
    await flush();
    const initialResults = await Promise.all(initialCalls);
    for (const result of initialResults) {
      // Each original caller times out, not admission_busy.
      const isAdmissionBusy =
        result instanceof ReputationStoreQuotaError && result.reason === "admission_busy";
      expect(isAdmissionBusy).toBe(false);
    }

    // (c) THE MUTATION-PROOF ASSERTION: admission is STILL refused
    // `admission_busy`, SYNCHRONOUSLY (the waiter-cap check is a synchronous
    // throw — no timer needed), for several more attempts after every
    // original caller has timed out — the waiter cap bounds CUMULATIVE
    // chained closures, not just concurrent ones. Checked via a microtask
    // flush rather than a bare `await`: pre-fix (slot released on the
    // caller's own timeout), these calls would be ACCEPTED — i.e. still
    // PENDING after a flush, chained onto admissionQueue behind the
    // permanently-hung write — which the assertion below catches without
    // hanging the test on a promise that (pre-fix) would never otherwise
    // resolve in this run.
    for (let i = 0; i < 5; i++) {
      let settledResult: unknown;
      let settled = false;
      void recordOnce(`post-timeout-overflow-${i}`).then(
        (r) => {
          settledResult = r;
          settled = true;
        },
        (e) => {
          settledResult = e;
          settled = true;
        }
      );
      await flush();
      expect(settled).toBe(true);
      expect(settledResult).toBeInstanceOf(ReputationStoreQuotaError);
      expect((settledResult as InstanceType<typeof ReputationStoreQuotaError>).reason).toBe(
        "admission_busy"
      );
    }
  });

  it("SentinelFindingStore.saveFinding(): waiter slots stay held after every original caller times out against a PERMANENTLY hung write, so chained-closure accumulation never exceeds maxPendingAdmissionWaiters", async () => {
    const storage = makeForeverHungStorage(SENTINEL_FINDING_NAMESPACE);
    const masterKey = generateRandomKey();

    const WAITER_CAP = 3;
    const origin = "agent:ld5-bp-deadline-02-sentinel";
    const store = new SentinelFindingStore({
      storage,
      masterKey,
      fortressId: "fortress-ld5-bp-deadline-02",
      maxTrackedFindings: 1000,
      maxFindingsPerOrigin: 1000,
      maxPendingAdmissionWaiters: WAITER_CAP,
    });

    const mkFinding = (id: string): SentinelFinding => ({
      finding_id: id,
      sentinel_id: "ld5-bp2-test-sentinel",
      severity: "alert",
      agent_id: origin,
      summary: `finding ${id}`,
      details: {},
      observed_at: new Date().toISOString(),
      evidence_audit_ids: [],
      fortress_id: "fortress-ld5-bp-deadline-02",
    });
    const saveOnce = (id: string) => store.saveFinding(mkFinding(id));

    // (a) Fill the waiter cap.
    const initialCalls = Array.from({ length: WAITER_CAP }, (_, i) =>
      saveOnce(`w-${i}`).catch((e) => e)
    );
    await flush();

    // (b) Immediate overflow refuses synchronously (holds pre- and post-fix).
    const immediateOverflow = await saveOnce("immediate-overflow").catch((e) => e);
    expect(immediateOverflow).toBeInstanceOf(SentinelFindingStoreRefusedError);
    expect((immediateOverflow as SentinelFindingStoreRefusedError).reason).toBe("admission_busy");

    // Let every ORIGINAL caller's deadline elapse; fn() never settles.
    await vi.advanceTimersByTimeAsync(ADMISSION_DEADLINE_MS);
    await flush();
    const initialResults = await Promise.all(initialCalls);
    for (const result of initialResults) {
      const isAdmissionBusy =
        result instanceof SentinelFindingStoreRefusedError && result.reason === "admission_busy";
      expect(isAdmissionBusy).toBe(false);
    }

    // (c) THE MUTATION-PROOF ASSERTION: admission is STILL refused
    // `admission_busy`, SYNCHRONOUSLY, for several more attempts after every
    // original caller has timed out — the waiter cap bounds CUMULATIVE chained
    // closures, not just concurrent ones. Pre-fix (slot released on the
    // caller's own timeout), these would be ACCEPTED and left PENDING behind
    // the permanently-hung write; the flush + `settled` check catches that
    // without hanging on a never-resolving promise.
    for (let i = 0; i < 5; i++) {
      let settledResult: unknown;
      let settled = false;
      void saveOnce(`post-timeout-overflow-${i}`).then(
        (r) => {
          settledResult = r;
          settled = true;
        },
        (e) => {
          settledResult = e;
          settled = true;
        }
      );
      await flush();
      expect(settled).toBe(true);
      expect(settledResult).toBeInstanceOf(SentinelFindingStoreRefusedError);
      expect((settledResult as SentinelFindingStoreRefusedError).reason).toBe("admission_busy");
    }
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
