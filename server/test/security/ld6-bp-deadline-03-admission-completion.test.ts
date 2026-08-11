/**
 * LD6 BP-DEADLINE-03 -- durable mutation-proof oracle (AGENTS.md rule 8;
 * V2-6 of Admission_Completion_Design_Brief_2026-08-11.md).
 *
 * BP-DEADLINE-01/02 (ld5-bp-deadline-detached-write.test.ts) closed the
 * admission-lock-vs-deadline race for QUOTA accounting. BP-DEADLINE-03 is the
 * residue: the SUCCESS AUDIT could still disagree with the durable write --
 * a caller-facing deadline could fire before `appendCritical` ran, and the
 * pre-fix record id was random, so a timed-out caller had no safe key to
 * retry (a retry minted a SECOND record). The v1 oracle for this class
 * (`ld5-bp-deadline-detached-write.test.ts` ~318-329) asserted only
 * `succeeded.length <= CAP` against an in-memory audit SPY, inspected after
 * convergence -- it could not see a committed-but-unaudited record, and it
 * could not tell "one record, audited once" apart from "one record, audit
 * lost forever." This file is the v2 replacement: it drives the PRODUCTION
 * object graph (the real store class, the real `AuditLog` writing to the
 * SAME `StorageBackend` the store commits to, the real MCP tool handler
 * threading the `InLockAuditEmit` callback), injects the fault at the exact
 * "committed, not yet audited" instant, and reads back DURABLE state --
 * `storage.list()` for the commit set, a FRESH `AuditLog` instance's
 * `query()` (which reloads from disk/storage, never an in-memory cache) for
 * the audit set -- never an in-memory spy.
 *
 * Four named mutants (see the design brief V2-6) are each proven to flip an
 * assertion in this file from PASS to FAIL by a manual revert-run-restore
 * pass recorded in the build's final report; this file's job is to BE that
 * proof, not merely to claim it.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { toBase64url, stringToBytes, bytesToString } from "../../src/core/encoding.js";
import { hash } from "../../src/core/hashing.js";
import { encrypt, type EncryptedPayload } from "../../src/core/encryption.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { ON_EVICT_AUDIT_TIMEOUT_MS } from "../../src/core/bounded-map.js";
import {
  createBridgeTools,
  type BridgeToolsTestOverrides,
} from "../../src/bridge/tools.js";
import {
  createBridgeCommitment,
  deriveBridgeCommitmentId,
} from "../../src/bridge/bridge.js";
import type { ConcordiaOutcome, BridgeCommitment } from "../../src/bridge/types.js";
import {
  ReputationStore,
  deriveReputationAttestationId,
} from "../../src/reputation/reputation-store.js";
import { createReputationTools } from "../../src/reputation/tools.js";
import {
  buildBridgeAttestationMetrics,
} from "../../src/reputation/bridge-metrics.js";
import {
  SentinelFindingStore,
  SENTINEL_FINDING_NAMESPACE,
  SENTINEL_FINDING_KEY_PREFIX,
} from "../../src/sentinel/sentinel-finding-store.js";
import { Sentinel } from "../../src/sentinel/sentinel.js";
import { SentinelRegistry } from "../../src/sentinel/sentinel-registry.js";
import { SentinelDispatcher } from "../../src/sentinel/sentinel-dispatcher.js";
import { SENTINEL_AUDIT_OPS, type SentinelFinding } from "../../src/sentinel/types.js";
import type { ToolDefinition } from "../../src/router.js";

// ─── Shared helpers ─────────────────────────────────────────────────────

/**
 * Cross-file pin: must match BRIDGE_STORE_ADMISSION_DEADLINE_MS /
 * REPUTATION_STORE_ADMISSION_DEADLINE_MS (bridge/tools.ts,
 * reputation-store.ts) -- ON_EVICT_AUDIT_TIMEOUT_MS + 10_000, not exported
 * (kept as separate per-module constants on purpose, see their docs), so
 * this test recomputes the same derivation.
 */
const ADMISSION_DEADLINE_MS = ON_EVICT_AUDIT_TIMEOUT_MS + 10_000;

async function flush(times = 40): Promise<void> {
  for (let i = 0; i < times; i++) {
    await Promise.resolve();
  }
}

function parseToolResult(result: { content: Array<{ type: string; text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text);
}

async function callToolSafe(
  tool: ToolDefinition,
  args: Record<string, unknown>,
  callerIdentity?: string
): Promise<{ ok: true; value: Record<string, unknown> } | { ok: false; error: unknown }> {
  try {
    const result = await tool.handler(args, callerIdentity);
    return { ok: true, value: parseToolResult(result) };
  } catch (error) {
    return { ok: false, error };
  }
}

function findTool(tools: ToolDefinition[], name: string): ToolDefinition {
  const tool = tools.find((t) => t.name === name);
  if (!tool) throw new Error(`Missing tool: ${name}`);
  return tool;
}

/**
 * Byte-identical to the unexported `stableStringify` in bridge/bridge.ts --
 * mirrors test/bridge/bridge.test.ts's own local copy for the same
 * module-boundary reason bridge.ts's version is not exported.
 */
function stableStringify(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) throw new Error("Cannot canonicalize undefined");
  if (typeof value === "number") return JSON.stringify(value);
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map((v) => stableStringify(v)).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(obj[k])).join(",") + "}";
}

function makeOutcome(overrides?: Partial<ConcordiaOutcome>): ConcordiaOutcome {
  const terms = { price: 100, currency: "USD", delivery: "2026-08-11" };
  const termsHash = toBase64url(hash(stringToBytes(stableStringify(terms))));
  return {
    session_id: "ld6-session-001",
    protocol_version: "concordia-v1",
    proposer_did: "did:sanctuary:proposer-ld6",
    acceptor_did: "did:sanctuary:acceptor-ld6",
    terms,
    terms_hash: termsHash,
    rounds: 3,
    accepted_at: "2026-08-11T00:00:00.000Z",
    ...overrides,
  };
}

/**
 * Wraps a MemoryStorage so writes to `faultNamespace` can be independently
 * FAILED (the next N writes reject, modeling "audit backend down -- a
 * failure, not a crash," V2-2's fail-closed branch) or HELD (parked on an
 * unresolved promise, modeling a deadline-boundary hang, released on
 * demand). Writes to every OTHER namespace pass straight through to a real
 * MemoryStorage, so the store's own write always settles fast and
 * DURABLY -- exactly the "release storage.write to durable completion,
 * THEN hold/fail the durable audit append" fault shape V2-6 specifies.
 */
function makeFaultableStorage(faultNamespace: string): {
  storage: StorageBackend;
  queueRejections: (n: number, message?: string) => void;
  setHolding: (v: boolean) => void;
  pendingCount: () => number;
  releaseNext: () => void;
} {
  const backing = new MemoryStorage();
  let rejectQueue = 0;
  let rejectMessage = "simulated audit backend failure";
  let holding = false;
  const pending: Array<() => void> = [];
  const storage: StorageBackend = {
    write: async (ns, key, data) => {
      if (ns === faultNamespace) {
        if (rejectQueue > 0) {
          rejectQueue -= 1;
          throw new Error(rejectMessage);
        }
        if (holding) {
          await new Promise<void>((resolve) => {
            pending.push(resolve);
          });
        }
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
    queueRejections: (n, message) => {
      rejectQueue = n;
      if (message) rejectMessage = message;
    },
    setHolding: (v) => {
      holding = v;
    },
    pendingCount: () => pending.length,
    releaseNext: () => {
      const releaser = pending.shift();
      if (!releaser) throw new Error("no pending write to release");
      releaser();
    },
  };
}

/** The durable commit-id SET: `_bridge`/`_reputation` are keyed EXACTLY by
 * their content-derived id, so `storage.list()`'s keys ARE the committed
 * record ids -- no decrypt needed for the set-membership check I1/I2/I3
 * need. */
async function durableRecordIds(storage: StorageBackend, ns: string): Promise<Set<string>> {
  const metas: StorageEntryMeta[] = await storage.list(ns);
  return new Set(metas.map((m) => m.key));
}

/**
 * The durable audit success-entry SET, deduped by record id: constructs a
 * FRESH `AuditLog` instance over the SAME storage + masterKey (never reuses
 * the production instance's in-memory state) and calls `query()`, which
 * reloads persisted entries from `storage` itself -- this is the "reload
 * the on-disk audit chain" oracle V2-6 requires, not an in-memory spy.
 * Audit semantics are at-least-once (a reconcile retry may re-append an
 * already-present success entry, V2-2), so this dedupes by the id field --
 * a `Set` collapses duplicates for free.
 */
async function auditSuccessIds(
  storage: StorageBackend,
  masterKey: Uint8Array,
  operation: string,
  idField: string
): Promise<Set<string>> {
  const freshAuditLog = new AuditLog(storage, masterKey);
  const { entries } = await freshAuditLog.query({ operation_type: operation, limit: 100_000 });
  const ids = new Set<string>();
  for (const entry of entries) {
    if (entry.result !== "success") continue;
    const value = entry.details?.[idField];
    if (typeof value === "string") ids.add(value);
  }
  return ids;
}

// ─── Bridge (bridge_commit) ─────────────────────────────────────────────

describe("LD6 BP-DEADLINE-03: bridge_commit durable admission-completion oracle", () => {
  function setup(faultNamespace = "_audit", overridesPatch?: Partial<BridgeToolsTestOverrides>) {
    const { storage, queueRejections, setHolding, pendingCount, releaseNext } =
      makeFaultableStorage(faultNamespace);
    const masterKey = generateRandomKey();
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const identityManager = new IdentityManager(storage, masterKey);
    const signer = createIdentity("ld6-bridge-signer", identityEncKey, "recovery-key");
    const counterparty = createIdentity("ld6-bridge-counterparty", identityEncKey, "recovery-key");
    const reputationStore = new ReputationStore(storage, masterKey);
    const auditLog = new AuditLog(storage, masterKey);
    const overrides: BridgeToolsTestOverrides = {
      maxBridgeCommitments: 1000,
      maxBridgeCommitmentsPerOrigin: 1000,
      maxPendingAdmissionWaiters: 50,
      ...overridesPatch,
    };
    const { tools } = createBridgeTools(
      storage,
      masterKey,
      identityManager,
      auditLog,
      reputationStore,
      undefined,
      overrides
    );
    const commit = findTool(tools, "bridge_commit");
    return {
      storage,
      masterKey,
      identityManager,
      signer,
      counterparty,
      commit,
      queueRejections,
      setHolding,
      pendingCount,
      releaseNext,
    };
  }

  async function seedIdentities(rig: ReturnType<typeof setup>): Promise<void> {
    await rig.identityManager.save(rig.signer.storedIdentity);
    await rig.identityManager.save(rig.counterparty.storedIdentity);
    await rig.identityManager.setPrimary(rig.signer.storedIdentity.identity_id);
  }

  it("I1/I4: an audit-append failure fails the caller CLOSED (never a committed-without-audit success), and a retry self-heals to commit == audit", async () => {
    const rig = setup();
    await seedIdentities(rig);
    const outcome = makeOutcome();
    const args = { ...outcome, identity_id: rig.signer.storedIdentity.identity_id };
    const commitId = deriveBridgeCommitmentId(
      outcome.session_id,
      outcome.terms_hash,
      rig.signer.publicIdentity.did
    );

    // Fault: the audit append fails ONCE (audit backend down, not a
    // crash). The durable write still lands (never held), so this models
    // exactly the "committed, audit rejected" window V2-2 names.
    rig.queueRejections(1);
    const first = await callToolSafe(rig.commit, args);
    // I4 / mutant "caller-success-without-record": the caller must NEVER
    // be told success when the audit could not be confirmed durable.
    expect(first.ok).toBe(false);

    // I1 boundary state: durably committed, but NOT yet durably audited.
    const commitIdsAtBoundary = await durableRecordIds(rig.storage, "_bridge");
    const auditIdsAtBoundary = await auditSuccessIds(
      rig.storage,
      rig.masterKey,
      "bridge_commit",
      "bridge_commitment_id"
    );
    expect(commitIdsAtBoundary.has(commitId)).toBe(true);
    expect(auditIdsAtBoundary.has(commitId)).toBe(false);

    // Retry the IDENTICAL request (audit now succeeds): the existence
    // guard finds the already-committed record and reconciles the audit.
    const second = await callToolSafe(rig.commit, args);
    expect(second.ok).toBe(true);
    if (second.ok) {
      expect(second.value.already_committed).toBe(true);
      expect(second.value.bridge_commitment_id).toBe(commitId);
    }

    // I1 self-heal: commit and audit sets are now EQUAL.
    const commitIdsAfter = await durableRecordIds(rig.storage, "_bridge");
    const auditIdsAfter = await auditSuccessIds(
      rig.storage,
      rig.masterKey,
      "bridge_commit",
      "bridge_commitment_id"
    );
    expect(commitIdsAfter).toEqual(new Set([commitId]));
    expect(auditIdsAfter).toEqual(new Set([commitId]));

    // I2/I3: the retry did not duplicate the record.
    expect((await rig.storage.list("_bridge")).length).toBe(1);
  });

  it("I2/I3: N retries of an identical request settle to exactly ONE durable record (mutant: revert to random id => grows unbounded)", async () => {
    const rig = setup();
    await seedIdentities(rig);
    const outcome = makeOutcome({ session_id: "ld6-retry-session" });
    const args = { ...outcome, identity_id: rig.signer.storedIdentity.identity_id };

    const N = 5;
    for (let i = 0; i < N; i++) {
      const result = await callToolSafe(rig.commit, args);
      expect(result.ok).toBe(true);
    }

    const entries = await rig.storage.list("_bridge");
    expect(entries.length).toBe(1);
  });

  it("I2/I3 isolated: retry-idempotence holds from content-derived ids ALONE, with the legacy tuple-scan fallback disabled (the reachable post-migration operator configuration, V2-4 sunset flag) -- proves the id-derivation itself is load-bearing, not merely the legacy-scan safety net", async () => {
    const rig = setup("_audit", { legacyIdScanEnabled: false });
    await seedIdentities(rig);
    const outcome = makeOutcome({ session_id: "ld6-retry-session-no-legacy" });
    const args = { ...outcome, identity_id: rig.signer.storedIdentity.identity_id };

    const N = 5;
    for (let i = 0; i < N; i++) {
      const result = await callToolSafe(rig.commit, args);
      expect(result.ok).toBe(true);
    }

    const entries = await rig.storage.list("_bridge");
    expect(entries.length).toBe(1);
  });

  it("mutant 4 (id-collision-blocks-legit): a mismatched-tuple record pre-seeded at the derived key yields a loud fail-closed refusal, never a foreign already_committed", async () => {
    const rig = setup();
    await seedIdentities(rig);
    const outcome = makeOutcome({ session_id: "ld6-preseed-target" });
    const legitId = deriveBridgeCommitmentId(
      outcome.session_id,
      outcome.terms_hash,
      rig.signer.publicIdentity.did
    );

    // Pre-seed a GENUINE bridge commitment for a totally DIFFERENT
    // negotiation at the exact key the legit request will compute --
    // simulating a garbage/mis-filed record occupying the derived slot.
    const foreignOutcome = makeOutcome({ session_id: "ld6-preseed-foreign" });
    const foreignCommitment = createBridgeCommitment(
      foreignOutcome,
      rig.signer.storedIdentity,
      derivePurposeKey(rig.masterKey, "identity-encryption")
    );
    const bridgeEncKey = derivePurposeKey(rig.masterKey, "bridge-commitments");
    const record = { commitment: foreignCommitment, outcome: foreignOutcome, origin: "agent:preseed" };
    const encrypted: EncryptedPayload = encrypt(stringToBytes(JSON.stringify(record)), bridgeEncKey);
    await rig.storage.write("_bridge", legitId, stringToBytes(JSON.stringify(encrypted)));

    const args = { ...outcome, identity_id: rig.signer.storedIdentity.identity_id };
    const result = await callToolSafe(rig.commit, args);
    // BridgeIdOccupiedUnverifiedError is caught INSIDE the handler and
    // returned as a toolResult with an `error` field (not a rejection) --
    // the mutation-proof assertion is on THAT field, and on the ABSENCE of
    // a false already_committed carrying the foreign record's data.
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(String(result.value.error)).toMatch(/occupied.*intent verification/i);
      expect(result.value.already_committed).toBeUndefined();
      expect(result.value.bridge_commitment_id).toBeUndefined();
    }

    // The foreign record must never be handed back as this caller's own
    // already-committed result.
    const entries = await rig.storage.list("_bridge");
    expect(entries.length).toBe(1); // only the pre-seeded foreign record
  });

  it("mutant 3 guard (caller-success-without-record): a deadline timeout on a stalled audit write NEVER surfaces a caller-visible success", async () => {
    vi.useFakeTimers();
    try {
      const rig = setup();
      await seedIdentities(rig);
      rig.setHolding(true);
      const outcome = makeOutcome({ session_id: "ld6-deadline-session" });
      const args = { ...outcome, identity_id: rig.signer.storedIdentity.identity_id };

      const pending = callToolSafe(rig.commit, args);
      await flush();
      expect(rig.pendingCount()).toBe(1); // parked on the audit write

      await vi.advanceTimersByTimeAsync(ADMISSION_DEADLINE_MS);
      const result = await pending;
      // The caller's own deadline elapsed while the audit write was still
      // held: it must NEVER be told success (a bare bridge_commitment_id
      // with no error), whatever the eventually-settling background
      // write/audit later does.
      expect(result.ok).toBe(false);

      // Release the parked write so the background fn() can settle and
      // does not leak a dangling timer/handle into later tests.
      rig.releaseNext();
      await flush();
    } finally {
      vi.useRealTimers();
    }
  });
});

// ─── Reputation (bridge_attest) ─────────────────────────────────────────

describe("LD6 BP-DEADLINE-03: bridge_attest durable admission-completion oracle", () => {
  function setup(faultNamespace = "_audit") {
    const { storage, queueRejections, pendingCount, releaseNext } = makeFaultableStorage(faultNamespace);
    const masterKey = generateRandomKey();
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const identityManager = new IdentityManager(storage, masterKey);
    const signer = createIdentity("ld6-attest-signer", identityEncKey, "recovery-key");
    const counterparty = createIdentity("ld6-attest-counterparty", identityEncKey, "recovery-key");
    const reputationStore = new ReputationStore(storage, masterKey);
    const auditLog = new AuditLog(storage, masterKey);
    const { tools: bridgeTools } = createBridgeTools(
      storage,
      masterKey,
      identityManager,
      auditLog,
      reputationStore,
      undefined,
      { maxBridgeCommitments: 1000, maxBridgeCommitmentsPerOrigin: 1000, maxPendingAdmissionWaiters: 50 }
    );
    return {
      storage,
      masterKey,
      identityManager,
      signer,
      counterparty,
      reputationStore,
      commit: findTool(bridgeTools, "bridge_commit"),
      attest: findTool(bridgeTools, "bridge_attest"),
      queueRejections,
      pendingCount,
      releaseNext,
    };
  }

  async function seedAndCommit(rig: ReturnType<typeof setup>): Promise<{ commitmentId: string; outcome: ConcordiaOutcome }> {
    await rig.identityManager.save(rig.signer.storedIdentity);
    await rig.identityManager.save(rig.counterparty.storedIdentity);
    await rig.identityManager.setPrimary(rig.signer.storedIdentity.identity_id);
    const outcome = makeOutcome({
      proposer_did: rig.signer.publicIdentity.did,
      acceptor_did: rig.counterparty.publicIdentity.did,
    });
    const committed = await callToolSafe(rig.commit, {
      ...outcome,
      identity_id: rig.signer.storedIdentity.identity_id,
    });
    if (!committed.ok) throw new Error("setup: bridge_commit failed");
    return { commitmentId: committed.value.bridge_commitment_id as string, outcome };
  }

  it("I1/I4: an audit-append failure on bridge_attest fails closed, and a retry reconciles (self-heal, no double-count)", async () => {
    const rig = setup();
    const { commitmentId, outcome } = await seedAndCommit(rig);
    const attestationId = deriveReputationAttestationId(
      outcome.session_id,
      rig.signer.publicIdentity.did,
      rig.counterparty.publicIdentity.did,
      "concordia-bridge"
    );

    rig.queueRejections(1);
    const first = await callToolSafe(rig.attest, {
      bridge_commitment_id: commitmentId,
      outcome_result: "completed",
      identity_id: rig.signer.storedIdentity.identity_id,
    });
    expect(first.ok).toBe(false);

    const commitIdsAtBoundary = await durableRecordIds(rig.storage, "_reputation");
    const auditIdsAtBoundary = await auditSuccessIds(
      rig.storage,
      rig.masterKey,
      "bridge_attest",
      "attestation_id"
    );
    expect(commitIdsAtBoundary.has(attestationId)).toBe(true);
    expect(auditIdsAtBoundary.has(attestationId)).toBe(false);

    const second = await callToolSafe(rig.attest, {
      bridge_commitment_id: commitmentId,
      outcome_result: "completed",
      identity_id: rig.signer.storedIdentity.identity_id,
    });
    expect(second.ok).toBe(true);
    if (second.ok) {
      expect(second.value.already_attested).toBe(true);
      expect(second.value.attestation_id).toBe(attestationId);
    }

    const commitIdsAfter = await durableRecordIds(rig.storage, "_reputation");
    const auditIdsAfter = await auditSuccessIds(
      rig.storage,
      rig.masterKey,
      "bridge_attest",
      "attestation_id"
    );
    expect(commitIdsAfter).toEqual(new Set([attestationId]));
    expect(auditIdsAfter).toEqual(new Set([attestationId]));
    expect((await rig.storage.list("_reputation")).length).toBe(1);
  });

  it("I2/I3: repeated bridge_attest calls for the SAME commitment collapse to exactly ONE attestation", async () => {
    const rig = setup();
    const { commitmentId } = await seedAndCommit(rig);

    for (let i = 0; i < 4; i++) {
      const result = await callToolSafe(rig.attest, {
        bridge_commitment_id: commitmentId,
        outcome_result: "completed",
        identity_id: rig.signer.storedIdentity.identity_id,
      });
      expect(result.ok).toBe(true);
    }

    expect((await rig.storage.list("_reputation")).length).toBe(1);
  });

  it("reconcile audit describes the STORED sovereignty tier, not the retry's freshly resolved tier", async () => {
    const rig = setup();
    const { commitmentId, outcome } = await seedAndCommit(rig);
    const identityEncryptionKey = derivePurposeKey(
      rig.masterKey,
      "identity-encryption"
    );

    // Pre-seed the logical record with a tier different from bridge_attest's
    // current local-signer resolution (self-attested). This models a record
    // written under an older tier decision or by an earlier internal caller.
    // bridge_attest must reconcile that durable record, not rewrite it.
    const builtMetrics = buildBridgeAttestationMetrics(outcome, undefined);
    const stored = await rig.reputationStore.record(
      outcome.session_id,
      rig.counterparty.publicIdentity.did,
      {
        type: "negotiation",
        result: "completed",
        metrics: builtMetrics.metrics,
        metric_policy: builtMetrics.policy,
      },
      "concordia-bridge",
      rig.signer.storedIdentity,
      identityEncryptionKey,
      undefined,
      "unverified"
    );

    const result = await callToolSafe(rig.attest, {
      bridge_commitment_id: commitmentId,
      outcome_result: "completed",
      identity_id: rig.signer.storedIdentity.identity_id,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.already_attested).toBe(true);
      expect(result.value.attestation_id).toBe(
        stored.attestation.attestation_id
      );
    }

    const freshAuditLog = new AuditLog(rig.storage, rig.masterKey);
    const { entries } = await freshAuditLog.query({
      operation_type: "bridge_attest",
      limit: 100,
    });
    const success = entries.find(
      (entry) =>
        entry.result === "success" &&
        entry.details?.["attestation_id"] ===
          stored.attestation.attestation_id
    );
    expect(success?.details?.["sovereignty_tier"]).toBe("unverified");
    expect((await rig.storage.list("_reputation")).length).toBe(1);
  });
});

// ─── Reputation (reputation_record, the general tool) ──────────────────

describe("LD6 BP-DEADLINE-03: reputation_record durable admission-completion oracle", () => {
  function setup(faultNamespace = "_audit") {
    const { storage, queueRejections } = makeFaultableStorage(faultNamespace);
    const masterKey = generateRandomKey();
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const identityManager = new IdentityManager(storage, masterKey);
    const signer = createIdentity("ld6-record-signer", identityEncKey, "recovery-key");
    const auditLog = new AuditLog(storage, masterKey);
    const { tools } = createReputationTools(storage, masterKey, identityManager, auditLog);
    return {
      storage,
      masterKey,
      identityManager,
      signer,
      record: findTool(tools, "reputation_record"),
      queueRejections,
    };
  }

  async function seedIdentity(rig: ReturnType<typeof setup>): Promise<void> {
    await rig.identityManager.save(rig.signer.storedIdentity);
    await rig.identityManager.setPrimary(rig.signer.storedIdentity.identity_id);
  }

  it("I1/I4: an audit-append failure fails the caller CLOSED, and a retry self-heals commit == audit (Erik-ratified idempotent-collapse)", async () => {
    const rig = setup();
    await seedIdentity(rig);
    const args = {
      interaction_id: "ld6-general-interaction",
      counterparty_did: "did:sanctuary:counterparty-general",
      outcome: { type: "transaction", result: "completed" },
      context: "general",
      identity_id: rig.signer.storedIdentity.identity_id,
    };
    const attestationId = deriveReputationAttestationId(
      args.interaction_id,
      rig.signer.publicIdentity.did,
      args.counterparty_did,
      args.context
    );

    rig.queueRejections(1);
    const first = await callToolSafe(rig.record, args, rig.signer.publicIdentity.did);
    expect(first.ok).toBe(false);

    const commitIdsAtBoundary = await durableRecordIds(rig.storage, "_reputation");
    const auditIdsAtBoundary = await auditSuccessIds(
      rig.storage,
      rig.masterKey,
      "reputation_record",
      "interaction_id"
    );
    expect(commitIdsAtBoundary.has(attestationId)).toBe(true);
    // Reconciled audit entries key on interaction_id (not the store key) --
    // see ReputationRecordAuditProjection; assert this exact interaction_id
    // has no success entry yet.
    expect(auditIdsAtBoundary.has(args.interaction_id)).toBe(false);

    const second = await callToolSafe(rig.record, args, rig.signer.publicIdentity.did);
    expect(second.ok).toBe(true);
    if (second.ok) {
      expect(second.value.already_committed).toBe(true);
      expect(second.value.attestation_id).toBe(attestationId);
    }

    const auditIdsAfter = await auditSuccessIds(
      rig.storage,
      rig.masterKey,
      "reputation_record",
      "interaction_id"
    );
    expect(auditIdsAfter.has(args.interaction_id)).toBe(true);
    expect((await rig.storage.list("_reputation")).length).toBe(1);
  });

  it("I2/I3: a repeated (interaction_id, participant_did, counterparty_did, context) tuple collapses to ONE record (Erik-ratified caller-semantic change, mirrors bridge_attest)", async () => {
    const rig = setup();
    await seedIdentity(rig);
    const args = {
      interaction_id: "ld6-collapse-interaction",
      counterparty_did: "did:sanctuary:counterparty-collapse",
      outcome: { type: "transaction", result: "completed" },
      context: "general",
      identity_id: rig.signer.storedIdentity.identity_id,
    };

    for (let i = 0; i < 4; i++) {
      const result = await callToolSafe(rig.record, args, rig.signer.publicIdentity.did);
      expect(result.ok).toBe(true);
    }

    expect((await rig.storage.list("_reputation")).length).toBe(1);
  });

  it("fix-round FIX 2: reconcile audit pins the STORED outcome, never a divergent retry's incoming outcome", async () => {
    const rig = setup();
    await seedIdentity(rig);
    const baseArgs = {
      interaction_id: "ld6-reconcile-divergent",
      counterparty_did: "did:sanctuary:counterparty-divergent",
      context: "general",
      identity_id: rig.signer.storedIdentity.identity_id,
    };
    const first = await callToolSafe(
      rig.record,
      { ...baseArgs, outcome: { type: "transaction", result: "completed" } },
      rig.signer.publicIdentity.did
    );
    expect(first.ok).toBe(true);

    // Retry the SAME (interaction_id, participant_did, counterparty_did,
    // context) tuple with a DIFFERENT incoming outcome -- the existence
    // guard collapses this to the already-committed record (I2/I3). Before
    // the fix, the reconcile audit closure read the OUTER closure's
    // `outcome`/`tierMeta` (this call's own "disputed" input) instead of
    // the projection's stored values, so caller-result (stored, via
    // `already_committed`), durable record (stored), and audit entry
    // (incoming) disagreed. The fix pins the audit to `projection`, sourced
    // from `existing.attestation.data` in reputation-store.ts.
    const second = await callToolSafe(
      rig.record,
      { ...baseArgs, outcome: { type: "transaction", result: "disputed" } },
      rig.signer.publicIdentity.did
    );
    expect(second.ok).toBe(true);
    if (second.ok) {
      expect(second.value.already_committed).toBe(true);
    }

    const freshAuditLog = new AuditLog(rig.storage, rig.masterKey);
    const { entries } = await freshAuditLog.query({
      operation_type: "reputation_record",
      limit: 100,
    });
    const successEntries = entries.filter(
      (e) => e.result === "success" && e.details?.["interaction_id"] === baseArgs.interaction_id
    );
    // At least the original write's audit, possibly plus the reconcile
    // audit -- either way every success entry for this interaction_id must
    // describe the STORED ("completed") outcome, never "disputed".
    expect(successEntries.length).toBeGreaterThan(0);
    for (const entry of successEntries) {
      expect(entry.details?.["outcome_result"]).toBe("completed");
    }

    // Still exactly one durable record -- the divergent retry never mints
    // a second attestation, it only reconciles the audit for the first.
    expect((await rig.storage.list("_reputation")).length).toBe(1);
  });
});

// ─── Sentinel (fix-round: NO stable id in production, no crash-window ──
// ─── self-heal -- honest accepted residual, V2-5 awaited-just-after) ────

describe("LD6 BP-DEADLINE-03: sentinel FINDING_EMITTED durable admission-completion oracle", () => {
  class StubSentinel extends Sentinel {
    readonly sentinelId: string;
    readonly description = "LD6 oracle fixture sentinel.";
    next: SentinelFinding[] = [];
    constructor(sentinelId = "ld6-stub") {
      super();
      this.sentinelId = sentinelId;
    }
    async evaluate(): Promise<SentinelFinding[]> {
      return this.next;
    }
  }

  function setup(faultNamespace = "_audit") {
    const { storage, queueRejections } = makeFaultableStorage(faultNamespace);
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const findingStore = new SentinelFindingStore({
      storage,
      masterKey,
      fortressId: "ld6-fortress",
      maxTrackedFindings: 1000,
      maxFindingsPerOrigin: 1000,
      maxPendingAdmissionWaiters: 50,
    });
    const registry = new SentinelRegistry();
    const stub = new StubSentinel();
    registry.register({ sentinelId: stub.sentinelId, description: stub.description, factory: () => stub });
    const dispatcher = new SentinelDispatcher({
      registry,
      findingStore,
      auditLog,
      fortressId: "ld6-fortress",
      identityId: "ld6-operator",
      tickIntervalMs: 0,
    });
    return { storage, masterKey, findingStore, dispatcher, stub, auditLog, queueRejections };
  }

  it("I1 (V2-5 sentinel exception, HONEST bound): an audit-append failure surfaces to tick()'s per-sentinel error path, the finding is ALREADY durably persisted, but -- unlike bridge/reputation -- the crash-window orphan is NEVER self-healed: production sentinels emit finding_id: \"\", so a later tick mints a DIFFERENT random id and never reconciles the first", async () => {
    const rig = setup();
    await rig.dispatcher.subscribeSentinel(rig.stub.sentinelId);
    // Drain the SUBSCRIBED audit append (fire-and-forget `append()`, not
    // `appendCritical`) before arming the fault queue below, so the fault
    // targets FINDING_EMITTED's write, not an unrelated pending write.
    await rig.auditLog.flush();

    // Matches the REAL production shape: every shipped sentinel (see
    // src/sentinel/sentinels/*.ts -- egress-volume-watcher.ts,
    // credential-usage-watcher.ts, cross-agent-chatter-watcher.ts, etc.)
    // emits `finding_id: ""` and lets sentinel-dispatcher.ts's routeFinding
    // mint a fresh `randomUUID()` per finding. A hardcoded caller-supplied
    // id here would test a fiction no production sentinel produces -- the
    // prior cut of this oracle did exactly that and masked the gap Codex
    // found (finding_id: "" never gives overwrite-in-place self-heal).
    const makeFinding = (): SentinelFinding => ({
      finding_id: "",
      sentinel_id: rig.stub.sentinelId,
      severity: "alert",
      summary: "LD6 oracle finding",
      details: {},
      observed_at: "2026-08-11T00:00:00.000Z",
      evidence_audit_ids: [],
      fortress_id: "",
    });
    rig.stub.next = [makeFinding()];

    // The audit write is awaited-just-after saveFinding (NOT folded into
    // its lock, V2-5) -- a rejection propagates out of routeFinding into
    // tick()'s per-sentinel try/catch, which logs evaluation_failed rather
    // than throwing out of tick() itself.
    rig.queueRejections(1);
    const firstTick = await rig.dispatcher.tick();
    // The failed audit means this finding is not reported as emitted THIS
    // tick (routeFinding never returned).
    expect(firstTick.length).toBe(0);

    // I4: the finding is nonetheless durably persisted -- saveFinding
    // settled BEFORE the audit append was even attempted. The fixture
    // cannot supply the id (production doesn't either), so capture the
    // RANDOM id the dispatcher minted for it from durable storage.
    const afterFirst = await rig.storage.list(SENTINEL_FINDING_NAMESPACE);
    expect(afterFirst.length).toBe(1);
    const firstId = afterFirst[0]!.key.slice(SENTINEL_FINDING_KEY_PREFIX.length);
    const stored = await rig.findingStore.loadFinding(firstId);
    expect(stored).not.toBeNull();

    const auditIdsAtBoundary = await auditSuccessIds(
      rig.storage,
      rig.masterKey,
      SENTINEL_AUDIT_OPS.FINDING_EMITTED,
      "finding_id"
    );
    expect(auditIdsAtBoundary.has(firstId)).toBe(false);

    // HONEST BOUND: a later tick re-evaluates from scratch (the real
    // production shape -- a sentinel does not resupply the failed attempt's
    // id, it has none to resupply) and gets its OWN fresh finding_id: "" ->
    // a NEW random id, distinct from firstId. No caller-supplied identifying
    // tuple exists for sentinel findings to retry against, unlike
    // bridge_commit/bridge_attest/reputation_record's content-derived ids
    // (V2-3), so this does NOT collapse onto the first tick's key.
    rig.stub.next = [makeFinding()];
    const secondTick = await rig.dispatcher.tick();
    expect(secondTick.length).toBe(1);
    const secondId = secondTick[0]!.finding_id;
    expect(secondId).not.toBe(firstId);

    const auditIdsAfter = await auditSuccessIds(
      rig.storage,
      rig.masterKey,
      SENTINEL_AUDIT_OPS.FINDING_EMITTED,
      "finding_id"
    );
    // The second tick's OWN finding gets its OWN successful audit...
    expect(auditIdsAfter.has(secondId)).toBe(true);
    // ...but the first tick's orphan is STILL unaudited. No self-heal
    // occurred for it, and none ever will -- this is the accepted,
    // disclosed residual (weaker than bridge/reputation's exactly-one-
    // record self-heal), not a fabricated stronger guarantee.
    expect(auditIdsAfter.has(firstId)).toBe(false);

    // Two DISTINCT durable records now exist: the crash-window orphan from
    // tick 1 (retained, not silently dropped -- an operator can still find
    // it via finding-store inspection) plus tick 2's own finding. If a
    // future change made sentinel ids stable/content-derived (closing this
    // residual for real), this assertion is exactly what would need to
    // flip alongside it -- it is not an incidental count.
    const finalEntries = await rig.storage.list(SENTINEL_FINDING_NAMESPACE);
    expect(finalEntries.length).toBe(2);
  });
});
