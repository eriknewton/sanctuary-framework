// Three audit-log steps are sequences of several storage writes: the first entry ever written and
// its head anchor, a rotation's anchor and the deletes below it, and the first signed checkpoint's
// arm records and its record. When a crash or a refused write stops one of them part way, the next
// load must open the store as an interrupted step and finish it, never flag it as tampered. These
// tests refuse one named write inside each sequence through a filesystem store, reopen the store
// with a plain FilesystemStorage, and prove it loads with no finding and that the step completes on
// the following append. The rules that fail closed on the deletion-shaped states are unchanged; the
// writer no longer produces those states. Private defect id:
// audit-log-torn-multi-write-sequences-01.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  AuditLog,
  type AuditEntryInput,
  type PersistedAuditEnvelopeV2,
} from "../../src/operational/audit-log.js";
import {
  checkpointSigningBytes,
  type AuditCheckpointRecord,
  type AuditCheckpointSigningPayload,
} from "../../src/audit/chain.js";
import { bytesToString, toBase64url } from "../../src/core/encoding.js";
import { createIdentity, sign as identitySign } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

// Storage namespaces and control keys, as the audit log lays them out on disk (AUDIT_NAMESPACE,
// AUDIT_CHECKPOINT_NAMESPACE in audit-log.ts; AUDIT_HEAD_ANCHOR_KEY, AUDIT_SIGNING_LATCH_V2_KEY in
// audit/checkpoint-shape.ts).
const ENTRIES = "_audit";
const CONTROL = "_audit_checkpoints";
const HEAD_ANCHOR = "__head_anchor";
const SIGNING_LATCH = "__signing_latch_v2";

type Mutation = { kind: "write" | "writeDurable" | "delete"; namespace: string; key: string };

// A filesystem store that refuses ONE mutation: the first one for which `failWhen` returns true,
// judged against the mutations that already went through. Everything else reaches the disk, so the
// store the next reader opens is exactly the prefix the refused write cut the sequence at.
class ProbeStorage extends FilesystemStorage {
  readonly mutations: Mutation[] = [];
  private armed: ((mutation: Mutation, prior: readonly Mutation[]) => boolean) | undefined;
  refusedOnce = false;

  refuseFirst(failWhen: (mutation: Mutation, prior: readonly Mutation[]) => boolean): void {
    this.armed = failWhen;
  }

  private observe(mutation: Mutation): void {
    if (this.armed && !this.refusedOnce && this.armed(mutation, this.mutations)) {
      this.refusedOnce = true;
      throw new Error(`probe refused ${mutation.kind} ${mutation.namespace}/${mutation.key}`);
    }
    this.mutations.push(mutation);
  }

  override async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    this.observe({ kind: "write", namespace, key });
    return super.write(namespace, key, data);
  }

  override async writeDurable(namespace: string, key: string, data: Uint8Array): Promise<void> {
    this.observe({ kind: "writeDurable", namespace, key });
    return super.writeDurable(namespace, key, data);
  }

  override async delete(namespace: string, key: string): Promise<boolean> {
    this.observe({ kind: "delete", namespace, key });
    return super.delete(namespace, key);
  }
}

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0)) await cleanup();
});

async function tempState(prefix: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), prefix));
  cleanups.push(() => rm(root, { recursive: true, force: true }));
  return join(root, "state");
}

function entry(operation: string): AuditEntryInput {
  return {
    layer: "l1",
    operation,
    identity_id: "interrupted-sequence-probe",
    result: "success",
    details: {},
  };
}

async function entrySequences(state: string): Promise<number[]> {
  const storage = new FilesystemStorage(state);
  const sequences: number[] = [];
  for (const meta of await storage.list(ENTRIES, "entry-")) {
    const raw = await storage.read(ENTRIES, meta.key);
    const envelope = JSON.parse(bytesToString(raw!)) as PersistedAuditEnvelopeV2;
    sequences.push(envelope.sequence);
  }
  return sequences.sort((a, b) => a - b);
}

async function controlKeys(state: string): Promise<string[]> {
  const storage = new FilesystemStorage(state);
  return (await storage.list(CONTROL)).map((meta) => meta.key).sort();
}

async function checkpointRecords(state: string): Promise<AuditCheckpointRecord[]> {
  const storage = new FilesystemStorage(state);
  const records: AuditCheckpointRecord[] = [];
  for (const meta of await storage.list(CONTROL, "audit-checkpoint-")) {
    const raw = await storage.read(CONTROL, meta.key);
    records.push(JSON.parse(bytesToString(raw!)) as AuditCheckpointRecord);
  }
  return records;
}

function checkpointSignerFixture(masterKey: Uint8Array): {
  publicKey: string;
  signer: (payload: AuditCheckpointSigningPayload) => Promise<{
    signer_kid: string;
    signature: string;
    public_key: string;
  }>;
} {
  const identityKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("checkpoint-signer", identityKey, "recovery-key");
  return {
    publicKey: storedIdentity.public_key,
    signer: async (payload) => ({
      signer_kid: storedIdentity.identity_id,
      signature: toBase64url(
        identitySign(checkpointSigningBytes(payload), storedIdentity.encrypted_private_key, identityKey),
      ),
      public_key: storedIdentity.public_key,
    }),
  };
}

const isHeadAnchor = (m: Mutation): boolean => m.namespace === CONTROL && m.key === HEAD_ANCHOR;
const isEntryWrite = (m: Mutation): boolean =>
  m.namespace === ENTRIES && m.kind !== "delete" && m.key.startsWith("entry-");

describe("audit log interrupted multi-write sequences load clean and complete", () => {
  it("first entry written, its head anchor refused: the next load accepts the store and the next append anchors it", async () => {
    const state = await tempState("audit-torn-first-entry-");
    const masterKey = generateRandomKey();
    const storage = new ProbeStorage(state);
    // The head-anchor write that FOLLOWS the first entry is the one refused; an anchor written
    // before any entry (the pre-anchor) is allowed through.
    storage.refuseFirst((m, prior) => isHeadAnchor(m) && prior.some(isEntryWrite));
    const writer = new AuditLog(storage, masterKey);
    await expect(writer.appendCritical(entry("first"))).rejects.toThrow();
    expect(storage.refusedOnce).toBe(true);
    expect(await entrySequences(state)).toEqual([1]);

    const reader = new AuditLog(new FilesystemStorage(state), masterKey);
    expect(await reader.getIntegrityFindings()).toEqual([]);
    await reader.appendCritical(entry("second"));
    expect(await entrySequences(state)).toEqual([1, 2]);
    expect(await controlKeys(state)).toContain(HEAD_ANCHOR);

    const verifier = new AuditLog(new FilesystemStorage(state), masterKey);
    expect(await verifier.getIntegrityFindings()).toEqual([]);
  });

  it("pre-anchor refused before the first entry: nothing is written and the store stays fresh", async () => {
    const state = await tempState("audit-torn-pre-anchor-");
    const masterKey = generateRandomKey();
    const storage = new ProbeStorage(state);
    storage.refuseFirst(isHeadAnchor);
    const writer = new AuditLog(storage, masterKey);
    await expect(writer.appendCritical(entry("first"))).rejects.toThrow();
    expect(await entrySequences(state)).toEqual([]);

    const reader = new AuditLog(new FilesystemStorage(state), masterKey);
    expect(await reader.getIntegrityFindings()).toEqual([]);
    await reader.appendCritical(entry("second"));
    expect(await entrySequences(state)).toEqual([1]);
  });

  it("rotation anchor written, a later delete refused: the next load accepts the chained stretch and the next append finishes the prune", async () => {
    const state = await tempState("audit-torn-rotation-");
    const masterKey = generateRandomKey();
    const seeded = new AuditLog(new FilesystemStorage(state), masterKey);
    const seedCount = 10;
    for (let i = 1; i <= seedCount; i++) await seeded.appendCritical(entry(`seed-${i}`));
    await seeded.flush();

    // A cap below the seeded count makes the next append's rotation cut several entries at once;
    // the SECOND delete is refused, so one pruned entry is gone and the rest survive below the
    // anchored base.
    const maxEntries = 5;
    const storage = new ProbeStorage(state);
    storage.refuseFirst(
      (m, prior) =>
        m.kind === "delete" &&
        m.namespace === ENTRIES &&
        prior.filter((p) => p.kind === "delete" && p.namespace === ENTRIES).length === 1,
    );
    const rotator = new AuditLog(storage, masterKey, { maxEntries });
    await rotator.appendCritical(entry("over-cap"));
    await rotator.flush();
    expect(storage.refusedOnce).toBe(true);
    const afterCut = seedCount + 1;
    // Entries 2..11 survive under an anchor whose base is above 2.
    expect(await entrySequences(state)).toEqual(
      Array.from({ length: afterCut - 1 }, (_, i) => i + 2),
    );

    const reader = new AuditLog(new FilesystemStorage(state), masterKey, { maxEntries });
    expect(await reader.getIntegrityFindings()).toEqual([]);
    await reader.appendCritical(entry("after-reopen"));
    await reader.flush();
    const survivors = await entrySequences(state);
    expect(survivors).toHaveLength(maxEntries);
    expect(survivors.at(-1)).toBe(afterCut + 1);

    const verifier = new AuditLog(new FilesystemStorage(state), masterKey, { maxEntries });
    expect(await verifier.getIntegrityFindings()).toEqual([]);
  });

  it("signing head written, latch refused: no checkpoint record is written, the store loads clean and the next interval arms", async () => {
    const state = await tempState("audit-torn-signing-arm-");
    const masterKey = generateRandomKey();
    const { publicKey, signer } = checkpointSignerFixture(masterKey);
    const storage = new ProbeStorage(state);
    storage.refuseFirst((m) => m.namespace === CONTROL && m.key === SIGNING_LATCH);
    const writer = new AuditLog(storage, masterKey, {
      checkpointInterval: 1,
      checkpointSigner: signer,
      checkpointPublicKeyResolver: () => publicKey,
    });
    // The append itself drives the interval checkpoint; no flush here, since a flush is the
    // shutdown retry and would complete the arm before the torn prefix is inspected.
    await writer.appendCritical(entry("first"));
    expect(storage.refusedOnce).toBe(true);
    expect(await entrySequences(state)).toEqual([1]);
    expect(await checkpointRecords(state)).toEqual([]);
    expect(await controlKeys(state)).not.toContain(SIGNING_LATCH);

    const reader = new AuditLog(new FilesystemStorage(state), masterKey, {
      checkpointPublicKeyResolver: () => publicKey,
    });
    expect(await reader.getIntegrityFindings()).toEqual([]);

    // The next critical interval on the same writer retries the whole checkpoint: arm, then sign.
    await writer.appendCritical(entry("second"));
    await writer.flush();
    expect(await controlKeys(state)).toContain(SIGNING_LATCH);
    const records = await checkpointRecords(state);
    expect(records.map((r) => [r.from_sequence, r.checkpoint_sequence, r.unsigned])).toEqual([
      [1, 2, false],
    ]);

    const verifier = new AuditLog(new FilesystemStorage(state), masterKey, {
      checkpointPublicKeyResolver: () => publicKey,
    });
    expect(await verifier.getIntegrityFindings()).toEqual([]);
  });
});
