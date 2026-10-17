// Two audit-log steps are sequences of several storage writes: a rotation's anchor and the deletes
// below it, and the first signed checkpoint's arm records and its record. When a crash or a refused
// write stops one of them part way, the next load must open the store as an interrupted step and
// finish it, never flag it as tampered, and the retry must work from what is on disk, so a process
// that reopens the store (not only the one that saw the refusal) completes the step. These tests
// refuse named writes inside each sequence through a filesystem store, reopen with a plain
// FilesystemStorage, and prove the store loads with no finding and that the step completes. The
// rules that fail closed on deletion-shaped states are unchanged: a zero-sequence head anchor
// replayed over an established store is still rejected, a stretch below a rotation anchor is
// accepted only when every entry's recomputed hash chains to the anchor, and a signed checkpoint
// is never written without its latch. Private defect id: audit-log-torn-multi-write-sequences-01.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  AuditLog,
  probeAuditHeadAnchor,
  type AuditEntryInput,
  type PersistedAuditEnvelopeV2,
} from "../../src/operational/audit-log.js";
import {
  canonicalJson,
  checkpointSigningBytes,
  computeAuditEntryHash,
  type AuditCheckpointRecord,
  type AuditCheckpointSigningPayload,
} from "../../src/audit/chain.js";
import { bytesToString, stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { hmacSha256 } from "../../src/core/hashing.js";
import { createIdentity, sign as identitySign } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

// Storage namespaces and control keys, as the audit log lays them out on disk (AUDIT_NAMESPACE,
// AUDIT_CHECKPOINT_NAMESPACE, AUDIT_META_NAMESPACE in audit-log.ts; AUDIT_HEAD_ANCHOR_KEY,
// AUDIT_SIGNING_LATCH_V2_KEY in audit/checkpoint-shape.ts).
const ENTRIES = "_audit";
const CONTROL = "_audit_checkpoints";
const META = "_meta";
const HEAD_ANCHOR = "__head_anchor";
const SIGNING_LATCH = "__signing_latch_v2";
const CHECKPOINT_PREFIX = "audit-checkpoint-";
// Must match AUDIT_HEAD_ANCHOR_MARKER / AUDIT_HEAD_ANCHOR_MAC_DOMAIN in audit-log.ts and the
// `audit-head-anchor` purpose label, so the replayed anchor below is one the product itself
// would have minted.
const HEAD_ANCHOR_MARKER = "__sanctuary_audit_head_anchor_v1";
const HEAD_ANCHOR_MAC_DOMAIN = "sanctuary.audit-head-anchor.v1\n";
const HEAD_ANCHOR_MAC_PURPOSE = "audit-head-anchor";
// Must match AUDIT_CHECKPOINT_OWED_KEY in audit-log.ts.
const CHECKPOINT_OWED = "audit-checkpoint-owed-v1";

type Mutation = { kind: "write" | "writeDurable" | "delete"; namespace: string; key: string };
type Refusal = (mutation: Mutation, prior: readonly Mutation[]) => boolean;

// A filesystem store that refuses the first `times` mutations for which `failWhen` returns true,
// judged against the mutations that already went through. Everything else reaches the disk, so the
// store the next reader opens is exactly the prefix the refused write cut the sequence at.
class ProbeStorage extends FilesystemStorage {
  readonly mutations: Mutation[] = [];
  refusals = 0;
  private armed: Refusal | undefined;
  private remaining = 0;

  refuse(failWhen: Refusal, times = 1): void {
    this.armed = failWhen;
    this.remaining = times;
  }

  private observe(mutation: Mutation): void {
    if (this.armed && this.remaining > 0 && this.armed(mutation, this.mutations)) {
      this.remaining -= 1;
      this.refusals += 1;
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

async function metaKeys(state: string): Promise<string[]> {
  const storage = new FilesystemStorage(state);
  return (await storage.list(META)).map((meta) => meta.key).sort();
}

/** `[from_sequence, checkpoint_sequence, unsigned]` per checkpoint record, ascending. */
async function checkpointShape(state: string): Promise<Array<[number, number, boolean]>> {
  const storage = new FilesystemStorage(state);
  const shape: Array<[number, number, boolean]> = [];
  for (const meta of await storage.list(CONTROL, CHECKPOINT_PREFIX)) {
    const raw = await storage.read(CONTROL, meta.key);
    const record = JSON.parse(bytesToString(raw!)) as AuditCheckpointRecord;
    shape.push([record.from_sequence, record.checkpoint_sequence, record.unsigned]);
  }
  return shape;
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

function signedLog(
  storage: FilesystemStorage,
  masterKey: Uint8Array,
  fixture: ReturnType<typeof checkpointSignerFixture>,
  checkpointInterval: number,
  extra: { maxEntries?: number } = {},
): AuditLog {
  return new AuditLog(storage, masterKey, {
    checkpointInterval,
    checkpointSigner: fixture.signer,
    checkpointPublicKeyResolver: () => fixture.publicKey,
    ...extra,
  });
}

function reader(state: string, masterKey: Uint8Array, publicKey?: string): AuditLog {
  return new AuditLog(new FilesystemStorage(state), masterKey, {
    ...(publicKey ? { checkpointPublicKeyResolver: () => publicKey } : {}),
  });
}

const isLatchWrite = (m: Mutation): boolean => m.namespace === CONTROL && m.key === SIGNING_LATCH;
const isCheckpointRecordWrite = (m: Mutation): boolean =>
  m.namespace === CONTROL && m.kind !== "delete" && m.key.startsWith(CHECKPOINT_PREFIX);
const isEntryDelete = (m: Mutation): boolean => m.kind === "delete" && m.namespace === ENTRIES;

describe("audit log interrupted multi-write sequences load clean and complete", () => {
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
    storage.refuse(
      (m, prior) => isEntryDelete(m) && prior.filter(isEntryDelete).length === 1,
    );
    const rotator = new AuditLog(storage, masterKey, { maxEntries });
    await rotator.appendCritical(entry("over-cap"));
    await rotator.flush();
    expect(storage.refusals).toBe(1);
    const afterCut = seedCount + 1;
    // Entries 2..11 survive under an anchor whose base is above 2.
    expect(await entrySequences(state)).toEqual(
      Array.from({ length: afterCut - 1 }, (_, i) => i + 2),
    );

    const reopened = new AuditLog(new FilesystemStorage(state), masterKey, { maxEntries });
    expect(await reopened.getIntegrityFindings()).toEqual([]);
    await reopened.appendCritical(entry("after-reopen"));
    await reopened.flush();
    const survivors = await entrySequences(state);
    expect(survivors).toHaveLength(maxEntries);
    expect(survivors.at(-1)).toBe(afterCut + 1);
    expect(await reader(state, masterKey).getIntegrityFindings()).toEqual([]);
  });

  it("a stretch below the rotation base is accepted only when each entry's recomputed hash chains to the anchor", async () => {
    // Reached through a cast: the acceptance predicate is private, and a rename breaks this test
    // loudly rather than letting it pass vacuously.
    type Internals = {
      stretchChainsToRotationBase: (
        chainedEntries: ReadonlyArray<{ envelope: PersistedAuditEnvelopeV2 }>,
        anchor: { base_sequence: number; base_prev_hash: string },
      ) => boolean;
    };
    const log = new AuditLog(new FilesystemStorage(await tempState("audit-stretch-")), generateRandomKey());
    const stretchChains = (log as unknown as Internals).stretchChainsToRotationBase.bind(log);

    const payload = toBase64url(stringToBytes("opaque"));
    const timestamp = "2026-10-17T00:00:00.000Z";
    const chain = (first: number, count: number, prevHash: string): PersistedAuditEnvelopeV2[] => {
      const out: PersistedAuditEnvelopeV2[] = [];
      let prev = prevHash;
      for (let sequence = first; sequence < first + count; sequence++) {
        const base = { sequence, prev_hash: prev, timestamp, encrypted_payload_bytes: payload };
        const entry_hash = computeAuditEntryHash({ ...base, schema_version: 2 });
        out.push({ schema_version: 2, ...base, entry_hash });
        prev = entry_hash;
      }
      return out;
    };
    // Entries 2..5 with a real chain; the anchor's base is 5 and its base hash is entry 4's.
    const genuine = chain(2, 4, "f".repeat(64));
    const anchor = { base_sequence: 5, base_prev_hash: genuine[2]!.entry_hash };
    const wrap = (envelopes: PersistedAuditEnvelopeV2[]) => envelopes.map((envelope) => ({ envelope }));
    expect(stretchChains(wrap(genuine), anchor)).toBe(true);

    // A forged stretch: the link fields are edited so the strings chain and the last below-base
    // `entry_hash` equals the anchor's base hash, but no entry's hash is the digest of its bytes.
    const forged = genuine.map((envelope, index) => ({
      ...envelope,
      encrypted_payload_bytes: toBase64url(stringToBytes(`forged-${index}`)),
    }));
    expect(stretchChains(wrap(forged), anchor)).toBe(false);

    // The base entry must itself point at the accepted stretch.
    const detachedBase = [...genuine.slice(0, 3), { ...genuine[3]!, prev_hash: "0".repeat(64) }];
    expect(stretchChains(wrap(detachedBase), anchor)).toBe(false);
  });

  it("a zero-sequence head anchor replayed over an established store with its entries deleted is rejected", async () => {
    const state = await tempState("audit-genesis-replay-");
    const masterKey = generateRandomKey();
    const writer = new AuditLog(new FilesystemStorage(state), masterKey);
    await writer.appendCritical(entry("first"));
    await writer.appendCritical(entry("second"));
    await writer.flush();
    expect(await metaKeys(state)).toContain("audit-head-anchor-established-v1");

    // The replay: every entry deleted, a correctly MAC'd anchor at the genesis floor put in the
    // head anchor's place, the established marker left behind.
    const storage = new FilesystemStorage(state);
    for (const meta of await storage.list(ENTRIES)) await storage.delete(ENTRIES, meta.key);
    const data = { highest_sequence: 0, head_hash: "GENESIS" };
    const macKey = derivePurposeKey(masterKey, HEAD_ANCHOR_MAC_PURPOSE);
    const mac = toBase64url(
      hmacSha256(macKey, stringToBytes(HEAD_ANCHOR_MAC_DOMAIN + canonicalJson(data))),
    );
    await storage.write(
      CONTROL,
      HEAD_ANCHOR,
      stringToBytes(JSON.stringify({ [HEAD_ANCHOR_MARKER]: true, data, mac })),
    );

    const findings = await reader(state, masterKey).getIntegrityFindings();
    expect(findings.map((finding) => finding.kind)).toContain("tail_anchor_invalid");
    expect(await probeAuditHeadAnchor(new FilesystemStorage(state), masterKey)).toEqual({
      status: "tampered",
    });
  });

  it("signing head written, latch refused: no checkpoint record is written, the store loads clean and the same writer's next interval arms", async () => {
    const state = await tempState("audit-torn-signing-arm-");
    const masterKey = generateRandomKey();
    const fixture = checkpointSignerFixture(masterKey);
    const storage = new ProbeStorage(state);
    storage.refuse(isLatchWrite);
    const writer = signedLog(storage, masterKey, fixture, 1);
    // The append itself drives the interval checkpoint; no flush here, since a flush is the
    // shutdown retry and would complete the arm before the torn prefix is inspected.
    await writer.appendCritical(entry("first"));
    expect(storage.refusals).toBe(1);
    expect(await entrySequences(state)).toEqual([1]);
    expect(await checkpointShape(state)).toEqual([]);
    expect(await controlKeys(state)).not.toContain(SIGNING_LATCH);
    expect(await metaKeys(state)).toContain(CHECKPOINT_OWED);
    expect(await reader(state, masterKey, fixture.publicKey).getIntegrityFindings()).toEqual([]);

    await writer.appendCritical(entry("second"));
    expect(await controlKeys(state)).toContain(SIGNING_LATCH);
    expect(await checkpointShape(state)).toEqual([[1, 2, false]]);
    expect(await metaKeys(state)).not.toContain(CHECKPOINT_OWED);
    expect(await reader(state, masterKey, fixture.publicKey).getIntegrityFindings()).toEqual([]);
  });

  it("latch refused, then a different process reopens the store: its retry re-runs the arm from disk and never writes a signed record without the latch", async () => {
    const state = await tempState("audit-torn-signing-reopen-");
    const masterKey = generateRandomKey();
    const fixture = checkpointSignerFixture(masterKey);
    const storage = new ProbeStorage(state);
    storage.refuse(isLatchWrite);
    const crashed = signedLog(storage, masterKey, fixture, 1);
    await crashed.appendCritical(entry("first"));
    expect(storage.refusals).toBe(1);
    expect(await checkpointShape(state)).toEqual([]);

    // A fresh instance over a plain filesystem store: it knows nothing of the refusal and holds no
    // queue; the signing head it finds on disk has no committed tip, so it arms.
    const reopened = signedLog(new FilesystemStorage(state), masterKey, fixture, 1);
    expect(await reopened.getIntegrityFindings()).toEqual([]);
    await reopened.appendCritical(entry("second"));
    expect(await controlKeys(state)).toContain(SIGNING_LATCH);
    expect(await checkpointShape(state)).toEqual([[1, 2, false]]);
    expect(await reader(state, masterKey, fixture.publicKey).getIntegrityFindings()).toEqual([]);
  });

  it("a process that dies after the aborted checkpoint's append was acknowledged leaves a durable owed marker, and the next process retries at its first critical append", async () => {
    const state = await tempState("audit-torn-owed-");
    const masterKey = generateRandomKey();
    const fixture = checkpointSignerFixture(masterKey);
    const interval = 3;
    const storage = new ProbeStorage(state);
    storage.refuse(isLatchWrite);
    const crashed = signedLog(storage, masterKey, fixture, interval);
    for (let i = 1; i <= interval; i++) await crashed.appendCritical(entry(`before-${i}`));
    // The third append met the interval; its arm was refused and nothing more happens in this
    // process (no flush: the process is gone).
    expect(storage.refusals).toBe(1);
    expect(await checkpointShape(state)).toEqual([]);
    expect(await metaKeys(state)).toContain(CHECKPOINT_OWED);

    const next = signedLog(new FilesystemStorage(state), masterKey, fixture, interval);
    await next.appendCritical(entry("after-restart"));
    // One critical append, not a whole interval: the owed marker primed the retry.
    expect(await checkpointShape(state)).toEqual([[1, interval + 1, false]]);
    expect(await metaKeys(state)).not.toContain(CHECKPOINT_OWED);
    expect(await reader(state, masterKey, fixture.publicKey).getIntegrityFindings()).toEqual([]);
  });

  it("rotation that pruned past an aborted checkpoint: the retry covers from the lowest surviving entry instead of skipping forever", async () => {
    const state = await tempState("audit-torn-rotation-checkpoint-");
    const masterKey = generateRandomKey();
    const fixture = checkpointSignerFixture(masterKey);
    const storage = new ProbeStorage(state);
    storage.refuse(isLatchWrite, 2);
    const writer = signedLog(storage, masterKey, fixture, 1, { maxEntries: 1 });
    await writer.appendCritical(entry("first"));
    await writer.appendCritical(entry("second"));
    await writer.appendCritical(entry("third"));
    await writer.flush();
    expect(storage.refusals).toBe(2);
    // The third append's interval ran before its own rotation pruned entry 2, so the lagging
    // checkpoint starts at the lowest survivor of that moment (2, entry 1 already pruned) rather
    // than at the never-coverable sequence 1; rotation then keeps only the newest entry.
    expect(await entrySequences(state)).toEqual([3]);
    expect(await checkpointShape(state)).toEqual([[2, 3, false]]);
    expect(await reader(state, masterKey, fixture.publicKey).getIntegrityFindings()).toEqual([]);
  });

  it("latch armed, the checkpoint record itself refused: the store loads clean and the next checkpoint completes under the existing latch", async () => {
    const state = await tempState("audit-torn-record-refused-");
    const masterKey = generateRandomKey();
    const fixture = checkpointSignerFixture(masterKey);
    const storage = new ProbeStorage(state);
    storage.refuse(isCheckpointRecordWrite);
    const writer = signedLog(storage, masterKey, fixture, 1);
    // A refused record write is a persistence failure the append reports; the entry is durable.
    await expect(writer.appendCritical(entry("first"))).rejects.toThrow();
    expect(storage.refusals).toBe(1);
    expect(await entrySequences(state)).toEqual([1]);
    expect(await controlKeys(state)).toContain(SIGNING_LATCH);
    expect(await checkpointShape(state)).toEqual([]);
    expect(await reader(state, masterKey, fixture.publicKey).getIntegrityFindings()).toEqual([]);

    const reopened = signedLog(new FilesystemStorage(state), masterKey, fixture, 1);
    await reopened.appendCritical(entry("second"));
    expect(await checkpointShape(state)).toEqual([[1, 2, false]]);
    expect(await reader(state, masterKey, fixture.publicKey).getIntegrityFindings()).toEqual([]);
  });
});
