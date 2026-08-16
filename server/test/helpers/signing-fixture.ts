/**
 * IC-05-DG test fixture: build fortress stores with signed audit checkpoints
 * and manipulate them the way the design's threat model says an operator-uid
 * attacker can (rewrite/delete any plaintext record, induce signer failures,
 * schedule storage faults). Shared by the downgrade/deletion/enumeration/
 * fault/rotation suites so every suite drives the SAME production shapes.
 */
import { AuditLog } from "../../src/operational/audit-log.js";
import type { AuditIntegrityFinding } from "../../src/operational/audit-log.js";
import type { AuditCheckpointRecord } from "../../src/audit/chain.js";
import {
  AUDIT_SIGNING_LATCH_V2_KEY,
  AUDIT_SIGNING_HEAD_KEY,
} from "../../src/audit/checkpoint-shape.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type {
  StorageBackend,
  StorageEntryMeta,
} from "../../src/storage/interface.js";
import { encrypt } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { stringToBytes, bytesToString } from "../../src/core/encoding.js";
import { generateRandomKey } from "../../src/core/random.js";

export const CHECKPOINT_NAMESPACE = "_audit_checkpoints";
export { AUDIT_SIGNING_LATCH_V2_KEY, AUDIT_SIGNING_HEAD_KEY };

export function checkpointKey(sequence: number): string {
  // Must match the key layout in writeCheckpointRecord
  // (`${kind}-${20-digit zero-padded sequence}`).
  return `audit-checkpoint-${String(sequence).padStart(20, "0")}`;
}

export async function seedStoredIdentity(
  storage: StorageBackend,
  masterKey: Uint8Array,
  label = "fortress"
) {
  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity(
    label,
    identityEncryptionKey,
    "recovery-key"
  );
  await storage.write(
    "_identities",
    storedIdentity.identity_id,
    stringToBytes(
      JSON.stringify(
        encrypt(stringToBytes(JSON.stringify(storedIdentity)), identityEncryptionKey)
      )
    )
  );
  await storage.write(
    "_meta",
    "primary_identity_id",
    stringToBytes(JSON.stringify(storedIdentity.identity_id))
  );
  return { storedIdentity, identityEncryptionKey };
}

export async function appendCriticalEntries(
  auditLog: AuditLog,
  count: number,
  identityId: string
): Promise<void> {
  for (let i = 0; i < count; i++) {
    await auditLog.appendCritical({
      layer: "l2",
      operation: "state_write",
      identity_id: identityId,
      result: "success",
      details: { index: i },
    });
  }
  await auditLog.flush();
}

/**
 * A fortress store with `count` SIGNED audit checkpoints (checkpoint per
 * critical append), written through the production write path (bare
 * constructor + the constructor-derived fortress signer), so the latch and
 * signing head exist exactly as production would leave them.
 */
export async function buildSignedFortress(count: number) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const { storedIdentity } = await seedStoredIdentity(storage, masterKey);
  const writer = new AuditLog(storage, masterKey, { checkpointInterval: 1 });
  await appendCriticalEntries(writer, count, storedIdentity.identity_id);
  return { storage, masterKey, storedIdentity, writer };
}

export async function readCheckpointRecord(
  storage: StorageBackend,
  sequence: number
): Promise<AuditCheckpointRecord | null> {
  const raw = await storage.read(CHECKPOINT_NAMESPACE, checkpointKey(sequence));
  return raw ? (JSON.parse(bytesToString(raw)) as AuditCheckpointRecord) : null;
}

export async function writeCheckpointRecordRaw(
  storage: StorageBackend,
  sequence: number,
  record: AuditCheckpointRecord
): Promise<void> {
  await storage.write(
    CHECKPOINT_NAMESPACE,
    checkpointKey(sequence),
    stringToBytes(JSON.stringify(record))
  );
}

/** The D1 strip: rewrite a signed checkpoint to `unsigned: true`, deleting
 * every signature field, exactly as the #1243 gate's probe did. */
export async function stripCheckpoint(
  storage: StorageBackend,
  sequence: number,
  unsignedReason = "no signing identity available at checkpoint time"
): Promise<void> {
  const record = await readCheckpointRecord(storage, sequence);
  if (!record) throw new Error(`no checkpoint at sequence ${sequence}`);
  const stripped: AuditCheckpointRecord = {
    ...record,
    unsigned: true,
    signer_kid: null,
    signature: null,
    signature_algorithm: null,
    unsigned_reason: unsignedReason,
  };
  delete (stripped as { public_key?: string }).public_key;
  await writeCheckpointRecordRaw(storage, sequence, stripped);
}

export async function deleteCheckpoint(
  storage: StorageBackend,
  sequence: number
): Promise<void> {
  await storage.delete(CHECKPOINT_NAMESPACE, checkpointKey(sequence));
}

export async function deleteControlRecord(
  storage: StorageBackend,
  key: string
): Promise<void> {
  await storage.delete(CHECKPOINT_NAMESPACE, key);
}

/** Corrupt an existing identity record in place (identity material EXISTS but
 * cannot decrypt): the signer must throw `identity_undecryptable`, never
 * collapse to honest absence. */
export async function corruptIdentityRecord(
  storage: StorageBackend,
  identityId: string
): Promise<void> {
  await storage.write(
    "_identities",
    identityId,
    stringToBytes("this is not an encrypted identity payload")
  );
}

export async function deleteIdentity(
  storage: StorageBackend,
  identityId: string
): Promise<void> {
  await storage.delete("_identities", identityId);
  await storage.delete("_meta", "primary_identity_id");
}

/** Lenient full read: surfaces every finding without throwing. */
export async function lenientFindings(
  storage: StorageBackend,
  masterKey: Uint8Array
): Promise<AuditIntegrityFinding[]> {
  const reader = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
  const result = await reader.query({ limit: 1000 });
  return result.integrity_findings as AuditIntegrityFinding[];
}

/** Strict full read: resolves with null when clean, else the thrown error. */
export async function strictReadError(
  storage: StorageBackend,
  masterKey: Uint8Array
): Promise<Error & { findings?: AuditIntegrityFinding[] } | null> {
  const reader = new AuditLog(storage, masterKey);
  try {
    await reader.query({ limit: 1000 });
    return null;
  } catch (err) {
    return err as Error & { findings?: AuditIntegrityFinding[] };
  }
}

export function findingsOfKind(
  findings: readonly AuditIntegrityFinding[],
  kind: AuditIntegrityFinding["kind"]
): AuditIntegrityFinding[] {
  return findings.filter((finding) => finding.kind === kind);
}

/** Only the hard (strict-fatal) findings: everything except the warn-grade
 * latched-recovery re-emission. */
export function hardFindings(
  findings: readonly AuditIntegrityFinding[]
): AuditIntegrityFinding[] {
  return findings.filter((finding) => finding.severity !== "warn");
}

type FaultRule = {
  /** Applies to reads of this namespace/key. */
  namespace: string;
  key: string;
  error?: () => Error;
};

/**
 * Fault-injecting storage wrapper (rule-12 harness): per-key read faults
 * (enumeration starvation / unreadable control records), write-sequence
 * faults (crash-ordering matrix), and deferred write completion (the LD6
 * delayed-completion schedule).
 */
export class FaultInjectingStorage implements StorageBackend {
  readFaults: FaultRule[] = [];
  /** When set, the nth (1-based) write to a key with this prefix throws. */
  failWriteOnCall: { namespace: string; keyPrefix: string; calls: number[] } | null =
    null;
  /** When set, writes to this key are DEFERRED: the returned promise stays
   * pending until `releaseDeferredWrites()` runs (late completion). */
  deferWritesTo: { namespace: string; key: string } | null = null;
  onRead: ((namespace: string, key: string) => void) | null = null;
  private writeCalls = new Map<string, number>();
  private deferred: Array<() => Promise<void>> = [];

  constructor(private readonly inner: StorageBackend) {}

  private matchReadFault(namespace: string, key: string): FaultRule | undefined {
    return this.readFaults.find(
      (rule) => rule.namespace === namespace && rule.key === key
    );
  }

  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    this.onRead?.(namespace, key);
    const fault = this.matchReadFault(namespace, key);
    if (fault) {
      throw fault.error
        ? fault.error()
        : Object.assign(new Error(`EACCES: injected read fault on ${key}`), {
            code: "EACCES",
          });
    }
    return this.inner.read(namespace, key);
  }

  async write(
    namespace: string,
    key: string,
    data: Uint8Array
  ): Promise<void> {
    if (this.failWriteOnCall) {
      const rule = this.failWriteOnCall;
      if (namespace === rule.namespace && key.startsWith(rule.keyPrefix)) {
        const id = `${namespace}/${rule.keyPrefix}`;
        const call = (this.writeCalls.get(id) ?? 0) + 1;
        this.writeCalls.set(id, call);
        if (rule.calls.includes(call)) {
          throw new Error(`injected write fault (call ${call}) on ${key}`);
        }
      }
    }
    if (
      this.deferWritesTo &&
      namespace === this.deferWritesTo.namespace &&
      key === this.deferWritesTo.key
    ) {
      const bytes = data.slice();
      return new Promise<void>((resolve, reject) => {
        this.deferred.push(async () => {
          try {
            await this.inner.write(namespace, key, bytes);
            resolve();
          } catch (err) {
            reject(err);
          }
        });
      });
    }
    return this.inner.write(namespace, key, data);
  }

  async releaseDeferredWrites(): Promise<void> {
    const pending = this.deferred;
    this.deferred = [];
    for (const run of pending) await run();
  }

  get deferredCount(): number {
    return this.deferred.length;
  }

  async delete(
    namespace: string,
    key: string,
    secureOverwrite?: boolean
  ): Promise<boolean> {
    return this.inner.delete(namespace, key, secureOverwrite);
  }

  async list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
    return this.inner.list(namespace, prefix);
  }

  async exists(namespace: string, key: string): Promise<boolean> {
    return this.inner.exists(namespace, key);
  }

  async totalSize(): Promise<number> {
    return this.inner.totalSize();
  }

  async listNamespaces(): Promise<string[]> {
    return this.inner.listNamespaces
      ? this.inner.listNamespaces()
      : Promise.resolve([]);
  }
}
