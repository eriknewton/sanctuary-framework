/**
 * Shared test fixtures for the Governed File-Grant v1 test suite. Not a test
 * file itself (does not match `*.test.ts`), so vitest never collects it as a
 * suite.
 */

import { StateStore } from "../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FileGrantStore } from "../../src/file-grant/store.js";
import type {
  FileGrantAclResult,
  FileGrantRemoveEntryOptions,
  FsOps,
} from "../../src/file-grant/types.js";

/** A real `FileGrantStore` backed by an in-memory StateStore, for tests that want real store code without touching disk. */
export function makeFileGrantTestStore() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("operator", identityEncKey, "passphrase");
  const grantStore = new FileGrantStore(stateStore, {
    identityId: storedIdentity.identity_id,
    encryptedPrivateKey: storedIdentity.encrypted_private_key,
    identityEncryptionKey: identityEncKey,
  });
  const auditLog = new AuditLog(storage, masterKey);
  return { storage, masterKey, stateStore, grantStore, auditLog, identityId: storedIdentity.identity_id };
}

export interface FakeFsOpsOptions {
  /** If set, `place()` throws this BEFORE recording (nothing is placed). */
  placeThrows?: Error;
  /**
   * If set, `place()` RECORDS the placement (a partial tree entry now exists on
   * a real box) and THEN throws. Used to prove mint scrubs a partial entry on
   * a failed placement (no tree entry survives a failed mint).
   */
  placeRecordsThenThrows?: Error;
  /** If set, `removeEntry()` throws this on every call. */
  removeThrows?: Error;
  /** If set, ACL cleanup during `removeEntry()` throws this before the tree entry is scrubbed. */
  removeAclThrows?: Error;
  /** The dedicated agent uid `agentUid()` reports, or null for "no uid-split origin configured". */
  agentUid?: number | null;
  /** The uid `sourceOwnerUid()` reports (the owner of the source file). */
  sourceOwnerUid?: number | null;
  /** Structured result returned by `grantAgentRead()`. Defaults to unsupported. */
  grantAgentReadResult?: FileGrantAclResult;
  /** If set, `grantAgentRead()` throws despite the interface contract. */
  grantAgentReadThrows?: Error;
  /** Result returned by `probeAgentRead()`. Defaults to false. */
  probeAgentReadResult?: boolean;
  /** If set, `probeAgentRead()` throws despite the interface contract. */
  probeAgentReadThrows?: Error;
}

/** In-memory fake `FsOps`: records every call, never touches the real filesystem. */
export class FakeFsOps implements FsOps {
  placed: Array<{ src: string; dest: string }> = [];
  scrubbed: string[] = [];
  grantedReads: Array<{ entry: string; uid: number }> = [];
  probedReads: Array<{ entry: string; uid: number }> = [];
  removedAcls: Array<{ entry: string; uid: number }> = [];
  removeOptions: Array<{ entry: string; options?: FileGrantRemoveEntryOptions }> = [];
  events: string[] = [];

  constructor(private readonly opts: FakeFsOpsOptions = {}) {}

  async realpath(path: string): Promise<string> {
    return path;
  }

  async place(canonicalSrc: string, relativeTreeEntry: string): Promise<void> {
    this.events.push(`place:${relativeTreeEntry}`);
    if (this.opts.placeThrows) throw this.opts.placeThrows;
    if (this.opts.placeRecordsThenThrows) {
      this.placed.push({ src: canonicalSrc, dest: relativeTreeEntry });
      throw this.opts.placeRecordsThenThrows;
    }
    this.placed.push({ src: canonicalSrc, dest: relativeTreeEntry });
  }

  async grantAgentRead(
    relativeTreeEntry: string,
    agentUid: number
  ): Promise<FileGrantAclResult> {
    this.events.push(`grant:${relativeTreeEntry}:${agentUid}`);
    if (this.opts.grantAgentReadThrows) throw this.opts.grantAgentReadThrows;
    const result =
      this.opts.grantAgentReadResult ??
      ({
        status: "unsupported_platform",
        platform: process.platform,
        reason: "fake default",
      } satisfies FileGrantAclResult);
    if (result.status === "applied") {
      this.grantedReads.push({ entry: relativeTreeEntry, uid: agentUid });
    }
    return result;
  }

  async probeAgentRead(relativeTreeEntry: string, agentUid: number): Promise<boolean> {
    this.events.push(`probe:${relativeTreeEntry}:${agentUid}`);
    this.probedReads.push({ entry: relativeTreeEntry, uid: agentUid });
    if (this.opts.probeAgentReadThrows) throw this.opts.probeAgentReadThrows;
    return this.opts.probeAgentReadResult ?? false;
  }

  async removeEntry(
    relativeTreeEntry: string,
    options?: FileGrantRemoveEntryOptions
  ): Promise<void> {
    this.events.push(`remove:${relativeTreeEntry}`);
    this.removeOptions.push(
      options === undefined ? { entry: relativeTreeEntry } : { entry: relativeTreeEntry, options }
    );
    if (this.opts.removeThrows) throw this.opts.removeThrows;
    const matchingAcl = this.grantedReads.find((entry) => entry.entry === relativeTreeEntry);
    if (matchingAcl) {
      if (this.opts.removeAclThrows) throw this.opts.removeAclThrows;
      this.removedAcls.push({ entry: relativeTreeEntry, uid: matchingAcl.uid });
      this.events.push(`acl-removed:${relativeTreeEntry}:${matchingAcl.uid}`);
    }
    this.scrubbed.push(relativeTreeEntry);
  }

  async agentUid(_subjectAgentId: string): Promise<number | null> {
    return this.opts.agentUid ?? null;
  }

  async sourceOwnerUid(_canonicalPath: string): Promise<number | null> {
    return this.opts.sourceOwnerUid ?? 501;
  }
}
