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
  FileGrantGrantedReadAce,
  FileGrantPinnedSource,
  FileGrantRemoveEntryOptions,
  FileGrantRemoveEntryResult,
  FileGrantSourceIdentity,
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
  /** If set, ACL cleanup during `removeEntry()` reports this while the tree entry is scrubbed. */
  removeAclThrows?: Error;
  /** The dedicated agent uid `agentUid()` reports, or null for "no uid-split origin configured". */
  agentUid?: number | null;
  /** The uid `sourceOwnerUid()` reports (the owner of the source file). */
  sourceOwnerUid?: number | null;
  /** Inode identity captured by `pinSource()`. */
  sourceIdentity?: FileGrantSourceIdentity;
  /** Inode identity observed by ACL apply. Mismatch returns a failed ACL result. */
  applySourceIdentity?: FileGrantSourceIdentity;
  /** Inode identity observed by the read probe. Mismatch returns false. */
  probeReadIdentity?: FileGrantSourceIdentity;
  /** Inode identity observed during ACL removal. Mismatch reports scrubbed:false. */
  removeSourceIdentity?: FileGrantSourceIdentity;
  /** Structured result returned by `grantAgentRead()`. Defaults to unsupported. */
  grantAgentReadResult?: FileGrantAclResult;
  /** If set, `grantAgentRead()` throws despite the interface contract. */
  grantAgentReadThrows?: Error;
  /** Result returned by `probeAgentRead()`. Defaults to false. */
  probeAgentReadResult?: boolean;
  /** If set, `probeAgentRead()` throws despite the interface contract. */
  probeAgentReadThrows?: Error;
}

export const DEFAULT_FAKE_SOURCE_IDENTITY: FileGrantSourceIdentity = {
  source_dev: "100",
  source_ino: "200",
};

export const SWAPPED_FAKE_SOURCE_IDENTITY: FileGrantSourceIdentity = {
  source_dev: "100",
  source_ino: "201",
};

function sameSourceIdentity(left: FileGrantSourceIdentity, right: FileGrantSourceIdentity): boolean {
  return left.source_dev === right.source_dev && left.source_ino === right.source_ino;
}

function sourceIdText(identity: FileGrantSourceIdentity): string {
  return `${identity.source_dev}:${identity.source_ino}`;
}

/** In-memory fake `FsOps`: records every call, never touches the real filesystem. */
export class FakeFsOps implements FsOps {
  placed: Array<{ src: string; dest: string }> = [];
  scrubbed: string[] = [];
  grantedReads: Array<{
    entry: string;
    uid: number;
    sourceRealpath: string;
    sourceIdentity: FileGrantSourceIdentity;
  }> = [];
  probedReads: Array<{
    entry: string;
    uid: number;
    expectedIdentity: FileGrantSourceIdentity;
    readIdentity: FileGrantSourceIdentity;
  }> = [];
  removedAcls: Array<{
    entry: string;
    uid: number;
    sourceRealpath: string;
    sourceIdentity: FileGrantSourceIdentity;
  }> = [];
  removeOptions: Array<{ entry: string; options?: FileGrantRemoveEntryOptions }> = [];
  events: string[] = [];

  constructor(private readonly opts: FakeFsOpsOptions = {}) {}

  async realpath(path: string): Promise<string> {
    return path;
  }

  async pinSource(canonicalPath: string): Promise<FileGrantPinnedSource> {
    const identity = this.opts.sourceIdentity ?? DEFAULT_FAKE_SOURCE_IDENTITY;
    return {
      source_realpath: canonicalPath,
      source_owner_uid: this.opts.sourceOwnerUid === undefined ? 501 : this.opts.sourceOwnerUid,
      source_fd_path: `/proc/test/fd/${sourceIdText(identity)}`,
      ...identity,
      close: async () => {},
    };
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
    agentUid: number,
    pinnedSource: FileGrantPinnedSource
  ): Promise<FileGrantAclResult> {
    const observedIdentity = this.opts.applySourceIdentity ?? pinnedSource;
    this.events.push(
      `grant:${relativeTreeEntry}:${agentUid}:${pinnedSource.source_realpath}:${sourceIdText(pinnedSource)}`
    );
    if (this.opts.grantAgentReadThrows) throw this.opts.grantAgentReadThrows;
    if (!sameSourceIdentity(observedIdentity, pinnedSource)) {
      return {
        status: "failed",
        platform: process.platform,
        reason: "source inode mismatch before ACL apply",
      };
    }
    const result =
      this.opts.grantAgentReadResult ??
      ({
        status: "unsupported_platform",
        platform: process.platform,
        reason: "fake default",
      } satisfies FileGrantAclResult);
    if (result.status === "applied") {
      const grantedReadAce: FileGrantGrantedReadAce = {
        agent_uid: result.grantedReadAce?.agent_uid ?? agentUid,
        platform: result.grantedReadAce?.platform ?? result.platform,
        source_realpath: result.grantedReadAce?.source_realpath ?? pinnedSource.source_realpath,
        source_dev: result.grantedReadAce?.source_dev ?? pinnedSource.source_dev,
        source_ino: result.grantedReadAce?.source_ino ?? pinnedSource.source_ino,
        ...(result.grantedReadAce?.mac_principal
          ? { mac_principal: result.grantedReadAce.mac_principal }
          : {}),
        ...(result.grantedReadAce?.mac_acl_hardlink_path
          ? { mac_acl_hardlink_path: result.grantedReadAce.mac_acl_hardlink_path }
          : {}),
      };
      this.grantedReads.push({
        entry: relativeTreeEntry,
        uid: agentUid,
        sourceRealpath: grantedReadAce.source_realpath,
        sourceIdentity: {
          source_dev: grantedReadAce.source_dev,
          source_ino: grantedReadAce.source_ino,
        },
      });
      return { ...result, grantedReadAce };
    }
    return result;
  }

  async probeAgentRead(
    relativeTreeEntry: string,
    agentUid: number,
    pinnedSource: FileGrantSourceIdentity
  ): Promise<boolean> {
    const readIdentity = this.opts.probeReadIdentity ?? pinnedSource;
    this.events.push(`probe:${relativeTreeEntry}:${agentUid}:${sourceIdText(pinnedSource)}`);
    this.probedReads.push({
      entry: relativeTreeEntry,
      uid: agentUid,
      expectedIdentity: {
        source_dev: pinnedSource.source_dev,
        source_ino: pinnedSource.source_ino,
      },
      readIdentity: {
        source_dev: readIdentity.source_dev,
        source_ino: readIdentity.source_ino,
      },
    });
    if (this.opts.probeAgentReadThrows) throw this.opts.probeAgentReadThrows;
    return (this.opts.probeAgentReadResult ?? false) && sameSourceIdentity(readIdentity, pinnedSource);
  }

  async removeEntry(
    relativeTreeEntry: string,
    options?: FileGrantRemoveEntryOptions
  ): Promise<FileGrantRemoveEntryResult> {
    this.events.push(`remove:${relativeTreeEntry}`);
    this.removeOptions.push(
      options === undefined ? { entry: relativeTreeEntry } : { entry: relativeTreeEntry, options }
    );
    const ace = options?.grantedReadAce ?? null;
    let aclRemoval: FileGrantRemoveEntryResult["aclRemoval"] = { status: "not_applicable" };
    if (ace) {
      if (ace.source_dev === undefined || ace.source_ino === undefined) {
        aclRemoval = {
          status: "failed",
          agent_uid: ace.agent_uid,
          platform: ace.platform,
          source_realpath: ace.source_realpath,
          reason: "source inode identity missing from persisted ACE",
        };
        this.events.push(`acl-remove-skipped:${relativeTreeEntry}:${ace.agent_uid}`);
      } else {
        const aceIdentity = { source_dev: ace.source_dev, source_ino: ace.source_ino };
        const removeIdentity = this.opts.removeSourceIdentity ?? aceIdentity;
        if (!sameSourceIdentity(removeIdentity, aceIdentity)) {
          aclRemoval = {
            status: "failed",
            agent_uid: ace.agent_uid,
            platform: ace.platform,
            source_realpath: ace.source_realpath,
            reason: "source inode mismatch before ACL removal",
          };
          this.events.push(`acl-remove-skipped:${relativeTreeEntry}:${ace.agent_uid}`);
        } else if (this.opts.removeAclThrows) {
          aclRemoval = {
            status: "failed",
            agent_uid: ace.agent_uid,
            platform: ace.platform,
            source_realpath: ace.source_realpath,
            reason: this.opts.removeAclThrows.message,
          };
          this.events.push(`acl-remove-failed:${relativeTreeEntry}:${ace.agent_uid}`);
        } else {
          this.removedAcls.push({
            entry: relativeTreeEntry,
            uid: ace.agent_uid,
            sourceRealpath: ace.source_realpath,
            sourceIdentity: {
              source_dev: aceIdentity.source_dev,
              source_ino: aceIdentity.source_ino,
            },
          });
          aclRemoval = {
            status: "removed",
            agent_uid: ace.agent_uid,
            platform: ace.platform,
            source_realpath: ace.source_realpath,
          };
          this.events.push(`acl-removed:${relativeTreeEntry}:${ace.agent_uid}`);
        }
      }
    }
    if (this.opts.removeThrows) throw this.opts.removeThrows;
    this.scrubbed.push(relativeTreeEntry);
    return {
      treeEntryRemoved: true,
      aclRemoval,
      scrubbed: aclRemoval.status !== "failed",
    };
  }

  async agentUid(_subjectAgentId: string): Promise<number | null> {
    return this.opts.agentUid ?? null;
  }

  async sourceOwnerUid(_canonicalPath: string): Promise<number | null> {
    return this.opts.sourceOwnerUid === undefined ? 501 : this.opts.sourceOwnerUid;
  }
}
