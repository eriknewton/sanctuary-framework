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
import type { FsOps } from "../../src/file-grant/types.js";

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
  /** If set, `place()` throws this on every call (fail-closed test). */
  placeThrows?: Error;
  /** If set, `removeEntry()` throws this on every call. */
  removeThrows?: Error;
  /** The dedicated agent uid `agentUid()` reports, or null for "no uid-split origin configured". */
  agentUid?: number | null;
  /** The uid `operatorUid()` reports. */
  operatorUid?: number | null;
}

/** In-memory fake `FsOps`: records every call, never touches the real filesystem. */
export class FakeFsOps implements FsOps {
  placed: Array<{ src: string; dest: string }> = [];
  scrubbed: string[] = [];

  constructor(private readonly opts: FakeFsOpsOptions = {}) {}

  async realpath(path: string): Promise<string> {
    return path;
  }

  async place(canonicalSrc: string, relativeTreeEntry: string): Promise<void> {
    if (this.opts.placeThrows) throw this.opts.placeThrows;
    this.placed.push({ src: canonicalSrc, dest: relativeTreeEntry });
  }

  async removeEntry(relativeTreeEntry: string): Promise<void> {
    if (this.opts.removeThrows) throw this.opts.removeThrows;
    this.scrubbed.push(relativeTreeEntry);
  }

  async agentUid(_subjectAgentId: string): Promise<number | null> {
    return this.opts.agentUid ?? null;
  }

  async operatorUid(): Promise<number | null> {
    return this.opts.operatorUid ?? 501;
  }
}
