/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-1 Anomaly classifier state store.
 *
 * Encrypted at-rest persistence for classifier state. Mirrors the
 * Phi-1 finding store pattern: HKDF subkey from fortress master key,
 * AAD-bound per (classifier_id, agent_id) tuple. Two fortresses
 * never produce identical encryption keys for identical state keys.
 *
 * Storage layout:
 *   namespace: `_anomaly_classifier_state`
 *   key:       `state.{classifier_id}.{agent_id}`
 *   payload:   AES-256-GCM ciphertext of the JSON-serialized state.
 *   key:       `l2-anomaly-classifier-state-v1` HKDF subkey of fortress master.
 *   AAD:       UTF-8 bytes of `<classifier_id>|<agent_id>`.
 *
 * Sovereignty invariant: state never leaves the fortress. No outbound
 * surface is added by this store. Operator may inspect or delete via
 * the standard storage tools.
 */

import type { StorageBackend } from "../storage/interface.js";
import {
  encrypt,
  decrypt,
  type EncryptedPayload,
} from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";

export const ANOMALY_CLASSIFIER_STATE_NAMESPACE =
  "_anomaly_classifier_state";
export const ANOMALY_CLASSIFIER_STATE_KEY_PREFIX = "state.";
const HKDF_INFO = "l2-anomaly-classifier-state-v1";

/** Hard upper bound on per-record decode size. Defends against malformed input. */
const MAX_STATE_BYTES = 256 * 1024;

interface PersistedState<T> {
  version: 1;
  classifier_id: string;
  agent_id: string;
  fortress_id: string;
  saved_at: string;
  state: T;
}

export interface ClassifierStateStoreOptions {
  storage: StorageBackend;
  masterKey: Uint8Array;
  fortressId: string;
  /** Wall-clock provider for deterministic tests. */
  now?: () => Date;
}

export class ClassifierStateStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;
  private readonly fortressId: string;
  private readonly now: () => Date;

  constructor(opts: ClassifierStateStoreOptions) {
    this.storage = opts.storage;
    this.encryptionKey = derivePurposeKey(opts.masterKey, HKDF_INFO);
    this.fortressId = opts.fortressId;
    this.now = opts.now ?? (() => new Date());
  }

  async saveState<T>(
    classifierId: string,
    agentId: string,
    state: T,
  ): Promise<void> {
    const persisted: PersistedState<T> = {
      version: 1,
      classifier_id: classifierId,
      agent_id: agentId,
      fortress_id: this.fortressId,
      saved_at: this.now().toISOString(),
      state,
    };
    const aadString = aadFor(classifierId, agentId);
    const aad = stringToBytes(aadString);
    const plaintext = stringToBytes(JSON.stringify(persisted));
    const envelope = encrypt(plaintext, this.encryptionKey, aad);
    await this.storage.write(
      ANOMALY_CLASSIFIER_STATE_NAMESPACE,
      stateKey(classifierId, agentId),
      stringToBytes(JSON.stringify(envelope)),
    );
  }

  async loadState<T>(
    classifierId: string,
    agentId: string,
  ): Promise<T | null> {
    const key = stateKey(classifierId, agentId);
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(
        ANOMALY_CLASSIFIER_STATE_NAMESPACE,
        key,
      );
    } catch {
      return null;
    }
    if (!raw) return null;
    if (raw.length > MAX_STATE_BYTES) return null;
    try {
      const aad = stringToBytes(aadFor(classifierId, agentId));
      const envelope: EncryptedPayload = JSON.parse(bytesToString(raw));
      const plaintext = decrypt(envelope, this.encryptionKey, aad);
      const persisted = JSON.parse(
        bytesToString(plaintext),
      ) as PersistedState<T>;
      if (persisted.version !== 1) return null;
      if (persisted.classifier_id !== classifierId) return null;
      if (persisted.agent_id !== agentId) return null;
      if (persisted.fortress_id !== this.fortressId) return null;
      return persisted.state;
    } catch {
      return null;
    }
  }

  /** Delete a single classifier-agent state record. */
  async deleteState(classifierId: string, agentId: string): Promise<boolean> {
    const key = stateKey(classifierId, agentId);
    const existed = await this.storage.exists(
      ANOMALY_CLASSIFIER_STATE_NAMESPACE,
      key,
    );
    if (!existed) return false;
    try {
      await this.storage.delete(ANOMALY_CLASSIFIER_STATE_NAMESPACE, key);
    } catch {
      return false;
    }
    return true;
  }

  /**
   * List the (classifier_id, agent_id) tuples currently persisted.
   * Returns the agent ids for one classifier when classifierId is
   * given.
   */
  async listAgents(classifierId: string): Promise<string[]> {
    const metas = await this.storage.list(
      ANOMALY_CLASSIFIER_STATE_NAMESPACE,
      ANOMALY_CLASSIFIER_STATE_KEY_PREFIX,
    );
    const prefix = `${ANOMALY_CLASSIFIER_STATE_KEY_PREFIX}${classifierId}.`;
    const out: string[] = [];
    for (const meta of metas) {
      if (!meta.key.startsWith(prefix)) continue;
      out.push(meta.key.slice(prefix.length));
    }
    return out;
  }
}

function stateKey(classifierId: string, agentId: string): string {
  return `${ANOMALY_CLASSIFIER_STATE_KEY_PREFIX}${classifierId}.${agentId}`;
}

function aadFor(classifierId: string, agentId: string): string {
  return `${classifierId}|${agentId}`;
}
