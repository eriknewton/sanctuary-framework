import { describe, expect, it } from "vitest";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import {
  stateKey,
} from "../../src/sdw/grammar.js";
import {
  SDW_WORKING_STATE_HKDF_INFO,
  SDW_WORKING_STATE_NAMESPACE,
  type SdwWorkingStateRecord,
} from "../../src/sdw/records.js";
import {
  assertSdwRawWriteAuthorized,
  encryptedEnvelopeContains,
  mintPersistable,
  mintPersistableFromProvenance,
  sdwBackendWrite,
} from "../../src/sdw/write-gate.js";
import {
  sdwProvenanceMinters,
  taintClean,
  taintFromIdentityKey,
  taintFromPolicy,
  taintFromSecret,
  taintRecordFromFields,
} from "../../src/sdw/provenance.js";

const FORTRESS_ID = "fortress:test";
const MASTER_KEY = new Uint8Array(32).fill(11);
const NOW = "2026-06-09T00:00:00.000Z";

describe("SDW M-1 provenance-derived taint", () => {
  it("closes split-field laundering by joining identity-key field provenance", () => {
    const partA = taintFromIdentityKey("-----BEGIN ED25519");
    const separator = taintClean("ordinary separator", "user_content");
    const partB = taintFromIdentityKey(" PRIVATE KEY-----");
    const record = workingStateRecord("m1-split-identity", partA.value, [
      separator.value,
      partB.value,
    ]);

    const carrier = taintRecordFromFields(record, [partA, separator, partB]);
    expect(carrier.taint).toBe("identity_key");
    expectSdwThrow(() =>
      mintPersistableFromProvenance(
        carrier,
        SDW_WORKING_STATE_NAMESPACE,
        stateKey("task", "m1-split-identity"),
        FORTRESS_ID,
      ),
    "forbidden_taint");

    expectSdwThrow(() =>
      mintPersistable(
        { value: record, taint: "agent_derived_clean" },
        SDW_WORKING_STATE_NAMESPACE,
        stateKey("task", "m1-split-identity-legacy"),
        FORTRESS_ID,
      ),
    "classifier_reject");
  });

  it("does not expose a downgrade path for secret provenance", () => {
    const secret = taintFromSecret("broker token value");
    const clean = taintClean("benign operator note", "user_content");
    const record = workingStateRecord("m1-secret-join", clean.value, [secret.value]);
    const carrier = taintRecordFromFields(record, [clean, secret]);

    expect("taintDowngrade" in sdwProvenanceMinters).toBe(false);
    expect(carrier.taint).toBe("secret");
    expectSdwThrow(() =>
      mintPersistableFromProvenance(
        carrier,
        SDW_WORKING_STATE_NAMESPACE,
        stateKey("task", "m1-secret-join"),
        FORTRESS_ID,
      ),
    "forbidden_taint");
  });

  it("rejects policy provenance independent of content shape", () => {
    const policy = taintFromPolicy("allow read only");
    const record = workingStateRecord("m1-policy", policy.value);
    const carrier = taintRecordFromFields(record, [policy]);

    expectSdwThrow(() =>
      mintPersistableFromProvenance(
        carrier,
        SDW_WORKING_STATE_NAMESPACE,
        stateKey("task", "m1-policy"),
        FORTRESS_ID,
      ),
    "forbidden_taint");
  });

  it("mints and writes clean provenance", async () => {
    const storage = new MemoryStorage();
    const record = workingStateRecord("m1-clean", "benign operator note");
    const carrier = taintClean(record, "user_content");
    const persistable = mintPersistableFromProvenance(
      carrier,
      SDW_WORKING_STATE_NAMESPACE,
      stateKey("task", "m1-clean"),
      FORTRESS_ID,
    );

    await sdwBackendWrite(
      storage,
      persistable,
      derivePurposeKey(MASTER_KEY, SDW_WORKING_STATE_HKDF_INFO),
      FORTRESS_ID,
    );

    const raw = await storage.read(SDW_WORKING_STATE_NAMESPACE, stateKey("task", "m1-clean"));
    expect(raw).not.toBeNull();
    expect(encryptedEnvelopeContains(raw!, "benign operator note")).toBe(false);
  });

  it("makes implicit carrier laundering fail loudly", () => {
    const carrier = taintFromSecret("do not stringify");

    expectSdwThrow(() => String(carrier), "tainted_value_coercion");
    expectSdwThrow(() => JSON.stringify(carrier), "tainted_value_coercion");
    expectSdwThrow(() => `${carrier}`, "tainted_value_coercion");
  });

  it("rejects a generic token through the heuristic classifier", () => {
    const record = workingStateRecord(
      "m1-generic-token",
      "third-party token sk_test_1234567890abcdef1234567890abcdef",
    );

    expectSdwThrow(() =>
      mintPersistable(
        { value: record, taint: "agent_derived_clean" },
        SDW_WORKING_STATE_NAMESPACE,
        stateKey("task", "m1-generic-token"),
        FORTRESS_ID,
      ),
    "classifier_reject");
  });

  it("keeps a documented residual for free text that never passed a source minter", () => {
    const record = workingStateRecord(
      "m1-residual",
      "broker output handle v1.ephemeral.1234567890abcdef1234567890abcdef",
    );

    expect(() =>
      mintPersistable(
        { value: record, taint: "agent_derived_clean" },
        SDW_WORKING_STATE_NAMESPACE,
        stateKey("task", "m1-residual"),
        FORTRESS_ID,
      ),
    ).not.toThrow();
  });

  it("reassembles a PEM private-key marker split across adjacent array elements (values-only compact)", () => {
    // "...BEGIN ... PRIVATE" and "KEY ..." in two consecutive next_steps elements. The
    // canonical (key-path-interleaved) text wedges a "next_steps[1]" token between them
    // so the compact PRIVATEKEY match would miss; the values-only reassembly walks the
    // array in order with no key-path tokens between elements, so PRIVATE and KEY become
    // adjacent and the split marker is caught. Labeled clean via the legacy path -> only
    // the classifier tier can catch it (provenance was not used). Closes review finding #3.
    const record = workingStateRecord("m1-split-array", "checkpoint", [
      "intro BEGIN block PRIVATE",
      "KEY trailer material",
    ]);
    expectSdwThrow(() =>
      mintPersistable(
        { value: record, taint: "agent_derived_clean" },
        SDW_WORKING_STATE_NAMESPACE,
        stateKey("task", "m1-split-array"),
        FORTRESS_ID,
      ),
    "classifier_reject");
  });
});

function expectSdwThrow(fn: () => unknown, category: string): void {
  try {
    fn();
    throw new Error(`expected ${category}`);
  } catch (error) {
    expect(error).toMatchObject({ category });
  }
}

function workingStateRecord(
  stateId: string,
  summary: string,
  nextSteps?: readonly string[],
): SdwWorkingStateRecord {
  return {
    kind: "working_state",
    version: 1,
    state_id: stateId,
    scope: "task",
    owner_ref: "owner-1",
    status: "active",
    created_at: NOW,
    updated_at: NOW,
    content_type: "application/json",
    state: {
      kind: "task_checkpoint",
      task_ref: "task-1",
      summary,
      next_steps: nextSteps,
    },
  };
}

class MemoryStorage implements StorageBackend {
  private readonly data = new Map<string, Uint8Array>();

  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    this.rawWriteForTest(namespace, key, assertSdwRawWriteAuthorized(namespace, key, data));
  }

  rawWriteForTest(namespace: string, key: string, data: Uint8Array): void {
    this.data.set(`${namespace}\0${key}`, new Uint8Array(data));
  }

  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    return this.data.get(`${namespace}\0${key}`) ?? null;
  }

  async delete(namespace: string, key: string): Promise<boolean> {
    return this.data.delete(`${namespace}\0${key}`);
  }

  async list(namespace: string, prefix = ""): Promise<StorageEntryMeta[]> {
    const entries: StorageEntryMeta[] = [];
    for (const [composite, data] of this.data) {
      const [entryNamespace, key] = composite.split("\0", 2) as [string, string];
      if (entryNamespace !== namespace || !key.startsWith(prefix)) continue;
      entries.push({ namespace, key, size_bytes: data.byteLength, modified_at: NOW });
    }
    return entries.sort((a, b) => a.key.localeCompare(b.key));
  }

  async exists(namespace: string, key: string): Promise<boolean> {
    return this.data.has(`${namespace}\0${key}`);
  }

  async totalSize(): Promise<number> {
    let total = 0;
    for (const value of this.data.values()) total += value.byteLength;
    return total;
  }
}
