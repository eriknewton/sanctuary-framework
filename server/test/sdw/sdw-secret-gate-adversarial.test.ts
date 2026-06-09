import { describe, expect, it } from "vitest";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { stringToBytes } from "../../src/core/encoding.js";
import {
  documentKey,
  stateKey,
} from "../../src/sdw/grammar.js";
import {
  SDW_DOCUMENT_CORPUS_HKDF_INFO,
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  SDW_META_NAMESPACE,
  SDW_REPLAY_ANCHOR_KEY,
  SDW_WORKING_STATE_HKDF_INFO,
  SDW_WORKING_STATE_NAMESPACE,
  type SdwDocumentRecord,
  type SdwWorkingStateRecord,
} from "../../src/sdw/records.js";
import {
  assertSdwRawWriteAuthorized,
  combineTaint,
  encryptedEnvelopeContains,
  mintPersistable,
  prepareReplayAnchorWrite,
  sdwBackendWrite,
} from "../../src/sdw/write-gate.js";
import { emptyReplayAnchorData } from "../../src/sdw/replay-anchor.js";
import { SdwValidationError } from "../../src/sdw/errors.js";

const FORTRESS_ID = "fortress:test";
const MASTER_KEY = new Uint8Array(32).fill(9);
const NOW = "2026-06-09T00:00:00.000Z";

describe("SDW secret-persistence adversarial fixtures", () => {
  it("F-1 blocks encoded DER-shaped Ed25519 private-key material", () => {
    const encodedDer = encodedEd25519Pkcs8Fixture();

    expect(() =>
      mintPersistable(
        { value: workingStateRecord("f1-base64", encodedDer.base64), taint: "agent_derived_clean" },
        SDW_WORKING_STATE_NAMESPACE,
        stateKey("task", "f1-base64"),
        FORTRESS_ID,
      ),
    ).toThrow(SdwValidationError);

    expect(() =>
      mintPersistable(
        { value: workingStateRecord("f1-hex", encodedDer.hex), taint: "agent_derived_clean" },
        SDW_WORKING_STATE_NAMESPACE,
        stateKey("task", "f1-hex"),
        FORTRESS_ID,
      ),
    ).toThrow(SdwValidationError);

    expect(() =>
      mintPersistable(
        {
          value: workingStateRecord("f1-normal", "normal document hash 302e020100300506032b6571-not-a-der-key"),
          taint: "agent_derived_clean",
        },
        SDW_WORKING_STATE_NAMESPACE,
        stateKey("task", "f1-normal"),
        FORTRESS_ID,
      ),
    ).not.toThrow();
  });

  it("F-2 documents split-field classifier limits for separated PEM markers", async () => {
    const storage = new MemoryStorage();
    const record = workingStateRecord("f2-split", "-----BEGIN ED25519");
    const splitRecord: SdwWorkingStateRecord = {
      ...record,
      state: {
        kind: "task_checkpoint",
        task_ref: "task-1",
        summary: "-----BEGIN ED25519",
        next_steps: ["ordinary separator", " PRIVATE KEY-----"],
      },
    };

    const persistable = mintPersistable(
      { value: splitRecord, taint: "agent_derived_clean" },
      SDW_WORKING_STATE_NAMESPACE,
      stateKey("task", "f2-split"),
      FORTRESS_ID,
    );
    await sdwBackendWrite(
      storage,
      persistable,
      derivePurposeKey(MASTER_KEY, SDW_WORKING_STATE_HKDF_INFO),
      FORTRESS_ID,
    );

    const raw = await storage.read(SDW_WORKING_STATE_NAMESPACE, stateKey("task", "f2-split"));
    expect(raw).not.toBeNull();
    expect(encryptedEnvelopeContains(raw!, "PRIVATE KEY")).toBe(false);
  });

  it("F-3/F-5/F-6 are covered by phase1 architecture fixtures", () => {
    // See sdw-phase1.test.ts for forbidden taints and forged persistables.
    // See sdw-architecture.test.ts for raw-write authorization and mutation checks.
    expect(true).toBe(true);
  });

  it("F-4 documents that a generic third-party token mislabeled clean currently passes", async () => {
    const storage = new MemoryStorage();
    const tokenLikeText = "third-party token sk_test_1234567890abcdef1234567890abcdef";
    const record = workingStateRecord("f4-clean-token", tokenLikeText);
    const persistable = mintPersistable(
      { value: record, taint: "agent_derived_clean" },
      SDW_WORKING_STATE_NAMESPACE,
      stateKey("task", "f4-clean-token"),
      FORTRESS_ID,
    );

    await sdwBackendWrite(
      storage,
      persistable,
      derivePurposeKey(MASTER_KEY, SDW_WORKING_STATE_HKDF_INFO),
      FORTRESS_ID,
    );

    const raw = await storage.read(SDW_WORKING_STATE_NAMESPACE, stateKey("task", "f4-clean-token"));
    expect(raw).not.toBeNull();
    expect(encryptedEnvelopeContains(raw!, tokenLikeText)).toBe(false);
  });

  it("F-7 blocks structural metadata smuggling but documents generic metadata content limits", async () => {
    const storage = new MemoryStorage();

    expect(() =>
      mintPersistable(
        {
          value: documentRecord("f7-pem", "local only", [
            { key: "operator-note", value: "-----BEGIN ED25519 PRIVATE KEY-----\nredacted\n-----END ED25519 PRIVATE KEY-----" },
          ]),
          taint: "user_content",
        },
        SDW_DOCUMENT_CORPUS_NAMESPACE,
        documentKey("f7-pem"),
        FORTRESS_ID,
      ),
    ).toThrow(SdwValidationError);

    expect(() =>
      mintPersistable(
        {
          value: documentRecord("f7-bad-key", "local only", [{ key: "operator\nnote", value: "plain" }]),
          taint: "user_content",
        },
        SDW_DOCUMENT_CORPUS_NAMESPACE,
        documentKey("f7-bad-key"),
        FORTRESS_ID,
      ),
    ).toThrow(SdwValidationError);

    const genericToken = "metadata token ghp_1234567890abcdef1234567890abcdef";
    const record = documentRecord("f7-generic", "https://example.test/?token=ghp_1234567890abcdef", [
      { key: "operator-note", value: genericToken },
    ]);
    const persistable = mintPersistable(
      { value: record, taint: "agent_derived_clean" },
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentKey("f7-generic"),
      FORTRESS_ID,
    );
    await sdwBackendWrite(
      storage,
      persistable,
      derivePurposeKey(MASTER_KEY, SDW_DOCUMENT_CORPUS_HKDF_INFO),
      FORTRESS_ID,
    );

    const raw = await storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, documentKey("f7-generic"));
    expect(raw).not.toBeNull();
    expect(encryptedEnvelopeContains(raw!, genericToken)).toBe(false);
    expect(encryptedEnvelopeContains(raw!, "ghp_1234567890abcdef")).toBe(false);
  });

  it("F-8 documents broker-shaped output persistence boundaries", async () => {
    const storage = new MemoryStorage();
    const brokerToken = "broker-output token v1.ephemeral.1234567890abcdef1234567890abcdef";
    const record = workingStateRecord("f8-broker", brokerToken);
    const persistable = mintPersistable(
      { value: record, taint: "agent_derived_clean" },
      SDW_WORKING_STATE_NAMESPACE,
      stateKey("task", "f8-broker"),
      FORTRESS_ID,
    );

    await sdwBackendWrite(
      storage,
      persistable,
      derivePurposeKey(MASTER_KEY, SDW_WORKING_STATE_HKDF_INFO),
      FORTRESS_ID,
    );
    expect(await storage.read(SDW_WORKING_STATE_NAMESPACE, stateKey("task", "f8-broker"))).not.toBeNull();

    expect(() =>
      mintPersistable(
        {
          value: workingStateRecord(
            "f8-broker-pem",
            "broker-output -----BEGIN ED25519 PRIVATE KEY----- redacted -----END ED25519 PRIVATE KEY-----",
          ),
          taint: "agent_derived_clean",
        },
        SDW_WORKING_STATE_NAMESPACE,
        stateKey("task", "f8-broker-pem"),
        FORTRESS_ID,
      ),
    ).toThrow(SdwValidationError);
  });

  it("F-9 rejects malformed and oversized replay-anchor data before authorization", () => {
    expect(() =>
      prepareReplayAnchorWrite(MASTER_KEY, {
        ...emptyReplayAnchorData(),
        chain_head: [{ id: "bad\nid", seq: 1 }],
      }),
    ).toThrow(SdwValidationError);

    expect(() =>
      prepareReplayAnchorWrite(MASTER_KEY, {
        ...emptyReplayAnchorData(),
        catalog: -1,
      }),
    ).toThrow(SdwValidationError);

    try {
      prepareReplayAnchorWrite(MASTER_KEY, {
        catalog: 1,
        export_state: 0,
      } as any);
      throw new Error("expected malformed replay anchor rejection");
    } catch (error) {
      expect(error).toMatchObject({ category: "schema_mismatch" });
    }

    try {
      prepareReplayAnchorWrite(MASTER_KEY, {
        ...emptyReplayAnchorData(),
        chain_head: Array.from({ length: 26000 }, (_, index) => ({
          id: `counter-${index}-${"x".repeat(40)}`,
          seq: index,
        })),
      });
      throw new Error("expected oversized replay anchor rejection");
    } catch (error) {
      expect(error).toMatchObject({ category: "record_too_large" });
    }
  });

  it("F-10 combines taint using the more restrictive safety join", () => {
    expect(combineTaint("user_content", "secret")).toBe("secret");
    expect(combineTaint("agent_derived_clean", "identity_key")).toBe("identity_key");
    expect(combineTaint("policy", "system_generated")).toBe("policy");
  });

  it("direct never-authorized SDW bytes remain rejected at the raw-write boundary", () => {
    expect(() =>
      assertSdwRawWriteAuthorized(
        SDW_META_NAMESPACE,
        SDW_REPLAY_ANCHOR_KEY,
        stringToBytes(JSON.stringify({ marker: "forged" })),
      ),
    ).toThrow(SdwValidationError);
  });
});

function encodedEd25519Pkcs8Fixture(): { readonly hex: string; readonly base64: string } {
  const hex = "302e020100300506032b657004220420" + "11".repeat(32);
  return {
    hex,
    base64: Buffer.from(hex, "hex").toString("base64"),
  };
}

function workingStateRecord(stateId: string, summary: string): SdwWorkingStateRecord {
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
    },
  };
}

function documentRecord(
  documentId: string,
  uri: string,
  metadata: SdwDocumentRecord["metadata"],
): SdwDocumentRecord {
  return {
    kind: "document",
    version: 1,
    document_id: documentId,
    source: { kind: "url", uri, title: "Example", media_type: "text/plain" },
    content_hash: "hash-1",
    chunk_count: 1,
    byte_length: 10,
    created_at: NOW,
    updated_at: NOW,
    tags: ["tag-1"],
    metadata,
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
