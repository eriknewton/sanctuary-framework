import { describe, expect, it } from "vitest";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { sdwAad } from "../../src/sdw/grammar.js";
import {
  canonicalJson,
  decodeSdwRecord,
} from "../../src/sdw/store-codec.js";
import {
  SdwValidationError,
  UnsupportedRecordVersion,
} from "../../src/sdw/errors.js";
import {
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  type SdwDocumentRecord,
} from "../../src/sdw/records.js";

const encryptionKey = new Uint8Array(32).fill(7);
const fortressId = "fortress.test";
const storageKey = "doc.doc-1";

const documentRecord = {
  kind: "document",
  version: 1,
  document_id: "doc-1",
  source: {
    kind: "file",
    uri: "file:///tmp/doc.md",
    title: "Doc",
  },
  content_hash: "hash-1",
  chunk_count: 2,
  byte_length: 128,
  created_at: "2026-06-09T00:00:00.000Z",
  updated_at: "2026-06-09T00:01:00.000Z",
  tags: ["alpha", "beta"],
  metadata: [{ key: "owner", value: "test" }],
} satisfies SdwDocumentRecord;

function encodeRecord(
  record: unknown,
  overrides: Partial<{
    namespace: typeof SDW_DOCUMENT_CORPUS_NAMESPACE;
    key: string;
    fortress: string;
  }> = {},
): Uint8Array {
  const namespace = overrides.namespace ?? SDW_DOCUMENT_CORPUS_NAMESPACE;
  const key = overrides.key ?? storageKey;
  const fortress = overrides.fortress ?? fortressId;
  const envelope = encrypt(
    stringToBytes(JSON.stringify(record)),
    encryptionKey,
    sdwAad(fortress, namespace, key),
  );
  return stringToBytes(JSON.stringify(envelope));
}

function decodeDocument(
  raw: Uint8Array,
  verifyIdentity = (record: SdwDocumentRecord) => record.document_id === "doc-1",
): SdwDocumentRecord {
  return decodeSdwRecord<SdwDocumentRecord>(raw, {
    namespace: SDW_DOCUMENT_CORPUS_NAMESPACE,
    storageKey,
    fortressId,
    encryptionKey,
    expectedKind: "document",
    verifyIdentity,
  });
}

describe("sdw/store-codec : canonicalJson", () => {
  it("sorts object keys recursively while preserving array order", () => {
    expect(
      canonicalJson({
        z: 1,
        a: {
          c: 3,
          b: undefined,
          a: [{ d: 4, c: undefined }, 2],
        },
        m: null,
      }),
    ).toBe('{"a":{"a":[{"d":4},2],"c":3},"m":null,"z":1}');
  });
});

describe("sdw/store-codec : decodeSdwRecord", () => {
  it("decodes an encrypted record when kind and identity match", () => {
    expect(decodeDocument(encodeRecord(documentRecord))).toEqual(documentRecord);
  });

  it("throws UnsupportedRecordVersion for decrypted non-v1 records", () => {
    const raw = encodeRecord({ ...documentRecord, version: 2 });

    expect(() => decodeDocument(raw)).toThrow(UnsupportedRecordVersion);
    try {
      decodeDocument(raw);
    } catch (error) {
      expect(error).toMatchObject({
        namespace: SDW_DOCUMENT_CORPUS_NAMESPACE,
        storageKey,
        version: 2,
      });
    }
  });

  it("throws identity_mismatch when the identity verifier rejects the record", () => {
    expect(() => decodeDocument(encodeRecord(documentRecord), () => false)).toThrow(
      SdwValidationError,
    );
    try {
      decodeDocument(encodeRecord(documentRecord), () => false);
    } catch (error) {
      expect(error).toMatchObject({ category: "identity_mismatch" });
    }
  });

  it("maps malformed raw bytes to auth_failed validation errors", () => {
    expect(() => decodeDocument(stringToBytes("{not-json"))).toThrow(
      SdwValidationError,
    );
    try {
      decodeDocument(stringToBytes("{not-json"));
    } catch (error) {
      expect(error).toMatchObject({ category: "auth_failed" });
    }
  });

  it("maps authenticated-data mismatches to auth_failed validation errors", () => {
    const raw = encodeRecord(documentRecord, { key: "doc.other" });

    expect(() => decodeDocument(raw)).toThrow(SdwValidationError);
    try {
      decodeDocument(raw);
    } catch (error) {
      expect(error).toMatchObject({ category: "auth_failed" });
    }
  });
});
