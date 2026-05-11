/**
 * WP-V1.x-RECOGNITION-LAYER Path C primary build 3:
 * fortress-config persistence helper regression suite.
 *
 * Covers `loadFortressDidWebRecord` / `tryLoadFortressDidWebRecord`:
 *
 *   - Happy path: record persisted by `did-web issue` round-trips
 *     through the loader with all fields intact.
 *   - Missing file: returns null (no error). This is the load-bearing
 *     "no fortress-config registered" signal exit-bundle export keys
 *     off of.
 *   - Malformed JSON: strict loader throws; soft loader returns null.
 *   - Schema-level malformedness (wrong version, missing required
 *     fields, identifier.did without did:web prefix): strict loader
 *     throws; soft loader returns null.
 *   - Per-fortress isolation: two distinct storage paths carry two
 *     distinct records; loading one does not surface the other.
 *   - Constant: FORTRESS_DID_WEB_REGISTRY_PATH matches the path the
 *     foundation CLI writes to (no drift between writer and reader).
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  FORTRESS_DID_WEB_REGISTRY_PATH,
  loadFortressDidWebRecord,
  tryLoadFortressDidWebRecord,
  type FortressDidWebRecord,
} from "../../src/recognition/did-web.js";

const SAMPLE_DOC = {
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
  ],
  id: "did:web:alice.example.com",
  verificationMethod: [
    {
      id: "did:web:alice.example.com#key-1",
      type: "JsonWebKey2020",
      controller: "did:web:alice.example.com",
      publicKeyJwk: {
        kty: "OKP",
        crv: "Ed25519",
        x: "AAAA",
      },
    },
  ],
  authentication: ["did:web:alice.example.com#key-1"],
  assertionMethod: ["did:web:alice.example.com#key-1"],
};

function makeRecord(
  overrides: Partial<FortressDidWebRecord["identifier"]> = {},
): FortressDidWebRecord {
  return {
    version: 1,
    identifier: {
      did: "did:web:alice.example.com",
      created_at: "2026-05-09T12:00:00.000Z",
      authority_host: "alice.example.com",
      fortress_id: "abc123",
      did_document: SAMPLE_DOC,
      ...overrides,
    },
    artifact: {
      url: "https://alice.example.com/.well-known/did.json",
      publish_path: "/.well-known/did.json",
      sha256: "0000000000000000000000000000000000000000000000000000000000000000",
    },
  };
}

async function writeRecord(
  storagePath: string,
  record: FortressDidWebRecord | string,
): Promise<void> {
  const dir = join(storagePath, "recognition");
  await mkdir(dir, { recursive: true });
  const body = typeof record === "string" ? record : JSON.stringify(record);
  await writeFile(join(dir, "did-web.json"), body);
}

describe("did:web fortress-config helper (build 3)", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-fortcfg-"));
  });
  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true });
  });

  it("exposes the canonical registry path", () => {
    expect(FORTRESS_DID_WEB_REGISTRY_PATH).toBe("recognition/did-web.json");
  });

  it("returns null when no record has been issued", async () => {
    const result = await loadFortressDidWebRecord(tmp);
    expect(result).toBeNull();
  });

  it("round-trips a valid record through the loader", async () => {
    const original = makeRecord();
    await writeRecord(tmp, original);
    const loaded = await loadFortressDidWebRecord(tmp);
    expect(loaded).not.toBeNull();
    expect(loaded?.version).toBe(1);
    expect(loaded?.identifier.did).toBe("did:web:alice.example.com");
    expect(loaded?.identifier.authority_host).toBe("alice.example.com");
    expect(loaded?.identifier.fortress_id).toBe("abc123");
    expect(loaded?.artifact.url).toBe(
      "https://alice.example.com/.well-known/did.json",
    );
  });

  it("preserves optional agent_label when present", async () => {
    const original = makeRecord({
      did: "did:web:alice.example.com:fortress:abc123:agent:writer",
      agent_label: "writer",
    });
    await writeRecord(tmp, original);
    const loaded = await loadFortressDidWebRecord(tmp);
    expect(loaded?.identifier.agent_label).toBe("writer");
  });

  it("throws on malformed JSON via strict loader", async () => {
    await writeRecord(tmp, "this is not json {{{{");
    await expect(loadFortressDidWebRecord(tmp)).rejects.toThrow(
      /not valid JSON/,
    );
  });

  it("returns null on malformed JSON via soft loader", async () => {
    await writeRecord(tmp, "this is not json {{{{");
    const result = await tryLoadFortressDidWebRecord(tmp);
    expect(result).toBeNull();
  });

  it("rejects wrong schema version via strict loader", async () => {
    const bad = { ...makeRecord(), version: 2 as unknown as 1 };
    await writeRecord(tmp, bad as unknown as FortressDidWebRecord);
    await expect(loadFortressDidWebRecord(tmp)).rejects.toThrow(/malformed/);
  });

  it("rejects record missing identifier.did via strict loader", async () => {
    const bad = makeRecord();
    delete (bad.identifier as { did?: string }).did;
    await writeRecord(tmp, bad);
    await expect(loadFortressDidWebRecord(tmp)).rejects.toThrow(/malformed/);
  });

  it("rejects identifier.did without did:web prefix via strict loader", async () => {
    const bad = makeRecord({ did: "did:key:z6Mkabcd..." });
    await writeRecord(tmp, bad);
    await expect(loadFortressDidWebRecord(tmp)).rejects.toThrow(/malformed/);
  });

  it("rejects record missing artifact.url via strict loader", async () => {
    const bad = makeRecord();
    delete (bad.artifact as { url?: string }).url;
    await writeRecord(tmp, bad);
    await expect(loadFortressDidWebRecord(tmp)).rejects.toThrow(/malformed/);
  });

  it("soft loader returns null when schema is malformed", async () => {
    const bad = makeRecord();
    delete (bad.identifier as { did?: string }).did;
    await writeRecord(tmp, bad);
    const result = await tryLoadFortressDidWebRecord(tmp);
    expect(result).toBeNull();
  });

  it("isolates records per fortress storage path", async () => {
    const fortressA = await mkdtemp(join(tmpdir(), "sanctuary-fortcfg-a-"));
    const fortressB = await mkdtemp(join(tmpdir(), "sanctuary-fortcfg-b-"));
    try {
      await writeRecord(
        fortressA,
        makeRecord({
          did: "did:web:alice.example.com",
          fortress_id: "alice",
          authority_host: "alice.example.com",
        }),
      );
      await writeRecord(
        fortressB,
        makeRecord({
          did: "did:web:bob.example.com",
          fortress_id: "bob",
          authority_host: "bob.example.com",
        }),
      );

      const a = await loadFortressDidWebRecord(fortressA);
      const b = await loadFortressDidWebRecord(fortressB);

      expect(a?.identifier.did).toBe("did:web:alice.example.com");
      expect(a?.identifier.fortress_id).toBe("alice");
      expect(b?.identifier.did).toBe("did:web:bob.example.com");
      expect(b?.identifier.fortress_id).toBe("bob");

      // Neither path leaks the other's record.
      expect(a?.identifier.did).not.toBe(b?.identifier.did);
    } finally {
      await rm(fortressA, { recursive: true, force: true });
      await rm(fortressB, { recursive: true, force: true });
    }
  });

  it("returns null when only the recognition/ directory exists with no record file", async () => {
    await mkdir(join(tmp, "recognition"), { recursive: true });
    const result = await loadFortressDidWebRecord(tmp);
    expect(result).toBeNull();
  });
});
