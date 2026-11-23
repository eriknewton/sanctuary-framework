/**
 * An unattributed origin survives close and reopen as one canonical sealed
 * shape: shared_entangled with an empty lineage. Exit leaves it behind without
 * an operator consent release and carries it with one.
 */
import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString } from "../../src/core/encoding.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import {
  remintDeclaredProvenanceStamp,
  StateStore,
  type StateEntry,
} from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { fingerprintIdentityId } from "../../src/agent-native/safety-base.js";
import { partitionByMemoryClass, recordConsentRelease } from "../../src/exit/index.js";

let tempDirs: string[] = [];
afterEach(async () => {
  try {
    for (const dir of tempDirs) await rm(dir, { recursive: true, force: true });
  } finally {
    tempDirs = [];
  }
});

async function freshDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "sanctuary-unattributed-origin-"));
  tempDirs.push(dir);
  return dir;
}

async function rawEntry(storage: StorageBackend, namespace: string, key: string): Promise<StateEntry> {
  const bytes = await storage.read(namespace, key);
  if (bytes === null) throw new Error("entry not stored");
  return JSON.parse(bytesToString(bytes)) as StateEntry;
}

async function soleBoundWrite(storage: StorageBackend, masterKey: Uint8Array, namespace: string, key: string) {
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  let identityId: string | undefined;
  const { tools, identityManager } = createL1Tools(stateStore, storage, masterKey, "passphrase", auditLog, {
    sessionBindingBootState: () => "state_BOUND_SOLE_IDENTITY",
    currentSessionBinding: () => identityId === undefined ? undefined : {
      identity_id: identityId,
      requester_identity_fingerprint: fingerprintIdentityId(identityId),
      binding_source: "sole_identity",
    },
  });
  await identityManager.load();
  const call = async (name: string, args: Record<string, unknown>) =>
    JSON.parse((await tools.find((tool) => tool.name === name)!.handler(args)).content[0]!.text);
  identityId = (await call("identity_create", { label: "round-trip-subject" })).identity_id as string;
  expect(await call("state_write", { namespace, key, value: "sole-bound note" })).toMatchObject({ namespace, key });
  await auditLog.flush();
  return { auditLog, identityId };
}

/** A store and one created identity, for writes made straight through StateStore.write. */
async function storeWriter() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const { tools, identityManager } = createL1Tools(new StateStore(storage, masterKey), storage, masterKey, "passphrase");
  await identityManager.load();
  const created = JSON.parse((await tools.find((tool) => tool.name === "identity_create")!.handler({ label: "store-writer" })).content[0]!.text);
  const identity = identityManager.get(created.identity_id as string)!;
  const write = (origin_actor: "unattributed" | "agent" | "operator" | "system") =>
    new StateStore(storage, masterKey).write(
      "notes", "k", "v", identity.identity_id, identity.encrypted_private_key,
      derivePurposeKey(masterKey, "identity-encryption"),
      { provenance: { origin_actor } },
    );
  return { storage, masterKey, write };
}

describe("unattributed origin round trip", () => {
  it("a sole-bound write reopened from disk remints sealed shared_entangled and leaves only with consent", async () => {
    const dir = await freshDir();
    const masterKey = generateRandomKey();
    const { identityId } = await soleBoundWrite(new FilesystemStorage(dir), masterKey, "notes", "k");

    const reopened = new FilesystemStorage(dir);
    const store = new StateStore(reopened, masterKey);
    const reminted = await store.remintVerifiedProvenanceStampForExport(await rawEntry(reopened, "notes", "k"), "notes", "k");
    expect(reminted.status).toBe("sealed");
    if (reminted.status !== "sealed") return;
    expect(reminted.sealedStamp).toMatchObject({ origin_actor: "unattributed", memory_class: "shared_entangled", derived_from: [] });

    const candidate = { id: "notes/k", sealedStamp: reminted.sealedStamp, declaredStamp: reminted.declaredStamp };
    expect(partitionByMemoryClass([candidate]).excluded).toEqual([
      expect.objectContaining({ id: "notes/k", includable: false, reason: "class_shared_entangled_no_consent" }),
    ]);
    const receipt = await recordConsentRelease({
      auditLog: new AuditLog(reopened, masterKey),
      operatorIdentityId: identityId,
      lineageId: reminted.sealedStamp.lineage_id,
      memoryClass: "shared_entangled",
      agentRef: "agent:round-trip",
      disposition: "released_to_agent",
    });
    expect(partitionByMemoryClass([candidate], { consentReleases: [receipt] }).includable).toEqual([
      expect.objectContaining({ id: "notes/k", includable: true, reason: "released_by_consent" }),
    ]);
  });

  it("a store write with origin unattributed reloads as a sealed shared_entangled stamp", async () => {
    const { storage, masterKey, write } = await storeWriter();
    await write("unattributed");
    const reloaded = new StateStore(storage, masterKey);
    const reminted = await reloaded.remintVerifiedProvenanceStampForExport(await rawEntry(storage, "notes", "k"), "notes", "k");
    expect(reminted).toMatchObject({
      status: "sealed",
      sealedStamp: { origin_actor: "unattributed", memory_class: "shared_entangled", derived_from: [] },
    });
  });
});

describe("the canonical unattributed shape", () => {
  // A raw edit of a signed entry's stamp fails signature verification before it is read
  // ("tampering with signed provenance fails verification before read", test/cognitive/state-envelope-integrity.test.ts),
  // so these hand-edited copies go straight to the remint step.
  async function persistedStamp(origin_actor: "unattributed" | "agent" | "operator" | "system") {
    const { storage, write } = await storeWriter();
    await write(origin_actor);
    return (await rawEntry(storage, "notes", "k")).provenance_stamp as unknown as Record<string, unknown>;
  }

  it("the persisted canonical form remints sealed", async () => {
    const stamp = await persistedStamp("unattributed");
    expect(Object.hasOwn(stamp, "derived_from_edges")).toBe(false);
    expect(remintDeclaredProvenanceStamp(stamp)).toMatchObject({
      status: "sealed",
      sealedStamp: { origin_actor: "unattributed", memory_class: "shared_entangled" },
    });
  });

  it.each([
    ["one edge added", { derived_from: ["l0"], derived_from_edges: [{ lineage_id: "l0", memory_class: "operator_owned" }] }],
    ["class agent_owned", { memory_class: "agent_owned" }],
    ["class operator_owned", { memory_class: "operator_owned" }],
    ["a non-empty derived_from", { derived_from: ["l0"] }],
    ["an empty derived_from_edges array", { derived_from_edges: [] }],
  ])("an unattributed stamp with an edge, or with class agent_owned, is unsealed: %s", async (_name, edit) => {
    const stamp = { ...(await persistedStamp("unattributed")), ...edit };
    expect(remintDeclaredProvenanceStamp(stamp).status).toBe("unsealed");
  });

  it.each(["agent", "operator", "system"] as const)("a shared_entangled stamp without edges and any other origin is still unsealed: %s", async (origin) => {
    const stamp = { ...(await persistedStamp(origin)), memory_class: "shared_entangled" };
    expect(Object.hasOwn(stamp, "derived_from_edges")).toBe(false);
    expect(remintDeclaredProvenanceStamp(stamp).status).toBe("unsealed");
  });
});
