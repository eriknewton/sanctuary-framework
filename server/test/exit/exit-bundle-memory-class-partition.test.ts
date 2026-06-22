/**
 * Exit machinery Slice 1 — conservative partition wired into the real exit
 * bundle export.
 *
 * These tests drive the ACTUAL `exportExitBundle` path (signed manifest, hashed
 * artifacts, #499 re-key) with the `memoryClassPartition` option, and assert on
 * the encrypted_state artifact that actually lands on disk:
 *
 *   (a) a sealed agent_owned entry travels in the bundle;
 *   (b) LOAD-BEARING — an entry with no sealed agent_owned stamp is EXCLUDED
 *       (it fails toward "stays with the operator," never agent_owned);
 *   (c) an audited consent release flips a shared_entangled entry to includable.
 *
 * No external clean-exit claim is made or tested: only that the partition
 * mechanically excludes non-includable records and that exclusion is the
 * default for unsealed data.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore, type StateEntry } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { encrypt } from "../../src/core/encryption.js";
import {
  bytesToString,
  stringToBytes,
  toBase64url,
  fromBase64url,
} from "../../src/core/encoding.js";
import { sign } from "../../src/core/identity.js";
import { hashToString } from "../../src/core/hashing.js";
import { deriveNamespaceKey, derivePurposeKey } from "../../src/core/key-derivation.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import { fingerprintIdentityId } from "../../src/agent-native/safety-base.js";
import {
  exportExitBundle,
  verifyExitBundle,
  type ExitEncryptedStateBundle,
} from "../../src/exit/index.js";

async function callTool(
  tools: Array<{
    name: string;
    handler: (args: Record<string, unknown>) => Promise<{
      content: Array<{ type: string; text: string }>;
    }>;
  }>,
  name: string,
  args: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

async function buildSource() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  let sessionIdentityId: string | undefined;
  const { tools: l1Tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "passphrase",
    auditLog,
    {
      currentSessionBinding: () =>
        sessionIdentityId
          ? {
              identity_id: sessionIdentityId,
              requester_identity_fingerprint: fingerprintIdentityId(sessionIdentityId),
            }
          : undefined,
    },
  );
  await identityManager.load();
  const { tools: l4Tools, reputationStore } = createL4Tools(
    storage,
    masterKey,
    identityManager,
    auditLog,
  );
  const identity = await callTool([...l1Tools, ...l4Tools], "identity_create", {
    label: "partition-source",
  });
  const identityId = identity.identity_id as string;
  const storedIdentity = identityManager.get(identityId);
  if (!storedIdentity) throw new Error("source identity was not persisted");
  return {
    storage,
    masterKey,
    auditLog,
    stateStore,
    identityManager,
    reputationStore,
    tools: [...l1Tools, ...l4Tools],
    identityId,
    storedIdentity,
    identityEncKey,
    setAgentSession(active: boolean) {
      sessionIdentityId = active ? identityId : undefined;
    },
  };
}

type Source = Awaited<ReturnType<typeof buildSource>>;

async function writeState(
  source: Source,
  namespace: string,
  key: string,
  value: string,
  actor: "agent" | "operator" = "agent",
) {
  source.setAgentSession(actor === "agent");
  await callTool(source.tools, "state_write", {
    namespace,
    key,
    value,
    identity_id: source.identityId,
  });
}

async function writeSharedState(
  source: Source,
  namespace: string,
  key: string,
  value: string,
) {
  await source.stateStore.write(
    namespace,
    key,
    value,
    source.identityId,
    source.storedIdentity.encrypted_private_key,
    source.identityEncKey,
    {
      provenance: {
        origin_actor: "agent",
        derived_from: [{ lineage_id: "lin-op", memory_class: "operator_owned" }],
      },
    },
  );
}

async function writeLegacyUnstampedState(
  source: Source,
  namespace: string,
  key: string,
  value: string,
) {
  const plaintext = stringToBytes(value);
  const payload = encrypt(plaintext, deriveNamespaceKey(source.masterKey, namespace));
  const signature = sign(
    fromBase64url(payload.ct),
    source.storedIdentity.encrypted_private_key,
    source.identityEncKey,
  );
  await source.storage.write(
    namespace,
    key,
    stringToBytes(
      JSON.stringify({
        v: 1,
        payload,
        ver: 1,
        sig: toBase64url(signature),
        kid: source.identityId,
        integrity_hash: hashToString(plaintext),
        metadata: { written_at: new Date().toISOString() },
      }),
    ),
  );
}

function forgedAgentOwnedStamp(
  namespace: string,
  key: string,
): NonNullable<StateEntry["provenance_stamp"]> {
  return {
    memory_class: "agent_owned",
    origin_actor: "agent",
    origin_ref: "forged-agent",
    lineage_id: `state:${namespace}/${key}:v1`,
    written_at: new Date().toISOString(),
    derived_from: [],
    entry_binding: `${namespace}/${key}`,
  };
}

async function readRawStateEntry(
  source: Source,
  namespace: string,
  key: string,
): Promise<StateEntry> {
  const raw = await source.storage.read(namespace, key);
  if (!raw) throw new Error(`missing state entry: ${namespace}/${key}`);
  return JSON.parse(bytesToString(raw)) as StateEntry;
}

async function injectTopLevelForgedProvenance(
  source: Source,
  namespace: string,
  key: string,
): Promise<StateEntry> {
  const entry = await readRawStateEntry(source, namespace, key);
  entry.provenance_stamp = forgedAgentOwnedStamp(namespace, key);
  await source.storage.write(namespace, key, stringToBytes(JSON.stringify(entry)));
  return entry;
}

async function readEncryptedStateArtifact(bundleDir: string): Promise<ExitEncryptedStateBundle> {
  return JSON.parse(
    await readFile(join(bundleDir, "artifacts", "encrypted_state.json"), "utf8"),
  ) as ExitEncryptedStateBundle;
}

describe("exit bundle conservative memory-class partition", () => {
  const tempDirs: string[] = [];
  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });
  async function newBundleDir(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-exit-partition-"));
    tempDirs.push(dir);
    return dir;
  }

  it("(a) includes a sealed agent_owned entry; (b) EXCLUDES an unsealed entry; never agent_owned by default", async () => {
    const source = await buildSource();
    await writeState(source, "agent-memory", "self-note", "agent self-model note");
    await writeLegacyUnstampedState(
      source,
      "agent-memory",
      "operator-doc",
      "operator's private document",
    );

    const bundleDir = await newBundleDir();
    const result = await exportExitBundle({
      bundleDir,
      storage: source.storage,
      masterKey: source.masterKey,
      identityManager: source.identityManager,
      auditLog: source.auditLog,
      reputationStore: source.reputationStore,
      policy: DEFAULT_POLICY,
      config: defaultConfig(),
      stateNamespaces: ["agent-memory"],
      keySource: "passphrase",
      mintStateRekeyKey: true,
      memoryClassPartition: {},
    });

    // Telemetry: 1 included, 1 excluded (the legacy unstamped operator doc).
    expect(result.state_partition).toEqual({
      included: 1,
      excluded: 1,
      excluded_unstamped: 1,
      excluded_unsealed: 0,
    });

    // The artifact on disk contains ONLY the agent-owned entry.
    const artifact = await readEncryptedStateArtifact(bundleDir);
    expect(artifact.total_keys).toBe(1);
    expect(artifact.entries.map((e) => e.key)).toEqual(["self-note"]);
    // The operator doc did not travel — fails toward staying with the operator.
    expect(artifact.entries.some((e) => e.key === "operator-doc")).toBe(false);

    // The bundle still verifies (signed manifest, hash-pinned artifacts).
    const verification = await verifyExitBundle(bundleDir);
    expect(verification.passed).toBe(true);
  });

  it("treats forged top-level provenance on a legacy v1 entry as unstamped and excludes it", async () => {
    const source = await buildSource();
    await writeLegacyUnstampedState(
      source,
      "agent-memory",
      "forged-v1",
      "legacy v1 payload",
    );
    const forgedEntry = await injectTopLevelForgedProvenance(
      source,
      "agent-memory",
      "forged-v1",
    );

    await expect(
      source.stateStore.remintVerifiedProvenanceStampForExport(
        forgedEntry,
        "agent-memory",
        "forged-v1",
      ),
    ).resolves.toEqual({ status: "unstamped" });

    const bundleDir = await newBundleDir();
    const result = await exportExitBundle({
      bundleDir,
      storage: source.storage,
      masterKey: source.masterKey,
      identityManager: source.identityManager,
      auditLog: source.auditLog,
      reputationStore: source.reputationStore,
      policy: DEFAULT_POLICY,
      config: defaultConfig(),
      stateNamespaces: ["agent-memory"],
      keySource: "passphrase",
      mintStateRekeyKey: false,
      memoryClassPartition: {},
    });

    expect(result.state_partition).toEqual({
      included: 0,
      excluded: 1,
      excluded_unstamped: 1,
      excluded_unsealed: 0,
    });
    const artifact = await readEncryptedStateArtifact(bundleDir);
    expect(artifact.total_keys).toBe(0);
    expect(artifact.entries).toHaveLength(0);
  });

  it("treats forged top-level provenance on a legacy v2 entry as unstamped and excludes it", async () => {
    const source = await buildSource();
    await writeLegacyUnstampedState(
      source,
      "agent-memory",
      "forged-v2",
      "legacy v2 payload",
    );

    // Verified reads migrate v1 ciphertext-only entries to legacy schema v2.
    await source.stateStore.read("agent-memory", "forged-v2");
    const forgedEntry = await injectTopLevelForgedProvenance(
      source,
      "agent-memory",
      "forged-v2",
    );
    expect(forgedEntry.v).toBe(2);
    expect(forgedEntry.envelope?.provenance_stamp).toBeUndefined();

    await expect(
      source.stateStore.remintVerifiedProvenanceStampForExport(
        forgedEntry,
        "agent-memory",
        "forged-v2",
      ),
    ).resolves.toEqual({ status: "unstamped" });

    const bundleDir = await newBundleDir();
    const result = await exportExitBundle({
      bundleDir,
      storage: source.storage,
      masterKey: source.masterKey,
      identityManager: source.identityManager,
      auditLog: source.auditLog,
      reputationStore: source.reputationStore,
      policy: DEFAULT_POLICY,
      config: defaultConfig(),
      stateNamespaces: ["agent-memory"],
      keySource: "passphrase",
      mintStateRekeyKey: false,
      memoryClassPartition: {},
    });

    expect(result.state_partition).toEqual({
      included: 0,
      excluded: 1,
      excluded_unstamped: 1,
      excluded_unsealed: 0,
    });
    const artifact = await readEncryptedStateArtifact(bundleDir);
    expect(artifact.total_keys).toBe(0);
    expect(artifact.entries).toHaveLength(0);
  });

  it("still honors legitimate schema-3 signed provenance in the partitioned export", async () => {
    const source = await buildSource();
    await writeState(source, "agent-memory", "schema3-agent", "schema 3 agent note");
    const entry = await readRawStateEntry(source, "agent-memory", "schema3-agent");

    const reminted = await source.stateStore.remintVerifiedProvenanceStampForExport(
      entry,
      "agent-memory",
      "schema3-agent",
    );
    expect(reminted.status).toBe("sealed");

    const bundleDir = await newBundleDir();
    const result = await exportExitBundle({
      bundleDir,
      storage: source.storage,
      masterKey: source.masterKey,
      identityManager: source.identityManager,
      auditLog: source.auditLog,
      reputationStore: source.reputationStore,
      policy: DEFAULT_POLICY,
      config: defaultConfig(),
      stateNamespaces: ["agent-memory"],
      keySource: "passphrase",
      mintStateRekeyKey: false,
      memoryClassPartition: {},
    });

    expect(result.state_partition).toEqual({
      included: 1,
      excluded: 0,
      excluded_unstamped: 0,
      excluded_unsealed: 0,
    });
    const artifact = await readEncryptedStateArtifact(bundleDir);
    expect(artifact.entries.map((e) => e.key)).toEqual(["schema3-agent"]);
  });

  it("(b) a sealed operator_owned or shared_entangled entry is EXCLUDED without consent", async () => {
    const source = await buildSource();
    await writeState(source, "agent-memory", "op-state", "operator working state", "operator");
    await writeSharedState(source, "agent-memory", "shared-summary", "summary of operator doc");

    const bundleDir = await newBundleDir();
    const result = await exportExitBundle({
      bundleDir,
      storage: source.storage,
      masterKey: source.masterKey,
      identityManager: source.identityManager,
      auditLog: source.auditLog,
      reputationStore: source.reputationStore,
      policy: DEFAULT_POLICY,
      config: defaultConfig(),
      stateNamespaces: ["agent-memory"],
      keySource: "passphrase",
      mintStateRekeyKey: false,
      memoryClassPartition: {},
    });

    expect(result.state_partition).toEqual({
      included: 0,
      excluded: 2,
      excluded_unstamped: 0,
      excluded_unsealed: 0,
    });
    const artifact = await readEncryptedStateArtifact(bundleDir);
    expect(artifact.total_keys).toBe(0);
    expect(artifact.entries).toHaveLength(0);
  });

  it("(c) an audited consent release lets a shared_entangled entry travel", async () => {
    const source = await buildSource();
    await writeSharedState(source, "agent-memory", "shared-summary", "summary of operator doc");

    const bundleDir = await newBundleDir();
    const result = await exportExitBundle({
      bundleDir,
      storage: source.storage,
      masterKey: source.masterKey,
      identityManager: source.identityManager,
      auditLog: source.auditLog,
      reputationStore: source.reputationStore,
      policy: DEFAULT_POLICY,
      config: defaultConfig(),
      stateNamespaces: ["agent-memory"],
      keySource: "passphrase",
      mintStateRekeyKey: true,
      memoryClassPartition: {
        consentReleases: [
          {
            lineage_id: "state:agent-memory/shared-summary:v1",
            memory_class: "shared_entangled",
            disposition: "released_to_agent",
          },
        ],
      },
    });

    expect(result.state_partition).toEqual({
      included: 1,
      excluded: 0,
      excluded_unstamped: 0,
      excluded_unsealed: 0,
    });
    const artifact = await readEncryptedStateArtifact(bundleDir);
    expect(artifact.entries.map((e) => e.key)).toEqual(["shared-summary"]);
  });

  it("verifies the signed envelope before re-minting provenance at export", async () => {
    const source = await buildSource();
    await writeState(source, "agent-memory", "op-state", "operator working state", "operator");

    const raw = await source.storage.read("agent-memory", "op-state");
    if (!raw) throw new Error("missing op-state");
    const entry = JSON.parse(bytesToString(raw)) as {
      provenance_stamp: Record<string, unknown>;
      envelope: { provenance_stamp: Record<string, unknown> };
    };
    entry.provenance_stamp = {
      ...entry.provenance_stamp,
      origin_actor: "agent",
      memory_class: "agent_owned",
    };
    entry.envelope.provenance_stamp = entry.provenance_stamp;
    await source.storage.write(
      "agent-memory",
      "op-state",
      stringToBytes(JSON.stringify(entry)),
    );

    const bundleDir = await newBundleDir();
    const result = await exportExitBundle({
      bundleDir,
      storage: source.storage,
      masterKey: source.masterKey,
      identityManager: source.identityManager,
      auditLog: source.auditLog,
      reputationStore: source.reputationStore,
      policy: DEFAULT_POLICY,
      config: defaultConfig(),
      stateNamespaces: ["agent-memory"],
      keySource: "passphrase",
      mintStateRekeyKey: false,
      memoryClassPartition: {},
    });

    expect(result.state_partition).toEqual({
      included: 0,
      excluded: 1,
      excluded_unstamped: 0,
      excluded_unsealed: 0,
    });
    const artifact = await readEncryptedStateArtifact(bundleDir);
    expect(artifact.total_keys).toBe(0);
    expect(artifact.entries).toHaveLength(0);
  });

  it("an export that supplies NEITHER partition nor the legacy opt-out THROWS (no silent skip)", async () => {
    const source = await buildSource();
    await writeState(source, "agent-memory", "a", "alpha");

    const bundleDir = await newBundleDir();
    await expect(
      exportExitBundle({
        bundleDir,
        storage: source.storage,
        masterKey: source.masterKey,
        identityManager: source.identityManager,
        auditLog: source.auditLog,
        reputationStore: source.reputationStore,
        policy: DEFAULT_POLICY,
        config: defaultConfig(),
        stateNamespaces: ["agent-memory"],
        keySource: "passphrase",
        mintStateRekeyKey: true,
        // Neither memoryClassPartition nor unpartitionedLegacyExport.
      }),
    ).rejects.toThrow(/exactly one of memoryClassPartition or unpartitionedLegacyExport/);
  });

  it("the LOUD, named legacy opt-out exports all state (deliberate full-fortress export)", async () => {
    const source = await buildSource();
    await writeState(source, "agent-memory", "a", "alpha");
    await writeState(source, "agent-memory", "b", "beta");

    const bundleDir = await newBundleDir();
    const result = await exportExitBundle({
      bundleDir,
      storage: source.storage,
      masterKey: source.masterKey,
      identityManager: source.identityManager,
      auditLog: source.auditLog,
      reputationStore: source.reputationStore,
      policy: DEFAULT_POLICY,
      config: defaultConfig(),
      stateNamespaces: ["agent-memory"],
      keySource: "passphrase",
      mintStateRekeyKey: true,
      unpartitionedLegacyExport: true,
    });

    expect(result.state_partition).toBeUndefined();
    const artifact = await readEncryptedStateArtifact(bundleDir);
    expect(artifact.entries.map((e) => e.key).sort()).toEqual(["a", "b"]);
  });
});
