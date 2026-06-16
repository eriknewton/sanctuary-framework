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
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import {
  exportExitBundle,
  verifyExitBundle,
  mintProvenanceStamp,
  type ExitEncryptedStateBundle,
  type SealedProvenanceStamp,
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
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  const { tools: l1Tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "passphrase",
    auditLog,
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
  return {
    storage,
    masterKey,
    auditLog,
    stateStore,
    identityManager,
    reputationStore,
    tools: [...l1Tools, ...l4Tools],
    identityId,
  };
}

type Source = Awaited<ReturnType<typeof buildSource>>;

async function writeState(source: Source, namespace: string, key: string, value: string) {
  await callTool(source.tools, "state_write", {
    namespace,
    key,
    value,
    identity_id: source.identityId,
  });
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
    await writeState(source, "agent-memory", "operator-doc", "operator's private document");

    // The agent-owned entry gets a sealed agent_owned stamp; the operator doc
    // gets NO stamp (the un-instrumented path — exactly the bypass M-1 warns of).
    const stampsByEntryKey = new Map<string, SealedProvenanceStamp>([
      [
        "agent-memory/self-note",
        mintProvenanceStamp({
          origin_actor: "agent",
          origin_ref: source.identityId,
          lineage_id: "lin-self-note",
          entry_binding: "agent-memory/self-note",
        }),
      ],
    ]);

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
      memoryClassPartition: { stampsByEntryKey },
    });

    // Telemetry: 1 included, 1 excluded (the unsealed operator doc).
    expect(result.state_partition).toEqual({
      included: 1,
      excluded: 1,
      excluded_unsealed: 1,
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

  it("(b) a sealed operator_owned or shared_entangled entry is EXCLUDED without consent", async () => {
    const source = await buildSource();
    await writeState(source, "agent-memory", "op-state", "operator working state");
    await writeState(source, "agent-memory", "shared-summary", "summary of operator doc");

    const stampsByEntryKey = new Map<string, SealedProvenanceStamp>([
      [
        "agent-memory/op-state",
        mintProvenanceStamp({
          origin_actor: "operator",
          origin_ref: source.identityId,
          lineage_id: "lin-op",
          entry_binding: "agent-memory/op-state",
        }),
      ],
      [
        "agent-memory/shared-summary",
        mintProvenanceStamp({
          origin_actor: "agent",
          origin_ref: source.identityId,
          lineage_id: "lin-shared",
          entry_binding: "agent-memory/shared-summary",
          derived_from: [{ lineage_id: "lin-op", memory_class: "operator_owned" }],
        }),
      ],
    ]);

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
      memoryClassPartition: { stampsByEntryKey },
    });

    expect(result.state_partition).toEqual({
      included: 0,
      excluded: 2,
      excluded_unsealed: 0,
    });
    const artifact = await readEncryptedStateArtifact(bundleDir);
    expect(artifact.total_keys).toBe(0);
    expect(artifact.entries).toHaveLength(0);
  });

  it("(c) an audited consent release lets a shared_entangled entry travel", async () => {
    const source = await buildSource();
    await writeState(source, "agent-memory", "shared-summary", "summary of operator doc");

    const stampsByEntryKey = new Map<string, SealedProvenanceStamp>([
      [
        "agent-memory/shared-summary",
        mintProvenanceStamp({
          origin_actor: "agent",
          origin_ref: source.identityId,
          lineage_id: "lin-shared",
          entry_binding: "agent-memory/shared-summary",
          derived_from: [{ lineage_id: "lin-op", memory_class: "operator_owned" }],
        }),
      ],
    ]);

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
        stampsByEntryKey,
        consentReleases: [
          {
            lineage_id: "lin-shared",
            memory_class: "shared_entangled",
            disposition: "released_to_agent",
          },
        ],
      },
    });

    expect(result.state_partition).toEqual({
      included: 1,
      excluded: 0,
      excluded_unsealed: 0,
    });
    const artifact = await readEncryptedStateArtifact(bundleDir);
    expect(artifact.entries.map((e) => e.key)).toEqual(["shared-summary"]);
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
