import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultConfig } from "../../../../server/src/config.js";
import { fromBase64url, stringToBytes } from "../../../../server/src/core/encoding.js";
import { generateRandomKey } from "../../../../server/src/core/random.js";
import { AuditLog } from "../../../../server/src/operational/audit-log.js";
import { StateStore } from "../../../../server/src/cognitive/state-store.js";
import { createL1Tools } from "../../../../server/src/cognitive/tools.js";
import { createL4Tools } from "../../../../server/src/reputation/tools.js";
import { ReputationStore } from "../../../../server/src/reputation/reputation-store.js";
import { DEFAULT_POLICY } from "../../../../server/src/principal-policy/loader.js";
import { exportExitBundle, importExitBundle, verifyExitBundle } from "../../../../server/src/exit/index.js";
import { MemoryStorage } from "../../../../server/src/storage/memory.js";
import { registerFixture } from "../../registry.js";
import { captureError, outcome } from "./helpers.js";

const CLAIM_ID = "12";
const CLAIM_LABEL = "Export / exit bundle";

// Entrypoints: exportExitBundle, verifyExitBundle, and importExitBundle in server/src/exit/index.ts.
// Mirrored tests: server/test/exit/exit-bundle.test.ts and server/test/drills/v1.1-exit-drill.test.ts.
// Matrix claim: Export / exit bundle.

type ToolResult = { content: Array<{ type: string; text: string }> };
type Tool = {
  name: string;
  handler: (args: Record<string, unknown>) => Promise<ToolResult>;
};

async function callTool(
  tools: Tool[],
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

async function makeHarness() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  const { tools: l1Tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  await identityManager.load();
  const { tools: l4Tools, reputationStore } = createL4Tools(
    storage,
    masterKey,
    identityManager,
    auditLog
  );
  return {
    storage,
    masterKey,
    auditLog,
    stateStore,
    identityManager,
    reputationStore,
    tools: [...l1Tools, ...l4Tools] as Tool[],
  };
}

async function seedSource() {
  const source = await makeHarness();
  const identity = await callTool(source.tools, "identity_create", { label: "source-agent" });
  const identityId = identity.identity_id as string;
  await callTool(source.tools, "state_write", {
    namespace: "agent-memory",
    key: "handoff",
    value: "durable state survives exit",
    identity_id: identityId,
  });
  await callTool(source.tools, "reputation_record", {
    interaction_id: "exit-synthetic-001",
    counterparty_did: "did:key:counterparty",
    outcome: { type: "transaction", result: "completed", metrics: { score: 100 } },
    context: "exit-synthetic",
    identity_id: identityId,
  });
  source.auditLog.append("l1", "exit_synthetic_source_unwrap", identityId, {
    harness: "synthetic",
  });
  return { source, identityId };
}

async function exportSeededBundle(bundleDir: string) {
  const { source, identityId } = await seedSource();
  await exportExitBundle({
    bundleDir,
    storage: source.storage,
    masterKey: source.masterKey,
    identityManager: source.identityManager,
    auditLog: source.auditLog,
    reputationStore: source.reputationStore,
    policy: DEFAULT_POLICY,
    config: defaultConfig(),
    stateNamespaces: ["agent-memory"],
    keySource: "recovery-key",
    // Full-fortress export fixture: ownership partition (exit Slice 1)
    // deliberately not applied. Named acknowledgement, not a silent skip.
    unpartitionedLegacyExport: true,
  });
  return { source, identityId };
}

async function withBundleDir<T>(prefix: string, fn: (bundleDir: string) => Promise<T>): Promise<T> {
  const bundleDir = await mkdtemp(join(tmpdir(), prefix));
  try {
    return await fn(bundleDir);
  } finally {
    await rm(bundleDir, { recursive: true, force: true });
  }
}

async function importToDestination(bundleDir: string, source: Awaited<ReturnType<typeof makeHarness>>) {
  const destination = await makeHarness();
  const destinationIdentity = await callTool(destination.tools, "identity_create", {
    label: "destination-import-signer",
  });
  const imported = await importExitBundle({
    bundleDir,
    storage: destination.storage,
    masterKey: destination.masterKey,
    identityManager: destination.identityManager,
    auditLog: destination.auditLog,
    reputationStore: destination.reputationStore,
    activate: true,
    forceRebind: true,
    sourceMasterKey: source.masterKey,
    destinationSignerIdentityId: destinationIdentity.identity_id as string,
  });
  return { destination, destinationIdentityId: destinationIdentity.identity_id as string, imported };
}

registerFixture(CLAIM_ID, CLAIM_LABEL, "exit-bundle: export then offline-verify happy path", async () => {
  const started = performance.now();
  const passed = await withBundleDir("sanctuary-synth-exit-verify-", async (bundleDir) => {
    await exportSeededBundle(bundleDir);
    const verified = await verifyExitBundle(bundleDir);
    return verified.passed === true && verified.failure_class === undefined;
  });
  return outcome(started, passed, "expected verifier PASS for exported bundle");
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "exit-bundle: import to fresh fortress dir", async () => {
  const started = performance.now();
  const passed = await withBundleDir("sanctuary-synth-exit-import-", async (bundleDir) => {
    const { source } = await exportSeededBundle(bundleDir);
    const { destination, imported } = await importToDestination(bundleDir, source);
    const read = await destination.stateStore.read("agent-memory", "handoff");
    return imported.activated && read?.value === "durable state survives exit";
  });
  return outcome(started, passed, "expected imported state to load in fresh destination");
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "exit-bundle: re-key after import", async () => {
  const started = performance.now();
  const passed = await withBundleDir("sanctuary-synth-exit-rekey-", async (bundleDir) => {
    const { source, identityId } = await exportSeededBundle(bundleDir);
    const { destination, destinationIdentityId, imported } = await importToDestination(bundleDir, source);
    const sourcePub = source.identityManager.get(identityId)!.public_key;
    const sourcePubBytes = fromBase64url(sourcePub);
    const read = await destination.stateStore.read("agent-memory", "handoff");
    const oldKeyErr = await captureError(() =>
      destination.stateStore.read("agent-memory", "handoff", sourcePubBytes)
    );
    return (
      imported.state.status === "rekeyed" &&
      imported.state.imported_keys === 1 &&
      read?.written_by === destinationIdentityId &&
      oldKeyErr instanceof Error &&
      /Signature verification failed/.test(oldKeyErr.message)
    );
  });
  return outcome(started, passed, "expected imported state to be re-keyed to destination signer");
});

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "exit-bundle: conflict-refusal on import into populated dir",
  async () => {
    const started = performance.now();
    const passed = await withBundleDir("sanctuary-synth-exit-conflict-", async (bundleDir) => {
      const { source } = await exportSeededBundle(bundleDir);
      const manifest = JSON.parse(await readFile(join(bundleDir, "manifest.json"), "utf8")) as {
        body: { exported_at: string; identity_binding: { identity_id: string } };
      };
      const importId = `${manifest.body.identity_binding.identity_id}-${manifest.body.exported_at.replace(/[^0-9a-zA-Z_.-]/g, "_")}`;
      const destination = await makeHarness();
      await destination.storage.write("_exit_policy_sets", importId, stringToBytes("{}"));
      const err = await captureError(() =>
        importExitBundle({
          bundleDir,
          storage: destination.storage,
          masterKey: destination.masterKey,
          identityManager: destination.identityManager,
          auditLog: destination.auditLog,
          reputationStore: destination.reputationStore,
          activate: true,
          sourceMasterKey: source.masterKey,
        })
      );
      return err instanceof Error && "code" in err && err.code === "STAGED_ARTIFACT_CONFLICT";
    });
    return outcome(started, passed, "expected populated destination import refusal");
  }
);

registerFixture(CLAIM_ID, CLAIM_LABEL, "exit-bundle: source-key cleanup after re-key", async () => {
  const started = performance.now();
  const passed = await withBundleDir("sanctuary-synth-exit-cleanup-", async (bundleDir) => {
    const { source, identityId } = await exportSeededBundle(bundleDir);
    const { destination } = await importToDestination(bundleDir, source);
    const namespaces = [
      "_staging",
      "_rekey_temp",
      "_source_keys",
      "_exit_source_keys",
    ];
    const noSourceKeyNamespaces = (
      await Promise.all(namespaces.map(async (namespace) => destination.storage.list(namespace)))
    ).every((entries) => entries.length === 0);
    const sourcePubBytes = fromBase64url(source.identityManager.get(identityId)!.public_key);
    const oldKeyErr = await captureError(() =>
      destination.stateStore.read("agent-memory", "handoff", sourcePubBytes)
    );
    const reputation = new ReputationStore(destination.storage, destination.masterKey);
    const rep = await reputation.query({ context: "exit-synthetic" });
    return (
      noSourceKeyNamespaces &&
      oldKeyErr instanceof Error &&
      /Signature verification failed/.test(oldKeyErr.message) &&
      rep.total_interactions === 1
    );
  });
  return outcome(started, passed, "expected no source-key residue after re-key");
});
