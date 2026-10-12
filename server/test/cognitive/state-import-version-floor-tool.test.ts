/**
 * state_import enforces durable version floors through the MCP tool path.
 *
 * STATE-IMPORT-VERSION-FLOOR-01
 */

import { describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { createCognitiveTools } from "../../src/cognitive/tools.js";
import {
  STATE_META_VERSION_ANCHORS_KEY,
  StateImportPartialApplyError,
  StateVerificationError,
  StateStore,
  isStateVersionFloorRefusal,
} from "../../src/cognitive/state-store.js";
import type { StoredIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { createServer, type ToolDefinition } from "../../src/router.js";
import { EXIT_IMPORT_JOURNAL_NAMESPACE } from "../../src/storage/exit-import-journal.js";
import { MemoryStorage } from "../../src/storage/memory.js";

type ToolPayload = Record<string, unknown>;

const READ_TOOLS = new Set(["state_read"]);
const HMAC_SHA256_BYTE_LENGTH = 32;
const CONCURRENT_WRITE_BLOCKED_PROBE_MS = 25;
// Must match FACADE_HIDDEN_MARKER_NAMESPACE in src/cognitive/state-store.ts.
const FACADE_HIDDEN_MARKER_NAMESPACE = "_facade/hidden";

class HookedMemoryStorage extends MemoryStorage {
  beforeWrite: ((namespace: string, key: string) => Promise<void>) | undefined;
  onWrite: ((namespace: string, key: string) => Promise<void>) | undefined;

  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    await this.beforeWrite?.(namespace, key);
    await super.write(namespace, key, data);
    await this.onWrite?.(namespace, key);
  }
}

function selectedTools(
  tools: ToolDefinition[],
  names: string[]
): ToolDefinition[] {
  const wanted = new Set(names);
  return tools
    .filter((tool) => wanted.has(tool.name))
    .map((tool) => ({
      ...tool,
      tool_class: READ_TOOLS.has(tool.name) ? "read" as const : "write" as const,
    }));
}

function parseToolPayload(
  result: Awaited<ReturnType<Client["callTool"]>>
): ToolPayload {
  const content = result.content;
  if (!Array.isArray(content) || content[0]?.type !== "text") {
    throw new Error("tool returned no text payload");
  }
  return JSON.parse(content[0].text) as ToolPayload;
}

async function callTool(
  client: Client,
  name: string,
  args: Record<string, unknown>
): Promise<ToolPayload> {
  return parseToolPayload(await client.callTool({ name, arguments: args }));
}

interface ToolRig {
  client: Client;
  close: () => Promise<void>;
  identityManager: ReturnType<typeof createCognitiveTools>["identityManager"];
  auditLog: AuditLog;
  stateStore: StateStore;
  storage: MemoryStorage;
  masterKey: Uint8Array;
  identityEncKey: Uint8Array;
}

async function makeToolRig(storage: MemoryStorage = new MemoryStorage()): Promise<ToolRig> {
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const { tools, identityManager } = createCognitiveTools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  await identityManager.load();

  const baseline = new BaselineTracker(storage, masterKey);
  await baseline.load();
  const gate = new ApprovalGate(
    DEFAULT_POLICY,
    baseline,
    new CallbackApprovalChannel(async () => ({
      decision: "approve",
      decided_at: new Date().toISOString(),
      decided_by: "human",
    })),
    auditLog
  );

  const server = createServer(
    selectedTools(tools, [
      "identity_create",
      "state_write",
      "state_export",
      "state_import",
      "state_read",
    ]),
    { gate, auditLog }
  );
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({
    name: "state-import-version-floor-tool-test",
    version: "1.0.0",
  });
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  return {
    client,
    identityManager,
    auditLog,
    stateStore,
    storage,
    masterKey,
    identityEncKey,
    close: async () => {
      await client.close().catch(() => {});
      await server.close().catch(() => {});
    },
  };
}

function decodeBundle(bundleBase64: string): Record<string, unknown> {
  return JSON.parse(bytesToString(fromBase64url(bundleBase64))) as Record<
    string,
    unknown
  >;
}

function encodeBundle(bundle: Record<string, unknown>): string {
  return toBase64url(stringToBytes(JSON.stringify(bundle)));
}

function stripCompleteness(bundleBase64: string): string {
  const decoded = decodeBundle(bundleBase64);
  delete decoded.completeness_manifest;
  delete decoded.bundle_integrity;
  return encodeBundle(decoded);
}

function duplicateFirstEntry(bundleBase64: string): string {
  const decoded = decodeBundle(bundleBase64);
  const data = decoded.data;
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("missing bundle data");
  }
  const entries = (data as Record<string, unknown>).notes;
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error("missing notes entry");
  }
  entries.push(JSON.parse(JSON.stringify(entries[0])));
  delete decoded.completeness_manifest;
  delete decoded.bundle_integrity;
  return encodeBundle(decoded);
}

function exportedEntry(bundleBase64: string, key: string): unknown {
  const decoded = decodeBundle(bundleBase64);
  const data = decoded.data;
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("missing bundle data");
  }
  const entries = (data as Record<string, unknown>).notes;
  if (!Array.isArray(entries)) throw new Error("missing notes entry");
  const item = entries.find((candidate) => {
    return (
      candidate &&
      typeof candidate === "object" &&
      !Array.isArray(candidate) &&
      (candidate as Record<string, unknown>).key === key
    );
  });
  if (!item || typeof item !== "object" || Array.isArray(item)) {
    throw new Error("missing requested entry");
  }
  return (item as Record<string, unknown>).entry;
}

async function wait(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

function replaceBundleIntegrityMac(bundleBase64: string): string {
  const decoded = decodeBundle(bundleBase64);
  const integrity = decoded.bundle_integrity;
  if (!integrity || typeof integrity !== "object" || Array.isArray(integrity)) {
    throw new Error("missing bundle integrity");
  }
  (integrity as Record<string, unknown>).mac = toBase64url(
    new Uint8Array(HMAC_SHA256_BYTE_LENGTH)
  );
  return encodeBundle(decoded);
}

async function versionAnchorBytes(storage: MemoryStorage): Promise<string | null> {
  const raw = await storage.read("_meta", STATE_META_VERSION_ANCHORS_KEY);
  return raw ? bytesToString(raw) : null;
}

async function createIdentity(client: Client): Promise<string> {
  const identity = await callTool(client, "identity_create", {
    label: "version-floor-writer",
  });
  return identity.identity_id as string;
}

async function writeValue(
  client: Client,
  identityId: string,
  key: string,
  value: string
): Promise<void> {
  await callTool(client, "state_write", {
    namespace: "notes",
    key,
    value,
    identity_id: identityId,
  });
}

async function readValue(
  client: Client,
  key: string
): Promise<ToolPayload> {
  return callTool(client, "state_read", {
    namespace: "notes",
    key,
  });
}

async function sourceBundle(args: {
  masterKey: Uint8Array;
  identityEncKey: Uint8Array;
  identity: StoredIdentity;
  values: Array<{ key: string; value: string }>;
  facadeHiddenMarkers?: Array<{ key: string; marker: { namespace: string; key: string } }>;
}): Promise<string> {
  const sourceStorage = new MemoryStorage();
  const sourceStore = new StateStore(sourceStorage, args.masterKey);
  for (const item of args.values) {
    await sourceStore.write(
      "notes",
      item.key,
      item.value,
      args.identity.identity_id,
      args.identity.encrypted_private_key,
      args.identityEncKey
    );
  }
  for (const item of args.facadeHiddenMarkers ?? []) {
    await sourceStorage.write(
      FACADE_HIDDEN_MARKER_NAMESPACE,
      item.key,
      stringToBytes(JSON.stringify(item.marker))
    );
  }
  return (await sourceStore.exportNamespaces(["notes"])).bundle;
}

describe("state_import version floor tool path", () => {
  it("continues when the imported key has no established floor", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      const bundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [{ key: "absent", value: "first" }],
      });

      const imported = await callTool(rig.client, "state_import", {
        bundle,
        conflict_resolution: "overwrite",
      });
      expect(imported.imported_keys).toBe(1);

      const current = await readValue(rig.client, "absent");
      expect(current.value).toBe("first");
      expect(current.version).toBe(1);
    } finally {
      await rig.close();
    }
  });

  it("continues when the imported key is at the established floor", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      await writeValue(rig.client, identityId, "equal", "first");
      const exported = await callTool(rig.client, "state_export", {
        namespace: "notes",
      });

      const imported = await callTool(rig.client, "state_import", {
        bundle: exported.bundle,
        conflict_resolution: "overwrite",
      });
      expect(imported.imported_keys).toBe(1);

      const current = await readValue(rig.client, "equal");
      expect(current.value).toBe("first");
      expect(current.version).toBe(1);
    } finally {
      await rig.close();
    }
  });

  it("continues when the imported key advances the established floor", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      await writeValue(rig.client, identityId, "above", "first");
      const bundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [
          { key: "above", value: "first" },
          { key: "above", value: "second" },
        ],
      });

      const imported = await callTool(rig.client, "state_import", {
        bundle,
        conflict_resolution: "overwrite",
      });
      expect(imported.imported_keys).toBe(1);

      const current = await readValue(rig.client, "above");
      expect(current.value).toBe("second");
      expect(current.version).toBe(2);
    } finally {
      await rig.close();
    }
  });

  it("refuses a bundle below an established floor before changing state", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      await writeValue(rig.client, identityId, "below", "first");
      const oldExport = await callTool(rig.client, "state_export", {
        namespace: "notes",
      });

      await writeValue(rig.client, identityId, "below", "second");

      const refusedImport = await callTool(rig.client, "state_import", {
        bundle: oldExport.bundle,
        conflict_resolution: "overwrite",
      });
      expect(refusedImport.denied).toBe(true);

      const currentRead = await readValue(rig.client, "below");
      expect(currentRead.value).toBe("second");
      expect(currentRead.version).toBe(2);
    } finally {
      await rig.close();
    }
  });

  it("records an import attempt before the first import mutation", async () => {
    const storage = new HookedMemoryStorage();
    const rig = await makeToolRig(storage);
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      const bundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [{ key: "attempt-before-write", value: "imported" }],
      });

      let attemptSeenDuringWrite = false;
      let successSeenDuringWrite = false;
      storage.onWrite = async (namespace, key) => {
        if (namespace !== "notes" || key !== "attempt-before-write") return;
        attemptSeenDuringWrite = (await rig.auditLog.query({
          operation_type: "state_import_attempt",
          limit: 10,
        })).entries.length === 1;
        successSeenDuringWrite = (await rig.auditLog.query({
          operation_type: "state_import",
          limit: 10,
        })).entries.length > 0;
      };

      const imported = await callTool(rig.client, "state_import", {
        bundle,
        conflict_resolution: "overwrite",
      });
      expect(imported.imported_keys).toBe(1);
      expect(attemptSeenDuringWrite).toBe(true);
      expect(successSeenDuringWrite).toBe(false);
      expect((await rig.auditLog.query({
        operation_type: "state_import_attempt",
        limit: 10,
      })).entries).toHaveLength(1);
      expect((await rig.auditLog.query({
        operation_type: "state_import",
        limit: 10,
      })).entries).toHaveLength(1);
    } finally {
      storage.onWrite = undefined;
      await rig.close();
    }
  });

  it("aborts import before mutation when the attempt audit cannot be recorded", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      const bundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [{ key: "attempt-audit-abort", value: "imported" }],
      });
      const appendCritical = rig.auditLog.appendCritical.bind(rig.auditLog);
      const appendSpy = vi
        .spyOn(rig.auditLog, "appendCritical")
        .mockImplementation(async (entry) => {
          if (entry.operation === "state_import_attempt") {
            throw new Error("injected attempt audit refusal");
          }
          return appendCritical(entry);
        });

      const result = await rig.client.callTool({
        name: "state_import",
        arguments: { bundle, conflict_resolution: "overwrite" },
      });
      expect(result.isError).toBe(true);
      expect(parseToolPayload(result).error).toBe("tool execution failed");
      expect(await rig.storage.read("notes", "attempt-audit-abort")).toBeNull();
      appendSpy.mockRestore();
    } finally {
      await rig.close();
    }
  });

  it("refuses a mixed bundle before changing any entry", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      await writeValue(rig.client, identityId, "mixed-a", "first");
      await writeValue(rig.client, identityId, "mixed-a", "second");

      const mixedBundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [
          { key: "mixed-a", value: "first" },
          { key: "mixed-b", value: "first" },
          { key: "mixed-b", value: "second" },
        ],
      });

      const refusedImport = await callTool(rig.client, "state_import", {
        bundle: mixedBundle,
        conflict_resolution: "overwrite",
      });
      expect(refusedImport.denied).toBe(true);

      const currentA = await readValue(rig.client, "mixed-a");
      expect(currentA.value).toBe("second");
      expect(currentA.version).toBe(2);
      const missingB = await readValue(rig.client, "mixed-b");
      expect(missingB.denied).toBe(true);
      expect(missingB.value).toBeUndefined();
    } finally {
      await rig.close();
    }
  });

  it("skip mode restores write candidates without checking skipped entries", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      await writeValue(rig.client, identityId, "kept", "first");
      await writeValue(rig.client, identityId, "restore-me", "first");
      const oldExport = await callTool(rig.client, "state_export", {
        namespace: "notes",
      });

      await writeValue(rig.client, identityId, "kept", "second");
      await rig.stateStore.delete("notes", "restore-me");
      const floorBefore = await versionAnchorBytes(rig.storage);

      const imported = await callTool(rig.client, "state_import", {
        bundle: oldExport.bundle,
        conflict_resolution: "skip",
      });
      expect(imported.denied).toBeUndefined();
      expect(imported.imported_keys).toBe(1);
      expect(imported.skipped_keys).toBe(1);

      const kept = await readValue(rig.client, "kept");
      expect(kept.value).toBe("second");
      expect(kept.version).toBe(2);
      const restored = await readValue(rig.client, "restore-me");
      expect(restored.value).toBe("first");
      expect(restored.version).toBe(1);
      await expect(versionAnchorBytes(rig.storage)).resolves.toBe(floorBefore);
    } finally {
      await rig.close();
    }
  });

  it("version mode restores write candidates without checking entries that are not newer", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      await writeValue(rig.client, identityId, "kept-version", "first");
      await writeValue(rig.client, identityId, "restore-version", "first");
      const oldExport = await callTool(rig.client, "state_export", {
        namespace: "notes",
      });

      await writeValue(rig.client, identityId, "kept-version", "second");
      await rig.stateStore.delete("notes", "restore-version");
      const floorBefore = await versionAnchorBytes(rig.storage);

      const imported = await callTool(rig.client, "state_import", {
        bundle: oldExport.bundle,
        conflict_resolution: "version",
      });
      expect(imported.denied).toBeUndefined();
      expect(imported.imported_keys).toBe(1);
      expect(imported.skipped_keys).toBe(1);

      const kept = await readValue(rig.client, "kept-version");
      expect(kept.value).toBe("second");
      expect(kept.version).toBe(2);
      const restored = await readValue(rig.client, "restore-version");
      expect(restored.value).toBe("first");
      expect(restored.version).toBe(1);
      await expect(versionAnchorBytes(rig.storage)).resolves.toBe(floorBefore);
    } finally {
      await rig.close();
    }
  });

  it("records the operator-side reason when import verification refuses", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      await writeValue(rig.client, identityId, "audit-floor", "first");
      const oldExport = await callTool(rig.client, "state_export", {
        namespace: "notes",
      });
      await writeValue(rig.client, identityId, "audit-floor", "second");

      const refused = await callTool(rig.client, "state_import", {
        bundle: oldExport.bundle,
        conflict_resolution: "overwrite",
      });
      expect(refused.denied).toBe(true);
      expect(refused.classification).toBeUndefined();

      const audit = await rig.auditLog.query({
        operation_type: "state_import_verification_failed",
        limit: 10,
      });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]?.result).toBe("failure");
      expect(audit.entries[0]?.details?.classification).toBe(
        "rollback_detected"
      );
      expect(typeof audit.entries[0]?.details?.reason).toBe("string");

      const success = await rig.auditLog.query({
        operation_type: "state_import",
        limit: 10,
      });
      expect(success.entries).toHaveLength(0);
    } finally {
      await rig.close();
    }
  });

  it("keeps the legacy-bundle operator hint while returning a generic denial", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      await writeValue(rig.client, identityId, "legacy-audit", "first");
      const exported = await callTool(rig.client, "state_export", {
        namespace: "notes",
      });

      const refused = await callTool(rig.client, "state_import", {
        bundle: stripCompleteness(exported.bundle as string),
      });
      expect(refused.denied).toBe(true);
      expect(JSON.stringify(refused)).not.toContain("allow_unverified_legacy");

      const audit = await rig.auditLog.query({
        operation_type: "state_import_verification_failed",
        limit: 10,
      });
      expect(audit.entries).toHaveLength(1);
      expect(typeof audit.entries[0]?.details?.classification).toBe("string");
      expect(audit.entries[0]?.details?.reason).toContain(
        "allow_unverified_legacy"
      );
    } finally {
      await rig.close();
    }
  });

  it("keeps the bundle-integrity operator reason while returning a generic denial", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      await writeValue(rig.client, identityId, "integrity-audit", "first");
      const exported = await callTool(rig.client, "state_export", {
        namespace: "notes",
      });

      const refused = await callTool(rig.client, "state_import", {
        bundle: replaceBundleIntegrityMac(exported.bundle as string),
      });
      expect(refused.denied).toBe(true);
      expect(JSON.stringify(refused)).not.toContain("integrity");

      const audit = await rig.auditLog.query({
        operation_type: "state_import_verification_failed",
        limit: 10,
      });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]?.details?.classification).toBe(
        "integrity_hash_mismatch"
      );
      expect(audit.entries[0]?.details?.reason).toContain("integrity");
    } finally {
      await rig.close();
    }
  });

  it("StateStore.import directly refuses entries below the stored floor", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      await writeValue(rig.client, identityId, "direct-floor", "first");
      const oldExport = await callTool(rig.client, "state_export", {
        namespace: "notes",
      });
      await writeValue(rig.client, identityId, "direct-floor", "second");

      await expect(
        rig.stateStore.import(
          oldExport.bundle as string,
          "overwrite",
          (kid) =>
            kid === identity.identity_id
              ? fromBase64url(identity.public_key)
              : null
        )
      ).rejects.toMatchObject({ classification: "rollback_detected" });

      const current = await readValue(rig.client, "direct-floor");
      expect(current.value).toBe("second");
      expect(current.version).toBe(2);
    } finally {
      await rig.close();
    }
  });

  it("StateStore.import refuses a mixed bundle before writing earlier valid candidates", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      await writeValue(rig.client, identityId, "direct-low", "first");
      await writeValue(rig.client, identityId, "direct-low", "second");
      const mixedBundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [
          { key: "direct-good", value: "first" },
          { key: "direct-good", value: "second" },
          { key: "direct-low", value: "first" },
        ],
      });

      await expect(
        rig.stateStore.import(
          mixedBundle,
          "overwrite",
          (kid) =>
            kid === identity.identity_id
              ? fromBase64url(identity.public_key)
              : null
        )
      ).rejects.toMatchObject({ classification: "rollback_detected" });

      const missingGood = await readValue(rig.client, "direct-good");
      expect(missingGood.denied).toBe(true);
      const currentLow = await readValue(rig.client, "direct-low");
      expect(currentLow.value).toBe("second");
      expect(currentLow.version).toBe(2);
    } finally {
      await rig.close();
    }
  });

  it("readExportData refuses duplicate keys before planning writes", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      const bundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [{ key: "duplicated", value: "first" }],
      });

      await expect(
        rig.stateStore.import(
          duplicateFirstEntry(bundle),
          "overwrite",
          (kid) =>
            kid === identity.identity_id
              ? fromBase64url(identity.public_key)
              : null,
          { allowUnverifiedLegacy: true }
        )
      ).rejects.toMatchObject({ classification: "schema_mismatch" });

      const missing = await readValue(rig.client, "duplicated");
      expect(missing.denied).toBe(true);
    } finally {
      await rig.close();
    }
  });

  it("StateStore.import serializes a two-key import against a concurrent local write", async () => {
    const storage = new HookedMemoryStorage();
    const rig = await makeToolRig(storage);
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      await writeValue(rig.client, identityId, "race-second", "first");
      const bundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [
          { key: "race-first", value: "imported" },
          { key: "race-second", value: "first" },
          { key: "race-second", value: "second" },
        ],
      });

      let concurrentWrite: Promise<unknown> | undefined;
      let anchorRaised = false;
      storage.onWrite = async (namespace, key) => {
        if (namespace === "notes" && key === "race-first" && !concurrentWrite) {
          concurrentWrite = rig.stateStore.write(
            "notes",
            "race-second",
            "concurrent",
            identity.identity_id,
            identity.encrypted_private_key,
            rig.identityEncKey
          );
          const settled = await Promise.race([
            concurrentWrite.then(() => "settled" as const),
            wait(CONCURRENT_WRITE_BLOCKED_PROBE_MS).then(() => "blocked" as const),
          ]);
          anchorRaised = settled === "settled";
        }
      };

      await expect(
        rig.stateStore.import(
          bundle,
          "overwrite",
          (kid) =>
            kid === identity.identity_id
              ? fromBase64url(identity.public_key)
              : null
        )
      ).resolves.toMatchObject({ imported_keys: 2 });
      expect(anchorRaised).toBe(false);
      expect(concurrentWrite).toBeDefined();
      await concurrentWrite!;

      const first = await readValue(rig.client, "race-first");
      expect(first.value).toBe("imported");
      const second = await readValue(rig.client, "race-second");
      expect(second.value).toBe("concurrent");
      expect(second.version).toBe(3);
    } finally {
      await rig.close();
    }
  });

  it("StateStore.import anchors imported entries before a later older import", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      const newerBundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [
          { key: "imported-anchor", value: "first" },
          { key: "imported-anchor", value: "second" },
          { key: "imported-anchor", value: "third" },
        ],
      });
      const olderBundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [
          { key: "imported-anchor", value: "first" },
          { key: "imported-anchor", value: "second" },
        ],
      });

      await expect(
        rig.stateStore.import(
          newerBundle,
          "overwrite",
          (kid) =>
            kid === identity.identity_id
              ? fromBase64url(identity.public_key)
              : null
        )
      ).resolves.toMatchObject({ imported_keys: 1 });

      await expect(
        rig.stateStore.import(
          olderBundle,
          "overwrite",
          (kid) =>
            kid === identity.identity_id
              ? fromBase64url(identity.public_key)
              : null
        )
      ).rejects.toMatchObject({ classification: "rollback_detected" });
      const current = await readValue(rig.client, "imported-anchor");
      expect(current.value).toBe("third");
      expect(current.version).toBe(3);
    } finally {
      await rig.close();
    }
  });

  it("audits partial import progress when a later entry is refused", async () => {
    const storage = new HookedMemoryStorage();
    const rig = await makeToolRig(storage);
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      await writeValue(rig.client, identityId, "partial-second", "first");
      await writeValue(rig.client, identityId, "partial-second", "second");
      await writeValue(rig.client, identityId, "partial-second", "third");
      const bundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [
          { key: "partial-first", value: "imported" },
          { key: "partial-second", value: "first" },
          { key: "partial-second", value: "second" },
          { key: "partial-second", value: "third" },
        ],
      });
      const raisedBundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [
          { key: "partial-second", value: "first" },
          { key: "partial-second", value: "second" },
          { key: "partial-second", value: "third" },
          { key: "partial-second", value: "fourth" },
        ],
      });
      const raisedEntry = exportedEntry(raisedBundle, "partial-second");

      let raised = false;
      storage.onWrite = async (namespace, key) => {
        if (namespace === "notes" && key === "partial-first" && !raised) {
          raised = true;
          await storage.write(
            "notes",
            "partial-second",
            stringToBytes(JSON.stringify(raisedEntry))
          );
          await readValue(rig.client, "partial-second");
        }
      };

      const refused = await callTool(rig.client, "state_import", {
        bundle,
        conflict_resolution: "overwrite",
      });
      expect(refused.denied).toBe(true);

      const first = await readValue(rig.client, "partial-first");
      expect(first.value).toBe("imported");
      const second = await readValue(rig.client, "partial-second");
      expect(second.value).toBe("fourth");
      expect(second.version).toBe(4);

      const audit = await rig.auditLog.query({
        operation_type: "state_import_verification_failed",
        limit: 10,
      });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]?.details).toMatchObject({
        partial: true,
        imported_before_refusal: 1,
        written_keys: [{ namespace: "notes", key: "partial-first" }],
      });
      expect(String(audit.entries[0]?.details?.reason)).toContain(
        "partially applied"
      );
      const success = await rig.auditLog.query({
        operation_type: "state_import",
        limit: 10,
      });
      expect(success.entries).toHaveLength(0);
    } finally {
      storage.onWrite = undefined;
      await rig.close();
    }
  });

  it("audits partial import progress when a journal appears after an earlier key", async () => {
    const storage = new HookedMemoryStorage();
    const rig = await makeToolRig(storage);
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      const bundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [
          { key: "journal-first", value: "imported" },
          { key: "journal-second", value: "imported" },
        ],
      });

      storage.onWrite = async (namespace, key) => {
        if (namespace !== "notes" || key !== "journal-first") return;
        await storage.write(
          EXIT_IMPORT_JOURNAL_NAMESPACE,
          "planted-import-journal",
          stringToBytes(JSON.stringify({
            import_id: "planted-import-journal",
            identity_id: identityId,
            started_at: new Date().toISOString(),
            snapshots: [],
          }))
        );
      };

      const refused = await callTool(rig.client, "state_import", {
        bundle,
        conflict_resolution: "overwrite",
      });
      expect(refused.error).toBe("exit_import_pending_recovery");

      const first = await readValue(rig.client, "journal-first");
      expect(first.value).toBe("imported");
      const second = await readValue(rig.client, "journal-second");
      expect(second.denied).toBe(true);
      const audit = await rig.auditLog.query({
        operation_type: "state_import_refused_pending_exit_import_recovery",
        limit: 10,
      });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]?.details).toMatchObject({
        partial: true,
        imported_before_refusal: 1,
        written_keys: [{ namespace: "notes", key: "journal-first" }],
      });
    } finally {
      storage.onWrite = undefined;
      await rig.close();
    }
  });

  it("audits partial import progress when storage refuses after an earlier key", async () => {
    const storage = new HookedMemoryStorage();
    const rig = await makeToolRig(storage);
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      const bundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [
          { key: "storage-first", value: "imported" },
          { key: "storage-second", value: "imported" },
        ],
      });
      storage.beforeWrite = async (namespace, key) => {
        if (namespace === "notes" && key === "storage-second") {
          throw new Error("injected storage refusal");
        }
      };

      const refused = await callTool(rig.client, "state_import", {
        bundle,
        conflict_resolution: "overwrite",
      });
      expect(refused.denied).toBe(true);
      const first = await readValue(rig.client, "storage-first");
      expect(first.value).toBe("imported");
      const audit = await rig.auditLog.query({
        operation_type: "state_import_failed",
        limit: 10,
      });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]?.details).toMatchObject({
        error_name: "Error",
        error_message: "injected storage refusal",
        partial: true,
        imported_before_refusal: 1,
        written_keys: [{ namespace: "notes", key: "storage-first" }],
      });
    } finally {
      storage.beforeWrite = undefined;
      await rig.close();
    }
  });

  it("audits the in-flight import key when the first storage write refuses", async () => {
    const storage = new HookedMemoryStorage();
    const rig = await makeToolRig(storage);
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      const bundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [{ key: "storage-first-in-flight", value: "imported" }],
      });
      storage.onWrite = async (namespace, key) => {
        if (namespace === "notes" && key === "storage-first-in-flight") {
          throw new Error("injected first storage refusal");
        }
      };

      const refused = await callTool(rig.client, "state_import", {
        bundle,
        conflict_resolution: "overwrite",
      });
      expect(refused.denied).toBe(true);
      const first = await readValue(rig.client, "storage-first-in-flight");
      expect(first.value).toBe("imported");
      const audit = await rig.auditLog.query({
        operation_type: "state_import_failed",
        limit: 10,
      });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]?.details).toMatchObject({
        error_name: "Error",
        error_message: "injected first storage refusal",
        partial: true,
        imported_before_refusal: 0,
        written_keys: [],
        in_flight_key: { namespace: "notes", key: "storage-first-in-flight" },
        in_flight_key_may_have_landed: true,
      });
    } finally {
      storage.onWrite = undefined;
      await rig.close();
    }
  });

  it("audits the in-flight import key when a later storage write refuses", async () => {
    const storage = new HookedMemoryStorage();
    const rig = await makeToolRig(storage);
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      const bundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [
          { key: "storage-landed-first", value: "imported" },
          { key: "storage-landed-second", value: "imported" },
        ],
      });
      storage.onWrite = async (namespace, key) => {
        if (namespace === "notes" && key === "storage-landed-second") {
          throw new Error("injected landed storage refusal");
        }
      };

      const refused = await callTool(rig.client, "state_import", {
        bundle,
        conflict_resolution: "overwrite",
      });
      expect(refused.denied).toBe(true);
      expect((await readValue(rig.client, "storage-landed-first")).value).toBe("imported");
      expect((await readValue(rig.client, "storage-landed-second")).value).toBe("imported");
      const audit = await rig.auditLog.query({
        operation_type: "state_import_failed",
        limit: 10,
      });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]?.details).toMatchObject({
        error_name: "Error",
        error_message: "injected landed storage refusal",
        partial: true,
        imported_before_refusal: 1,
        written_keys: [{ namespace: "notes", key: "storage-landed-first" }],
        in_flight_key: { namespace: "notes", key: "storage-landed-second" },
        in_flight_key_may_have_landed: true,
      });
    } finally {
      storage.onWrite = undefined;
      await rig.close();
    }
  });

  it("labels a first in-flight key when storage refuses before bytes land", async () => {
    const storage = new HookedMemoryStorage();
    const rig = await makeToolRig(storage);
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      const bundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [{ key: "storage-before-first", value: "imported" }],
      });
      storage.beforeWrite = async (namespace, key) => {
        if (namespace === "notes" && key === "storage-before-first") {
          throw new Error("injected before-write refusal");
        }
      };

      const refused = await callTool(rig.client, "state_import", {
        bundle,
        conflict_resolution: "overwrite",
      });
      expect(refused.denied).toBe(true);
      expect(await storage.read("notes", "storage-before-first")).toBeNull();
      const audit = await rig.auditLog.query({
        operation_type: "state_import_failed",
        limit: 10,
      });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]?.details).toMatchObject({
        error_name: "Error",
        error_message: "injected before-write refusal",
        partial: true,
        imported_before_refusal: 0,
        written_keys: [],
        in_flight_key: { namespace: "notes", key: "storage-before-first" },
        in_flight_key_may_have_landed: true,
      });
    } finally {
      storage.beforeWrite = undefined;
      await rig.close();
    }
  });

  it("audits partial import progress when a facade marker write refuses", async () => {
    const storage = new HookedMemoryStorage();
    const rig = await makeToolRig(storage);
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      const bundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [{ key: "facade-first", value: "imported" }],
        facadeHiddenMarkers: [
          {
            key: "facade-marker",
            marker: { namespace: "notes", key: "facade-first" },
          },
        ],
      });
      storage.beforeWrite = async (namespace, key) => {
        if (namespace === FACADE_HIDDEN_MARKER_NAMESPACE && key === "facade-marker") {
          throw new Error("injected facade marker refusal");
        }
      };

      const refused = await callTool(rig.client, "state_import", {
        bundle,
        conflict_resolution: "overwrite",
      });
      expect(refused.denied).toBe(true);
      const first = await readValue(rig.client, "facade-first");
      expect(first.value).toBe("imported");
      const audit = await rig.auditLog.query({
        operation_type: "state_import_failed",
        limit: 10,
      });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]?.details).toMatchObject({
        partial: true,
        imported_before_refusal: 1,
        written_keys: [{ namespace: "notes", key: "facade-first" }],
      });
    } finally {
      storage.beforeWrite = undefined;
      await rig.close();
    }
  });

  it("keeps partial import errors out of read-only floor refusal classification", () => {
    const cause = new StateVerificationError(
      "rollback_detected",
      "injected floor refusal",
      "version_below_floor"
    );
    const partial = new StateImportPartialApplyError(cause, [
      { namespace: "notes", key: "partial-classification" },
    ]);
    expect(isStateVersionFloorRefusal(cause)).toBe(true);
    expect(isStateVersionFloorRefusal(partial)).toBe(false);
  });
});
