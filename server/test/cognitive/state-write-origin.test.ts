/**
 * A state write's origin is decided by the session that makes it: a sole
 * binding names no author, so its writes are stamped unattributed and classify
 * shared_entangled.
 */
import { describe, expect, it } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString } from "../../src/core/encoding.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { fingerprintIdentityId, type SessionBinding } from "../../src/agent-native/safety-base.js";
import type { SessionBindingState } from "../../src/agent-native/session-binding-state.js";

type Tool = { name: string; handler: (args: Record<string, unknown>) => Promise<{ content: Array<{ text: string }> }> };

async function buildTools(bootState: () => SessionBindingState, binding: (identityId: string) => SessionBinding | undefined) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  let identityId: string | undefined;
  const { tools, identityManager } = createL1Tools(stateStore, storage, masterKey, "passphrase", auditLog, {
    sessionBindingBootState: bootState,
    currentSessionBinding: () => (identityId === undefined ? undefined : binding(identityId)),
  });
  await identityManager.load();
  const call = async (name: string, args: Record<string, unknown>) =>
    (tools as Tool[]).find((tool) => tool.name === name)!.handler(args);
  const created = JSON.parse((await call("identity_create", { label: "origin-subject" })).content[0]!.text);
  identityId = created.identity_id as string;
  const rawStamp = async (namespace: string, key: string) => {
    const bytes = await storage.read(namespace, key);
    return bytes === null ? null : (JSON.parse(bytesToString(bytes)).provenance_stamp as Record<string, unknown>);
  };
  const successRows = async () =>
    (await auditLog.query({ operation_type: "state_write", limit: Number.MAX_SAFE_INTEGER })).total;
  return { storage, auditLog, call, rawStamp, successRows, identityId };
}

const boundTo = (identityId: string, binding_source?: "sole_identity" | "launch_variable"): SessionBinding => ({
  identity_id: identityId,
  requester_identity_fingerprint: fingerprintIdentityId(identityId),
  ...(binding_source !== undefined ? { binding_source } : {}),
});

describe("state_write origin", () => {
  it("a sole-bound write is unattributed and classifies shared_entangled", async () => {
    const t = await buildTools(() => "state_BOUND_SOLE_IDENTITY", (id) => boundTo(id, "sole_identity"));
    const result = JSON.parse((await t.call("state_write", { namespace: "notes", key: "k", value: "v" })).content[0]!.text);
    expect(result).toMatchObject({ namespace: "notes", key: "k" });
    const stamp = await t.rawStamp("notes", "k");
    expect(stamp).toMatchObject({ origin_actor: "unattributed", memory_class: "shared_entangled", derived_from: [] });
    expect(Object.hasOwn(stamp!, "derived_from_edges")).toBe(false);
  });
});
