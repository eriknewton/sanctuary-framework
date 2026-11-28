// fail-before-exempt: opened_at is reachable only through the cursor table view this change adds, so no surface at the base can observe the injected clock.
/**
 * An events cursor's opened_at is read from the surface's injected clock.
 */
import { describe, expect, it } from "vitest";
import { recordingNamespaceInserts } from "../helpers/cooperative-test-options.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog, runInCallScope } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createAgentNativeCooperativeTools } from "../../src/agent-native/cooperative-surface.js";
import { ApprovalProofStore, fingerprintIdentityId, type SessionBinding } from "../../src/agent-native/safety-base.js";

// A fixed instant far from the real clock, so a value taken from Date.now cannot match it.
const INJECTED_NOW_MS = 1_800_000_000_000;

describe("an events cursor's opened_at", () => {
  it("opened_at comes from the injected clock", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    let active: SessionBinding | undefined;
    const { tools: l1Tools, identityManager, namespaceRegistry } = createL1Tools(new StateStore(storage, masterKey), storage, masterKey,
      "recovery-key", auditLog, { sessionBindingBootState: () => "state_BOUND_NAMED", currentSessionBinding: () => active });
    await identityManager.load();
    const created = JSON.parse((await l1Tools.find((t) => t.name === "identity_create")!.handler({ label: "cursor-clock" })).content[0]!.text);
    const identityId = created.identity_id as string;
    active = { identity_id: identityId, requester_identity_fingerprint: fingerprintIdentityId(identityId) };
    const { tools, eventCursorTable } = createAgentNativeCooperativeTools({
      now: () => INJECTED_NOW_MS,
      baselineNamespaceInserts: recordingNamespaceInserts(),
      identityManager,
      namespaceRegistry,
      auditLog,
      currentSessionBinding: () => active,
      primitiveTools: l1Tools,
      storage,
      approvalProofStore: new ApprovalProofStore(),
    });
    const open = tools.find((t) => t.name === "sanctuary_events_open_cursor")!;
    const result = await runInCallScope(() => open.handler({}, "agent:cursor-clock", {}));
    const cursor = JSON.parse(result.content[0]!.text).cursor as string;
    expect(eventCursorTable.openedAt(cursor)).toBe(new Date(INJECTED_NOW_MS).toISOString());
  });
});
