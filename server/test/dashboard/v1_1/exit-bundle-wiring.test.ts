import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { buildV11Bindings, fortressIdFromStoragePath } from "../../../src/dashboard/v1_1/wiring.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { StateStore } from "../../../src/cognitive/state-store.js";
import { createL1Tools } from "../../../src/cognitive/tools.js";
import { DEFAULT_POLICY } from "../../../src/principal-policy/loader.js";
import { verifyExitBundle } from "../../../src/exit/verifier.js";
import type { HubApprovalPendingItem } from "../../../src/contracts/v1.1/hub-events.js";

describe("v1.1 dashboard exit-bundle wiring", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("advertises fortress_exit_bundle_export when storage and key material are wired", async () => {
    const storagePath = await mkdtemp(join(tmpdir(), "sanctuary-exit-wire-"));
    tempDirs.push(storagePath);
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const stateStore = new StateStore(storage, masterKey);
    const { tools, identityManager } = createL1Tools(
      stateStore,
      storage,
      masterKey,
      "recovery-key",
      auditLog,
    );
    await identityManager.load();
    await tools
      .find((tool) => tool.name === "identity_create")!
      .handler({ label: "exit-wire-source" });

    const { hubService } = buildV11Bindings({
      identityId: "operator-exit-wire",
      fortressId: fortressIdFromStoragePath(storagePath),
      auditLog,
      storagePath,
      storage,
      masterKey,
      identityManager,
      policy: DEFAULT_POLICY,
    });

    const enqueued = hubService.enqueueFortressExportBundle();
    expect(enqueued.operation_category).toBe("exit_bundle_export");
    expect(enqueued.fortress_scope).toBe(true);

    const resolved = await hubService.resolveInboxItem(
      enqueued.inbox_item_id,
      "approve",
    );
    const payload = resolved.resolution_payload;
    expect(payload?.bundle_dir).toContain("exit-bundles");
    expect(payload?.manifest_hash?.length).toBeGreaterThan(16);
    expect(payload?.artifact_count).toBeGreaterThan(0);

    const verified = await verifyExitBundle(payload!.bundle_dir!);
    expect(verified.passed).toBe(true);
  });

  // A7: resolution_payload must carry state_entry_count and warnings so the
  // dashboard can surface them. Wiring drops these fields on base; this test
  // is the fail-before anchor for defect A7.
  it("A7: resolution_payload carries state_entry_count (number >= 0) and optional warnings", async () => {
    const storagePath = await mkdtemp(join(tmpdir(), "sanctuary-exit-a7-"));
    tempDirs.push(storagePath);
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const stateStore = new StateStore(storage, masterKey);
    const { tools, identityManager } = createL1Tools(
      stateStore,
      storage,
      masterKey,
      "recovery-key",
      auditLog,
    );
    await identityManager.load();
    await tools
      .find((t) => t.name === "identity_create")!
      .handler({ label: "a7-source" });

    const { hubService } = buildV11Bindings({
      identityId: "operator-a7",
      fortressId: fortressIdFromStoragePath(storagePath),
      auditLog,
      storagePath,
      storage,
      masterKey,
      identityManager,
      policy: DEFAULT_POLICY,
    });

    const enqueued = hubService.enqueueFortressExportBundle();
    const resolved = await hubService.resolveInboxItem(
      enqueued.inbox_item_id,
      "approve",
    );
    // Cast to the specific subtype: resolveInboxItem returns the union HubInboxItem
    // and resolution_payload lives on HubApprovalPendingItem. The existing first test
    // in this file uses the same pattern (baseline-accepted); this test narrows
    // explicitly to keep the typecheck baseline clean.
    const payload = (resolved as HubApprovalPendingItem).resolution_payload;

    // A7 fail-before: state_entry_count must be a number (including 0) so
    // "Bundle ready" cannot mask an empty-state export on the dashboard.
    // On base this field is absent (undefined), so the typeof check fails.
    expect(typeof payload?.state_entry_count).toBe("number");
    expect(payload!.state_entry_count!).toBeGreaterThanOrEqual(0);

    // A7: warnings must be absent or an array of strings; never a non-array.
    if (payload?.warnings !== undefined) {
      expect(Array.isArray(payload.warnings)).toBe(true);
      for (const w of payload.warnings!) {
        expect(typeof w).toBe("string");
      }
    }
  });
});
