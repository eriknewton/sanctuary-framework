import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { buildV11Bindings, fortressIdFromStoragePath } from "../../../src/dashboard/v1_1/wiring.js";
import { AuditLog } from "../../../src/l2-operational/audit-log.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { StateStore } from "../../../src/l1-cognitive/state-store.js";
import { createL1Tools } from "../../../src/l1-cognitive/tools.js";
import { DEFAULT_POLICY } from "../../../src/principal-policy/loader.js";
import { verifyExitBundle } from "../../../src/exit/verifier.js";

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
});
