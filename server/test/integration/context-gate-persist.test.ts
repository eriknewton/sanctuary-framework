import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { SovereigntyProfileStore } from "../../src/sovereignty-profile.js";
import {
  createContextGateTools,
  initializeContextGateEnforcerFromProfile,
} from "../../src/operational/context-gate-tools.js";

describe("context gate restart persistence", () => {
  let tempDir: string | null = null;

  afterEach(async () => {
    if (tempDir) {
      await rm(tempDir, { recursive: true, force: true });
      tempDir = null;
    }
  });

  it("boots the runtime enforcer enabled when the persisted profile enables context_gating", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "sanctuary-context-gate-"));
    const masterKey = generateRandomKey();

    const firstStorage = new FilesystemStorage(tempDir);
    const firstProfileStore = new SovereigntyProfileStore(firstStorage, masterKey);
    await firstProfileStore.load();
    await firstProfileStore.update({
      context_gating: { enabled: true, policy_id: "persisted-policy" },
    });

    const restartedStorage = new FilesystemStorage(tempDir);
    const restartedProfileStore = new SovereigntyProfileStore(restartedStorage, masterKey);
    const restartedProfile = await restartedProfileStore.load();
    const restartedAuditLog = new AuditLog(restartedStorage, masterKey);
    const { enforcer } = createContextGateTools(restartedStorage, masterKey, restartedAuditLog);

    initializeContextGateEnforcerFromProfile(enforcer, restartedProfile);

    expect(restartedProfile.features.context_gating.enabled).toBe(true);
    expect(enforcer.getStatus()).toMatchObject({
      enabled: true,
      default_policy_id: "persisted-policy",
    });
  });
});
