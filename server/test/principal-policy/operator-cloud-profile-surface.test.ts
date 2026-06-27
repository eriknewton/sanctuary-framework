import { afterEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { SovereigntyProfileStore } from "../../src/sovereignty-profile.js";

function pickPort(): number {
  return 23000 + Math.floor(Math.random() * 20000);
}

describe("dashboard sovereignty profile operator-cloud posture surface", () => {
  let dashboard: DashboardApprovalChannel | null = null;

  afterEach(async () => {
    await dashboard?.stop();
    dashboard = null;
  });

  it("adds deployment_posture without mutating the profile schema", async () => {
    const storage = new MemoryStorage();
    const masterKey = randomBytes(32);
    const auditLog = new AuditLog(storage, masterKey);
    const profileStore = new SovereigntyProfileStore(storage, masterKey);
    await profileStore.load();
    const authToken = "profile-posture-test";
    const port = pickPort();
    dashboard = new DashboardApprovalChannel({
      port,
      host: "127.0.0.1",
      timeout_seconds: 30,
      auth_token: authToken,
      auto_open: false,
    });
    dashboard.setDependencies({
      policy: {
        version: 1,
        tier1_always_approve: [],
        tier3_auto_allow: [],
        anomaly_thresholds: {
          new_namespace: true,
          unfamiliar_counterparty_window_days: 7,
          frequency_spike_multiplier: 5,
        },
        approval_channel: { type: "stderr", timeout_seconds: 30 },
      } as never,
      baseline: { load: async () => {}, save: async () => {} } as never,
      auditLog,
      profileStore,
    });
    await dashboard.start();

    const res = await fetch(`http://127.0.0.1:${port}/api/sovereignty-profile`, {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, any>;
    expect(body.profile.version).toBe(1);
    expect(body.deployment_posture).toEqual(
      expect.objectContaining({
        operator_cloud_nodes: 0,
        provider_in_trust_boundary: false,
        tee_attested: false,
      }),
    );
    expect(body.deployment_posture.trust_boundary).toEqual(
      expect.objectContaining({
        version: "operator-cloud-trust-boundary-v1",
        operator_cloud_nodes: 0,
        provider_in_trust_boundary: false,
        tee_attested: false,
      }),
    );
  });
});
