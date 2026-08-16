import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { startStandaloneDashboard } from "../../src/dashboard-standalone.js";
import { createSanctuaryServer } from "../../src/index.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { generateDefaultPolicyYaml } from "../../src/principal-policy/loader.js";
import { OperatorAuthorizationSpentStore } from "../../src/v1/operator-authorization-spent-store.js";
import { createTempFortress, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";
import {
  bindWithRetry,
  randomTestPort,
} from "../util/port-collision-retry.js";

type DashboardSpentStoreAccess = {
  _operatorAuthorizationSpentStore: OperatorAuthorizationSpentStore;
  _operatorAuthorizationSpentStoreUnavailable: boolean;
};

type SpentStoreDurabilityAccess = {
  durable?: unknown;
};

const capturedDashboards: DashboardApprovalChannel[] = [];

const envKeys = [
  "SANCTUARY_DASHBOARD_AUTH_TOKEN",
  "SANCTUARY_DASHBOARD_ENABLED",
  "SANCTUARY_DASHBOARD_HOST",
  "SANCTUARY_DASHBOARD_PORT",
  "SANCTUARY_RECOVERY_OUT",
] as const;

let restoreEnv: (() => void) | undefined;

afterEach(async () => {
  while (capturedDashboards.length > 0) {
    await capturedDashboards.pop()!.stop();
  }
  restoreEnv?.();
  restoreEnv = undefined;
  vi.restoreAllMocks();
});

describe("OperatorAuthorizationSpentStore production wiring", () => {
  it("wires a durable spent store through createSanctuaryServer for a non-federated single-node boot", async () => {
    restoreEnv = preserveEnv();
    const fortress = await createTempFortress("sanctuary-operator-auth-root");
    captureStartedDashboards();

    try {
      await writeDashboardPolicy(fortress.storagePath);
      await bindWithRetry(async () => {
        await stopCapturedDashboards();
        process.env.SANCTUARY_DASHBOARD_HOST = "127.0.0.1";
        process.env.SANCTUARY_DASHBOARD_PORT = String(randomTestPort());
        process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-root";

        const boot = await createSanctuaryServer();
        expect(boot.policy.approval_channel.type).toBe("dashboard");
      });

      expect(capturedDashboards).toHaveLength(1);
      const dashboard = capturedDashboards[0]!;
      expect(dashboard.isFederationProvisioned()).toBe(false);
      expectDurableSpentStore(dashboard);
    } finally {
      await stopCapturedDashboards();
      await fortress.cleanup();
    }
  });

  it("wires a durable spent store through wireUnlockedDeps for a standalone non-federated dashboard boot", async () => {
    restoreEnv = preserveEnv();
    const fortress = await createTempFortress("sanctuary-operator-auth-standalone");
    captureStartedDashboards();

    try {
      await bindWithRetry(async () => {
        await stopCapturedDashboards();
        process.env.SANCTUARY_RECOVERY_OUT = join(fortress.home, "recovery.txt");
        await startStandaloneDashboard({
          authToken: "test-token-standalone",
          distressPort: 0,
          host: "127.0.0.1",
          noConfirm: true,
          passphrase: TEST_PASSPHRASE,
          port: randomTestPort(),
          recoveryOut: process.env.SANCTUARY_RECOVERY_OUT,
          storagePath: fortress.storagePath,
        });
      });

      expect(capturedDashboards).toHaveLength(1);
      const dashboard = capturedDashboards[0]!;
      expect(dashboard.isFederationProvisioned()).toBe(false);
      expectDurableSpentStore(dashboard);
    } finally {
      await stopCapturedDashboards();
      await fortress.cleanup();
    }
  });
});

function captureStartedDashboards(): void {
  const original = DashboardApprovalChannel.prototype.start;
  vi.spyOn(DashboardApprovalChannel.prototype, "start").mockImplementation(
    async function (this: DashboardApprovalChannel) {
      await original.call(this);
      if (!capturedDashboards.includes(this)) {
        capturedDashboards.push(this);
      }
    },
  );
}

async function writeDashboardPolicy(storagePath: string): Promise<void> {
  await mkdir(storagePath, { recursive: true, mode: 0o700 });
  await writeFile(
    join(storagePath, "principal-policy.yaml"),
    generateDefaultPolicyYaml().replace("type: stderr", "type: dashboard"),
    { mode: 0o600 },
  );
}

function expectDurableSpentStore(dashboard: DashboardApprovalChannel): void {
  const access = dashboard as unknown as DashboardSpentStoreAccess;
  expect(access._operatorAuthorizationSpentStore).toBeInstanceOf(
    OperatorAuthorizationSpentStore,
  );
  expect(access._operatorAuthorizationSpentStoreUnavailable).toBe(false);
  expect(
    (access._operatorAuthorizationSpentStore as unknown as SpentStoreDurabilityAccess)
      .durable,
  ).toBeDefined();
}

async function stopCapturedDashboards(): Promise<void> {
  while (capturedDashboards.length > 0) {
    await capturedDashboards.pop()!.stop();
  }
}

function preserveEnv(): () => void {
  const previous = new Map<string, string | undefined>(
    envKeys.map((key) => [key, process.env[key]]),
  );
  return () => {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  };
}
