/**
 * The fleet-posture reads require the operator bearer, never loopback position.
 *
 * Companion to the folded-read gate #1075 added
 * (`isFoldedOperatorReadRoute`). That change closed the three reads the
 * dashboard fold MOVED onto the always-on surface; these three PREDATE the
 * fold on it and were left admitting a tokenless loopback caller through the
 * v0.10.2 auto-auth branch in `checkAuth`:
 *
 *   GET /api/fleet/status          the downgrade-banner state
 *   GET /api/fleet/capacity        enrollment headroom
 *   GET /api/fleet/downgrade-log   the operator-visible transition log
 *
 * In the MCP threat model the wrapped agent shares the loopback interface with
 * the operator, so a co-resident process (including a confined agent uid) could
 * read the fortress's licensing tier, node counts, cap headroom, and downgrade
 * history with no credential at all. That is the same fail-open ratified
 * decision 2 rejected, and it is what these tests close.
 *
 * Every rig here enables `setAutoAuthLocalhost(true)` — the production
 * `sanctuary protect` posture. That is the posture the pre-existing fleet
 * suites never enabled, which is why the gap survived them.
 */

import { describe, it, expect, afterEach } from "vitest";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  bindWithRetry,
  randomTestPort,
} from "../util/port-collision-retry.js";

const TOKEN = "operator-only-reads-token-0123456789abcdef";

/** The reads this change moves off loopback admission. */
const OPERATOR_ONLY_FLEET_READS = [
  "/api/fleet/status",
  "/api/fleet/capacity",
  "/api/fleet/downgrade-log",
] as const;

const STUB_POLICY = {
  version: 1,
  tier1_always_approve: [],
  tier3_auto_allow: [],
  anomaly_thresholds: {
    new_namespace: true,
    unfamiliar_counterparty_window_days: 7,
    frequency_spike_multiplier: 5,
  },
  approval_channel: { type: "stderr", timeout_seconds: 30 },
} as never;

const STUB_BASELINE = {
  load: async () => {},
  save: async () => {},
  getProfile: () => ({}),
} as never;

interface Rig {
  channel: DashboardApprovalChannel;
  base: string;
  bearer: Record<string, string>;
  stop: () => Promise<void>;
}

async function startRig(opts: { autoAuth: boolean }): Promise<Rig> {
  let channel: DashboardApprovalChannel | undefined;
  let port = 0;
  await bindWithRetry(async () => {
    port = randomTestPort();
    channel = new DashboardApprovalChannel({
      port,
      host: "127.0.0.1",
      timeout_seconds: 30,
      auto_deny: true,
      auth_token: TOKEN,
    });
    channel.setDependencies({
      policy: STUB_POLICY,
      baseline: STUB_BASELINE,
      auditLog: new AuditLog(new MemoryStorage(), generateRandomKey()),
    });
    channel.setAutoAuthLocalhost(opts.autoAuth);
    await channel.start();
  });
  return {
    channel: channel!,
    base: `http://127.0.0.1:${port}`,
    bearer: { Authorization: `Bearer ${TOKEN}` },
    stop: async () => channel!.stop(),
  };
}

describe("fleet-posture reads require the operator bearer, never loopback position", () => {
  const rigs: Rig[] = [];
  afterEach(async () => {
    for (const rig of rigs.splice(0)) await rig.stop();
  });

  /** A rig in the production `protect` posture: token minted AND auto-auth on. */
  async function loopbackAutoAuthRig(): Promise<Rig> {
    const rig = await startRig({ autoAuth: true });
    rigs.push(rig);
    return rig;
  }

  for (const path of OPERATOR_ONLY_FLEET_READS) {
    it(`DENIES a tokenless loopback GET ${path} even with auto-auth enabled`, async () => {
      const rig = await loopbackAutoAuthRig();
      const res = await fetch(`${rig.base}${path}`);
      expect([path, res.status]).toEqual([path, 401]);
      // Invariant 7: the denial is generic and names no rule or tier.
      expect(await res.json()).toEqual({ error: "unauthorized" });
    });
  }

  it("still serves every fleet-posture read to the operator bearer with auto-auth enabled", async () => {
    const rig = await loopbackAutoAuthRig();
    for (const path of OPERATOR_ONLY_FLEET_READS) {
      const res = await fetch(`${rig.base}${path}`, { headers: rig.bearer });
      expect([path, res.status]).toEqual([path, 200]);
    }
  });

  it("REJECTS a wrong bearer (the bearer test cannot pass on header presence alone)", async () => {
    const rig = await loopbackAutoAuthRig();
    for (const path of OPERATOR_ONLY_FLEET_READS) {
      const res = await fetch(`${rig.base}${path}`, {
        headers: { Authorization: `Bearer ${TOKEN}-wrong` },
      });
      expect([path, res.status]).toEqual([path, 401]);
    }
  });

  it("still serves the fleet-posture reads to a session minted from the operator bearer (the browser console keeps working)", async () => {
    const rig = await loopbackAutoAuthRig();
    const exchange = await fetch(`${rig.base}/auth/session`, {
      method: "POST",
      headers: rig.bearer,
    });
    expect(exchange.status).toBe(200);
    const { session_id: sessionId } = (await exchange.json()) as {
      session_id: string;
    };
    expect(typeof sessionId).toBe("string");
    for (const path of OPERATOR_ONLY_FLEET_READS) {
      const res = await fetch(
        `${rig.base}${path}?session=${encodeURIComponent(sessionId)}`,
      );
      expect([path, res.status]).toEqual([path, 200]);
    }
  });

  it("REJECTS a bogus ?session= (the session test cannot pass on the parameter's presence alone)", async () => {
    const rig = await loopbackAutoAuthRig();
    for (const path of OPERATOR_ONLY_FLEET_READS) {
      const res = await fetch(`${rig.base}${path}?session=not-a-real-session`);
      expect([path, res.status]).toEqual([path, 401]);
    }
  });

  it("CONTROL: the rigs really are in the auto-auth posture (an ungated read is tokenless-open with it on, denied with it off)", async () => {
    const on = await loopbackAutoAuthRig();
    const onRes = await fetch(`${on.base}/api/status`);
    expect(onRes.status).toBe(200);

    const off = await startRig({ autoAuth: false });
    rigs.push(off);
    const offRes = await fetch(`${off.base}/api/status`);
    expect(offRes.status).toBe(401);
  });

  it("leaves loopback auto-auth intact on the reads this change does not gate (scoped fix, not a repo-wide kill)", async () => {
    const rig = await loopbackAutoAuthRig();
    for (const path of ["/api/status", "/api/snapshot"]) {
      const res = await fetch(`${rig.base}${path}`);
      expect([path, res.status]).toEqual([path, 200]);
    }
  });
});
