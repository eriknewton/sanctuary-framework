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
import { ApprovalAggregator } from "../../src/principal-policy/approval-aggregator.js";
import { APPROVAL_INBOX_API_PREFIX } from "../../src/principal-policy/approval-aggregator-routes.js";
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

async function startRig(opts: {
  autoAuth: boolean;
  /**
   * Bind an approval aggregator, which is what makes the dashboard route
   * `/api/approval-inbox/*` at all (`dispatchApprovalInbox` returns false
   * without one). This is the `approval_redirect`-enabled posture.
   */
  withAggregator?: boolean;
}): Promise<Rig> {
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
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    channel.setDependencies({
      policy: STUB_POLICY,
      baseline: STUB_BASELINE,
      auditLog,
    });
    if (opts.withAggregator) {
      channel.setApprovalAggregator(
        new ApprovalAggregator({
          storage,
          masterKey,
          auditLog,
          identityId: "identity-operator-only-reads",
          fortressId: "fortress-operator-only-reads",
          resolveSourceContext: () => ({
            source_harness: "claude-code",
            source_agent_id: "agent-x",
          }),
        }),
      );
    }
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

/**
 * `GET /api/pending` — the operator's approval queue.
 *
 * It predates the fold on this surface and kept the same loopback admission:
 * a co-resident process (including a confined agent uid) could read every
 * operation waiting on the operator's decision, with its tier and reason, using
 * no credential at all.
 *
 * This one could not ship with #1075 because gating the route alone is a
 * REGRESSION, not a fix: the posture-home landing page reads it through
 * loopback auto-auth and swallows failure into an empty array, so a gated route
 * would silently empty the operator's approval inbox. The paired client change
 * lives in `principal-policy/posture-home-html.ts` and is covered by
 * `posture-home-html.test.ts`.
 */
describe("the approval queue read requires the operator bearer, never loopback position", () => {
  const rigs: Rig[] = [];
  afterEach(async () => {
    for (const rig of rigs.splice(0)) await rig.stop();
  });

  async function loopbackAutoAuthRig(): Promise<Rig> {
    const rig = await startRig({ autoAuth: true });
    rigs.push(rig);
    return rig;
  }

  it("DENIES a tokenless loopback GET /api/pending even with auto-auth enabled", async () => {
    const rig = await loopbackAutoAuthRig();
    const res = await fetch(`${rig.base}/api/pending`);
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
  });

  it("still serves the approval queue to the operator bearer with auto-auth enabled", async () => {
    const rig = await loopbackAutoAuthRig();
    const res = await fetch(`${rig.base}/api/pending`, { headers: rig.bearer });
    expect(res.status).toBe(200);
    expect(Array.isArray(await res.json())).toBe(true);
  });

  it("REJECTS a wrong bearer on the approval queue", async () => {
    const rig = await loopbackAutoAuthRig();
    const res = await fetch(`${rig.base}/api/pending`, {
      headers: { Authorization: `Bearer ${TOKEN}-wrong` },
    });
    expect(res.status).toBe(401);
  });

  it("still serves the approval queue to a session minted from the operator bearer (the auto-opened ?session= link keeps working)", async () => {
    const rig = await loopbackAutoAuthRig();
    const exchange = await fetch(`${rig.base}/auth/session`, {
      method: "POST",
      headers: rig.bearer,
    });
    expect(exchange.status).toBe(200);
    const { session_id: sessionId } = (await exchange.json()) as {
      session_id: string;
    };
    const res = await fetch(
      `${rig.base}/api/pending?session=${encodeURIComponent(sessionId)}`,
    );
    expect(res.status).toBe(200);
  });

  it("REJECTS a bogus ?session= on the approval queue", async () => {
    const rig = await loopbackAutoAuthRig();
    const res = await fetch(`${rig.base}/api/pending?session=not-a-real-session`);
    expect(res.status).toBe(401);
  });
});

/**
 * `GET /api/approval-inbox*` — the cross-harness approval inbox reads.
 *
 * The third and last of this class. Same exposure as the two above (a
 * tokenless loopback caller is admitted while `sanctuary protect` has auto-auth
 * on), but reached through a DIFFERENT gate: `/api/approval-inbox/*` is
 * dispatched by `dispatchApprovalInbox` BEFORE `handleLegacyRequest` runs, so
 * `checkAuth` and its `isOperatorOnlyReadRoute` chokepoint never see the path.
 * The router's own `authMiddleware` (`console/auth-middleware.ts`) gated it
 * instead, and that middleware's loopback shortcut applies to every GET.
 *
 * What a co-resident uid could read with no credential: every operation
 * waiting on the operator across ALL wrapped harnesses, with its tier, reason,
 * source harness and source agent id (`/api/approval-inbox`), the resolved
 * history of every past decision (`/history`), and the per-entry detail
 * including the decrypted audited payload (`/:id/payload`). That is a superset
 * of what `GET /api/pending` exposed, which #1077 closed.
 *
 * The gate is applied at the dispatch site (the `dispatchDistress` precedent),
 * not inside the router, because the router's `authMiddleware` reads neither
 * the `sanctuary_session` cookie nor `?session=`; requiring a bearer THERE
 * would break the operator's own browser. `checkAuth` honors both.
 *
 * Every rig here enables `setAutoAuthLocalhost(true)`, the production
 * `sanctuary protect` posture.
 */
describe("the approval-inbox reads require the operator bearer, never loopback position", () => {
  const rigs: Rig[] = [];
  afterEach(async () => {
    for (const rig of rigs.splice(0)) await rig.stop();
  });

  /** A rig in the production `protect` posture WITH the aggregator bound. */
  async function inboxRig(): Promise<Rig> {
    const rig = await startRig({ autoAuth: true, withAggregator: true });
    rigs.push(rig);
    return rig;
  }

  /** Reads that answer 200 against an empty aggregator. */
  const INBOX_READS = [
    APPROVAL_INBOX_API_PREFIX,
    // The exact read the posture-home page issues.
    `${APPROVAL_INBOX_API_PREFIX}?status=pending`,
    `${APPROVAL_INBOX_API_PREFIX}/history`,
    `${APPROVAL_INBOX_API_PREFIX}/revision`,
    `${APPROVAL_INBOX_API_PREFIX}/sync?since_revision=0`,
  ] as const;

  for (const path of INBOX_READS) {
    it(`DENIES a tokenless loopback GET ${path} even with auto-auth enabled`, async () => {
      const rig = await inboxRig();
      const res = await fetch(`${rig.base}${path}`);
      expect([path, res.status]).toEqual([path, 401]);
      // Invariant 7: the denial is generic and names no rule or tier.
      expect(await res.json()).toEqual({ error: "unauthorized" });
    });
  }

  it("DENIES a tokenless loopback entry-detail read, and refuses BEFORE it reveals whether the id exists (401, not 404)", async () => {
    const rig = await inboxRig();
    const res = await fetch(
      `${rig.base}${APPROVAL_INBOX_API_PREFIX}/no-such-entry-id`,
    );
    expect(res.status).toBe(401);
  });

  it("still serves every approval-inbox read to the operator bearer with auto-auth enabled", async () => {
    const rig = await inboxRig();
    for (const path of INBOX_READS) {
      const res = await fetch(`${rig.base}${path}`, { headers: rig.bearer });
      expect([path, res.status]).toEqual([path, 200]);
    }
  });

  it("REJECTS a wrong bearer (the bearer test cannot pass on header presence alone)", async () => {
    const rig = await inboxRig();
    for (const path of INBOX_READS) {
      const res = await fetch(`${rig.base}${path}`, {
        headers: { Authorization: `Bearer ${TOKEN}-wrong` },
      });
      expect([path, res.status]).toEqual([path, 401]);
    }
  });

  it("still serves the approval-inbox reads to a session minted from the operator bearer (the browser console keeps working)", async () => {
    const rig = await inboxRig();
    const exchange = await fetch(`${rig.base}/auth/session`, {
      method: "POST",
      headers: rig.bearer,
    });
    expect(exchange.status).toBe(200);
    const { session_id: sessionId } = (await exchange.json()) as {
      session_id: string;
    };
    expect(typeof sessionId).toBe("string");
    for (const path of INBOX_READS) {
      const joiner = path.indexOf("?") === -1 ? "?" : "&";
      const res = await fetch(
        `${rig.base}${path}${joiner}session=${encodeURIComponent(sessionId)}`,
      );
      expect([path, res.status]).toEqual([path, 200]);
    }
  });

  it("REJECTS a bogus ?session= (the session test cannot pass on the parameter's presence alone)", async () => {
    const rig = await inboxRig();
    for (const path of INBOX_READS) {
      const joiner = path.indexOf("?") === -1 ? "?" : "&";
      const res = await fetch(
        `${rig.base}${path}${joiner}session=not-a-real-session`,
      );
      expect([path, res.status]).toEqual([path, 401]);
    }
  });

  it("CONTROL: this rig really is in the auto-auth posture (an ungated read is tokenless-open with it on, denied with it off)", async () => {
    const on = await inboxRig();
    const onRes = await fetch(`${on.base}/api/status`);
    expect(onRes.status).toBe(200);

    const off = await startRig({ autoAuth: false, withAggregator: true });
    rigs.push(off);
    const offRes = await fetch(`${off.base}/api/status`);
    expect(offRes.status).toBe(401);
  });

  it("leaves the DECISION routes exactly as strict as they were (a session is still not enough to approve)", async () => {
    const rig = await inboxRig();
    const exchange = await fetch(`${rig.base}/auth/session`, {
      method: "POST",
      headers: rig.bearer,
    });
    const { session_id: sessionId } = (await exchange.json()) as {
      session_id: string;
    };
    const res = await fetch(
      `${rig.base}${APPROVAL_INBOX_API_PREFIX}/some-id/approve?session=${encodeURIComponent(sessionId)}`,
      { method: "POST" },
    );
    expect(res.status).toBe(401);
  });
});
