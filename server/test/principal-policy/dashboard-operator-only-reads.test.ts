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

const SENSITIVE_APPROVAL = {
  operation: "secret-req-1",
  tier: 1 as const,
  reason: "secret reason must not leak",
  context: { secret: "hidden-from-position-only" },
  timestamp: "2026-08-03T12:00:00.000Z",
};

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

async function readInitialSnapshotEvent(res: Response): Promise<Record<string, unknown>> {
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  try {
    for (let i = 0; i < 8; i++) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const match = /event: snapshot\ndata: ([^\n]+)\n\n/.exec(buf);
      if (match) return JSON.parse(match[1]!) as Record<string, unknown>;
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  throw new Error("snapshot event not received");
}

async function drainSSE(res: Response, ms: number): Promise<string> {
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  const deadline = Date.now() + ms;
  try {
    while (Date.now() < deadline) {
      const timer = new Promise<null>((resolve) =>
        setTimeout(() => resolve(null), Math.max(1, deadline - Date.now())),
      );
      const next = await Promise.race([reader.read(), timer]);
      if (next === null || next.done) break;
      buf += decoder.decode(next.value, { stream: true });
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  return buf;
}

function readEventData(raw: string, event: string): Record<string, unknown> {
  const match = new RegExp(`event: ${event}\\ndata: ([^\\n]+)\\n\\n`).exec(raw);
  if (!match) throw new Error(`${event} event not received:\n${raw}`);
  return JSON.parse(match[1]!) as Record<string, unknown>;
}

async function denyFirstPending(rig: Rig): Promise<void> {
  const res = await fetch(`${rig.base}/api/pending`, { headers: rig.bearer });
  if (!res.ok) return;
  const rows = (await res.json()) as Array<{ id: string }>;
  const id = rows[0]?.id;
  if (!id) return;
  await fetch(`${rig.base}/api/deny/${encodeURIComponent(id)}`, {
    method: "POST",
    headers: rig.bearer,
  });
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

/**
 * `GET /api/snapshot` and `GET /api/stream` stay ambient liveness reads, but
 * their embedded approval queue is operator-only. A loopback-position caller
 * gets the same snapshot posture document with approval rows redacted and a
 * count-only marker, never the sensitive operation/reason rows and never a
 * false empty inbox.
 */
describe("snapshot pending approvals redact for position-only callers", () => {
  const rigs: Rig[] = [];
  afterEach(async () => {
    for (const rig of rigs.splice(0)) await rig.stop();
  });

  async function loopbackAutoAuthRig(): Promise<Rig> {
    const rig = await startRig({ autoAuth: true });
    rigs.push(rig);
    return rig;
  }

  it("redacts pending approvals from tokenless loopback GET /api/snapshot while keeping the count marker", async () => {
    const rig = await loopbackAutoAuthRig();
    const decision = rig.channel.requestApproval(SENSITIVE_APPROVAL);
    try {
      const res = await fetch(`${rig.base}/api/snapshot`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.pending_approvals).toEqual([]);
      expect(body.pending_approvals_redacted).toBe(true);
      expect(body.pending_approvals_count).toBe(1);
      const encoded = JSON.stringify(body);
      expect(encoded).not.toContain("secret-req-1");
      expect(encoded).not.toContain("secret reason must not leak");
    } finally {
      await denyFirstPending(rig);
      await decision;
    }
  });

  it("redacts pending approvals from the tokenless loopback /api/stream initial snapshot event", async () => {
    const rig = await loopbackAutoAuthRig();
    const decision = rig.channel.requestApproval(SENSITIVE_APPROVAL);
    try {
      const res = await fetch(`${rig.base}/api/stream`);
      expect(res.status).toBe(200);
      const snapshot = await readInitialSnapshotEvent(res);
      expect(snapshot.pending_approvals).toEqual([]);
      expect(snapshot.pending_approvals_redacted).toBe(true);
      expect(snapshot.pending_approvals_count).toBe(1);
      const encoded = JSON.stringify(snapshot);
      expect(encoded).not.toContain("secret-req-1");
      expect(encoded).not.toContain("secret reason must not leak");
    } finally {
      await denyFirstPending(rig);
      await decision;
    }
  });

  it("redacts a live approval delta on tokenless loopback /api/stream when approval is raised after open", async () => {
    const rig = await loopbackAutoAuthRig();
    const res = await fetch(`${rig.base}/api/stream`);
    expect(res.status).toBe(200);
    const drained = drainSSE(res, 1300);
    await new Promise((resolve) => setTimeout(resolve, 250));
    const decision = rig.channel.requestApproval(SENSITIVE_APPROVAL);
    try {
      const seen = await drained;
      const approval = readEventData(seen, "approval");
      expect(approval.pending_approvals_redacted).toBe(true);
      expect(approval.pending_approvals_count).toBe(1);
      const encoded = JSON.stringify(approval);
      expect(encoded).not.toContain("secret-req-1");
      expect(encoded).not.toContain("secret reason must not leak");
      expect(encoded).not.toContain("hidden-from-position-only");
    } finally {
      await denyFirstPending(rig);
      await decision;
    }
  });

  it("CONTROL: serves the full live approval delta to an operator bearer subscriber", async () => {
    const rig = await loopbackAutoAuthRig();
    const res = await fetch(`${rig.base}/api/stream`, { headers: rig.bearer });
    expect(res.status).toBe(200);
    const drained = drainSSE(res, 1300);
    await new Promise((resolve) => setTimeout(resolve, 250));
    const decision = rig.channel.requestApproval(SENSITIVE_APPROVAL);
    try {
      const seen = await drained;
      const approval = readEventData(seen, "approval");
      expect(approval.operation).toBe("secret-req-1");
      expect(approval.reason).toBe("secret reason must not leak");
      expect(approval.pending_approvals_redacted).toBeUndefined();
    } finally {
      await denyFirstPending(rig);
      await decision;
    }
  });

  it("redacts tokenless loopback /events init.pending while preserving the count marker", async () => {
    const rig = await loopbackAutoAuthRig();
    const decision = rig.channel.requestApproval(SENSITIVE_APPROVAL);
    try {
      await new Promise((resolve) => setTimeout(resolve, 100));
      const res = await fetch(`${rig.base}/events`);
      expect(res.status).toBe(200);
      const seen = await drainSSE(res, 800);
      const init = readEventData(seen, "init");
      expect(init.pending).toEqual([]);
      expect(init.pending_approvals_redacted).toBe(true);
      expect(init.pending_approvals_count).toBe(1);
      const encoded = JSON.stringify(init);
      expect(encoded).not.toContain("secret-req-1");
      expect(encoded).not.toContain("secret reason must not leak");
      expect(encoded).not.toContain("hidden-from-position-only");
    } finally {
      await denyFirstPending(rig);
      await decision;
    }
  });

  it("serves full /events init.pending rows to an operator bearer", async () => {
    const rig = await loopbackAutoAuthRig();
    const decision = rig.channel.requestApproval(SENSITIVE_APPROVAL);
    try {
      await new Promise((resolve) => setTimeout(resolve, 100));
      const res = await fetch(`${rig.base}/events`, { headers: rig.bearer });
      expect(res.status).toBe(200);
      const seen = await drainSSE(res, 800);
      const init = readEventData(seen, "init");
      expect(init.pending).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            operation: "secret-req-1",
            reason: "secret reason must not leak",
            context: { secret: "hidden-from-position-only" },
          }),
        ]),
      );
      expect(init.pending_approvals_redacted).toBeUndefined();
    } finally {
      await denyFirstPending(rig);
      await decision;
    }
  });

  it("redacts a live pending-request event on tokenless loopback /events when approval is raised after open", async () => {
    const rig = await loopbackAutoAuthRig();
    const res = await fetch(`${rig.base}/events`);
    expect(res.status).toBe(200);
    const drained = drainSSE(res, 1300);
    await new Promise((resolve) => setTimeout(resolve, 250));
    const decision = rig.channel.requestApproval(SENSITIVE_APPROVAL);
    try {
      const seen = await drained;
      const approval = readEventData(seen, "pending-request");
      expect(approval.pending_approvals_redacted).toBe(true);
      expect(approval.pending_approvals_count).toBe(1);
      const encoded = JSON.stringify(approval);
      expect(encoded).not.toContain("secret-req-1");
      expect(encoded).not.toContain("secret reason must not leak");
      expect(encoded).not.toContain("hidden-from-position-only");
    } finally {
      await denyFirstPending(rig);
      await decision;
    }
  });

  it("serves full pending approval rows to an operator bearer and to a session minted from it", async () => {
    const rig = await loopbackAutoAuthRig();
    const decision = rig.channel.requestApproval(SENSITIVE_APPROVAL);
    try {
      const bearerSnapshot = await fetch(`${rig.base}/api/snapshot`, {
        headers: rig.bearer,
      });
      expect(bearerSnapshot.status).toBe(200);
      const bearerBody = await bearerSnapshot.json();
      expect(bearerBody.pending_approvals).toHaveLength(1);
      expect(bearerBody.pending_approvals[0].operation).toBe("secret-req-1");
      expect(bearerBody.pending_approvals_redacted).toBeUndefined();

      const exchange = await fetch(`${rig.base}/auth/session`, {
        method: "POST",
        headers: rig.bearer,
      });
      expect(exchange.status).toBe(200);
      const { session_id: sessionId } = (await exchange.json()) as {
        session_id: string;
      };

      const sessionSnapshot = await fetch(
        `${rig.base}/api/snapshot?session=${encodeURIComponent(sessionId)}`,
      );
      expect(sessionSnapshot.status).toBe(200);
      const sessionBody = await sessionSnapshot.json();
      expect(sessionBody.pending_approvals).toHaveLength(1);
      expect(sessionBody.pending_approvals[0].reason).toBe(
        "secret reason must not leak",
      );
      expect(sessionBody.pending_approvals_redacted).toBeUndefined();

      const streamRes = await fetch(
        `${rig.base}/api/stream?session=${encodeURIComponent(sessionId)}`,
      );
      expect(streamRes.status).toBe(200);
      const streamSnapshot = await readInitialSnapshotEvent(streamRes);
      expect(streamSnapshot.pending_approvals).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ operation: "secret-req-1" }),
        ]),
      );
      expect(streamSnapshot.pending_approvals_redacted).toBeUndefined();
    } finally {
      await denyFirstPending(rig);
      await decision;
    }
  });

  it("treats a wrong bearer on ambient snapshot reads as position-only, matching the existing loopback fallback", async () => {
    const rig = await loopbackAutoAuthRig();
    const decision = rig.channel.requestApproval(SENSITIVE_APPROVAL);
    try {
      const res = await fetch(`${rig.base}/api/snapshot`, {
        headers: { Authorization: `Bearer ${TOKEN}-wrong` },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.pending_approvals).toEqual([]);
      expect(body.pending_approvals_redacted).toBe(true);
      expect(body.pending_approvals_count).toBe(1);
    } finally {
      await denyFirstPending(rig);
      await decision;
    }
  });

  it("CONTROL: /api/status remains tokenless-open and exposes only the count oracle", async () => {
    const rig = await loopbackAutoAuthRig();
    const decision = rig.channel.requestApproval(SENSITIVE_APPROVAL);
    try {
      const res = await fetch(`${rig.base}/api/status`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.pending_count).toBe(1);
      expect(JSON.stringify(body)).not.toContain("secret-req-1");
    } finally {
      await denyFirstPending(rig);
      await decision;
    }
  });
});
