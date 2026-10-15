/**
 * The shape the dashboard's audit log read serves, pinned on the server side.
 *
 * The console's Evidence screen exports this read as JSON (`onEvidenceJsonExport`
 * in `server/src/dashboard/v1_1/client.ts`), and its client tests mock the
 * route. This file pins what the route actually serves so a client mock can
 * be checked against it: with an audit log, the `AuditLog.query` result
 * object; without one, an empty array.
 */
// fail-before-exempt: pins the shape main's audit log route already serves; this change adds no server behavior, so the pin passes before and after by design.

import { describe, it, expect, afterEach } from "vitest";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  bindWithRetry,
  randomTestPort,
} from "../util/port-collision-retry.js";

const TOKEN = "audit-log-route-shape-token-0123456789abcdef";

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

async function startChannel(withAuditLog: boolean): Promise<{ channel: DashboardApprovalChannel; base: string; auditLog: AuditLog | null }> {
  let channel: DashboardApprovalChannel | undefined;
  let auditLog: AuditLog | null = null;
  let port = 0;
  await bindWithRetry(async () => {
    port = randomTestPort();
    channel = new DashboardApprovalChannel({
      port,
      host: "127.0.0.1",
      timeout_seconds: 30,
      auto_deny: true,
      auth_token: TOKEN,
      auto_open: false,
    });
    if (withAuditLog) {
      auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
      channel.setDependencies({ policy: STUB_POLICY, baseline: STUB_BASELINE, auditLog });
    }
    await channel.start();
  });
  return { channel: channel!, base: `http://127.0.0.1:${port}`, auditLog };
}

describe("the dashboard audit log read's served shape", () => {
  const channels: DashboardApprovalChannel[] = [];
  afterEach(async () => {
    for (const channel of channels.splice(0)) await channel.stop();
  });

  // Must match the shape the Evidence export test in test/dashboard/v1_1/shell-wired-consumers.test.ts mocks.
  it("serves the query result object, with entries, total and integrity findings, when an audit log is wired", async () => {
    const rig = await startChannel(true);
    channels.push(rig.channel);
    await rig.auditLog!.append("l1", "audit_log_route_shape_probe", "identity-route-shape", { probe: true });
    await rig.auditLog!.flush();
    const res = await fetch(`${rig.base}/api/audit-log`, { headers: { Authorization: `Bearer ${TOKEN}` } });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(Array.isArray(body)).toBe(false);
    expect(Object.keys(body).sort()).toEqual(["entries", "integrity_findings", "total"]);
    expect(Array.isArray(body.entries)).toBe(true);
    expect(Array.isArray(body.integrity_findings)).toBe(true);
    const entries = body.entries as Array<Record<string, unknown>>;
    expect(entries.map((e) => e.operation)).toContain("audit_log_route_shape_probe");
    expect(body.total).toBe(entries.length);
  });

  it("serves an empty array when no audit log is wired", async () => {
    const rig = await startChannel(false);
    channels.push(rig.channel);
    const res = await fetch(`${rig.base}/api/audit-log`, { headers: { Authorization: `Bearer ${TOKEN}` } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual([]);
  });
});
