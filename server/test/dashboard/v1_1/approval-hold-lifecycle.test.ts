import { afterEach, describe, expect, it, vi } from 'vitest';
import { approvalHoldRig } from './approval-hold-rig.js';
import * as dashboardModule from '../../../src/principal-policy/dashboard.js';

let rig: Awaited<ReturnType<typeof approvalHoldRig>> | undefined;
afterEach(async () => { if (rig) await rig.stop(); rig = undefined; vi.useRealTimers(); });
async function held() {
  const result = rig!.gate.evaluate('memory_insert', { text_redacted: true, text_bytes: 1240, tag_count: 2 });
  let item: any;
  await vi.waitFor(async () => { item = (await (await rig!.request('/api/hub/inbox')).json() as { data: { items: any[] } }).data.items.find((i: any) => !i.resolved); expect(item).toBeTruthy(); });
  return { result, item };
}
async function decide(id: string) {
  const res = await rig!.request('/api/hub/inbox/' + id + '/approve', 'POST');
  return { status: res.status, body: await res.json() };
}
describe('approval hold real route lifecycle', () => {
  it('streams closure at expiry and a human decision, and audits timeout', async () => {
    rig = await approvalHoldRig(1);
    const controller = new AbortController();
    const res = await fetch(rig.url + '/api/stream', { headers: { Authorization: 'Bearer ' + rig.token }, signal: controller.signal });
    const reader = res.body!.getReader();
    let frames = '';
    const reading = (async () => { try { while (true) { const next = await reader.read(); if (next.done) break; frames += new TextDecoder().decode(next.value); } } catch { /* Abort owns teardown. */ } })();
    try {
      const first = await held();
      await first.result;
      await vi.waitFor(() => expect(frames).toContain('"resolved":true'));
      expect(frames).toContain('event: approval');
      expect(first.item.operator_preview).toEqual([{ kind: 'byte_count', field: 'memory', value: 1240 }, { kind: 'item_count', field: 'tags', value: 2 }]);
      expect(Date.parse(first.item.expires_at) - Date.parse(first.item.created_at)).toBe(1000);
      expect(frames).toContain('"id":"' + first.item.item_id.replace('charter.approval.', '') + '"');
      const audit = await rig.auditLog.query({ operation_type: 'gate_deny:memory_insert', limit: 10 });
      expect(audit.entries[0]!.details).toMatchObject({ decided_by: 'timeout' });
      frames = '';
      const second = await held();
      expect((await decide(second.item.item_id)).status).toBe(200);
      await second.result;
      await vi.waitFor(() => expect(frames).toContain('"resolved":true'));
    } finally { controller.abort(); await reading; }
  });
  it('returns typed expired, already-decided and unknown misses over the real POST', async () => {
    rig = await approvalHoldRig(1);
    const first = await held();
    await first.result;
    expect(await decide(first.item.item_id)).toEqual({ status: 409, body: { ok: false, public_code: 'approval_expired', expired_after_seconds: 1 } });
    const second = await held();
    await decide(second.item.item_id);
    await second.result;
    const again = await decide(second.item.item_id);
    expect(again.status).toBe(409);
    expect(again.body).toEqual({ ok: false, public_code: 'approval_already_decided', decided_by: 'human', decided_at: expect.stringMatching(/^\d{4}-.*Z$/) });
    expect(await decide('charter.approval.unknown')).toEqual({ status: 404, body: { ok: false, public_code: 'approval_not_found' } });
  });
  it('keeps non-approval failure responses scrubbed', async () => {
    rig = await approvalHoldRig();
    vi.spyOn(rig.bindings.hubService, 'resolveInboxItem').mockRejectedValue(new Error('PRIVATE-KEY must never escape'));
    const answer = await decide('arbitrary');
    expect(answer.status).toBe(500);
    expect(JSON.stringify(answer.body)).not.toContain('PRIVATE-KEY');
    // Exact base envelope captured by this witness before changes.
    expect(answer.body).toEqual({ error: 'internal_error' });
  });
});

it('bounds tombstone growth, evicts oldest and expires at the TTL', async () => {
  vi.useFakeTimers();
  const channel = new dashboardModule.DashboardApprovalChannel({ port: 0, host: '127.0.0.1', timeout_seconds: 1, auto_open: false });
  const inspect = channel as unknown as { pending: Map<string, unknown>; closedHolds: Map<string, unknown>; closedApproval(id: string): unknown; resolveApprovalDecision(id: string, decision: 'deny'): boolean };
  const ids: string[] = [];
  const waits: Promise<unknown>[] = [];
  const cap = 256; // Dispatch retention budget; two extra entries prove oldest-first eviction.
  try {
    for (let i = 0; i < cap + 2; i++) {
      waits.push(channel.requestApproval({ operation: 'memory_insert', tier: 1, reason: '', context: {}, timestamp: new Date().toISOString() }));
      const id = [...inspect.pending.keys()][0]!;
      ids.push(id);
      inspect.resolveApprovalDecision(id, 'deny');
    }
    expect(inspect.closedHolds?.size).toBe(cap);
    expect([...inspect.closedHolds.keys()]).toEqual(ids.slice(2));
    await vi.advanceTimersByTimeAsync(10 * 60 * 1000);
    expect(inspect.closedApproval(ids.at(-1)!)).toBeNull();
    expect(inspect.closedHolds.size).toBe(0);
  } finally { await channel.stop(); await Promise.all(waits); vi.clearAllTimers(); }
});

it('denies a late human decision before a delayed timeout callback runs', async () => {
  vi.useFakeTimers();
  const channel = new dashboardModule.DashboardApprovalChannel({ port: 0, host: '127.0.0.1', timeout_seconds: 1, auto_open: false });
  const inspect = channel as unknown as { pending: Map<string, unknown>; resolveApprovalDecision(id: string, decision: 'approve'): boolean };
  const result = channel.requestApproval({ operation: 'memory_insert', tier: 1, reason: '', context: {}, timestamp: new Date().toISOString() });
  try {
    const id = [...inspect.pending.keys()][0]!;
    vi.setSystemTime(Date.now() + 1001); // Move the clock beyond the deadline without delivering timer callbacks.
    expect(inspect.resolveApprovalDecision(id, 'approve')).toBe(false);
    expect(await result).toMatchObject({ decision: 'deny', decided_by: 'timeout' });
    expect(channel.closedApproval(id)).toMatchObject({ decision: 'deny', decided_by: 'timeout' });
    await vi.runOnlyPendingTimersAsync();
    expect(inspect.pending.size).toBe(0);
  } finally { await channel.stop(); vi.clearAllTimers(); }
});

it('redacts expiry stream frames for a loopback-position reader', async () => {
  rig = await approvalHoldRig(1);
  rig.channel.setAutoAuthLocalhost(true);
  const controller = new AbortController();
  const res = await fetch(rig.url + '/api/stream', { signal: controller.signal });
  expect(res.status).toBe(200);
  const reader = res.body!.getReader();
  let frames = '';
  const reading = (async () => { try { while (true) { const next = await reader.read(); if (next.done) break; frames += new TextDecoder().decode(next.value); } } catch { /* Abort owns teardown. */ } })();
  try {
    const first = await held();
    frames = '';
    await first.result;
    await vi.waitFor(() => expect(frames).toContain('"pending_approvals_count":0'));
    expect(frames).toContain('event: approval');
    expect(frames).not.toContain(first.item.item_id.replace('charter.approval.', ''));
    expect(frames).not.toContain('memory_insert');
    expect(frames).not.toContain('operator_preview');
  } finally { controller.abort(); await reading; }
});
