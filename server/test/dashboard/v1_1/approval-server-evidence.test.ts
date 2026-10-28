import { expect, it, vi } from 'vitest';
import { approvalHoldRig } from './approval-hold-rig.js';

async function bootId(rig: Awaited<ReturnType<typeof approvalHoldRig>>) {
  const controller = new AbortController();
  try {
    const response = await fetch(rig.url + '/api/stream', { headers: { Connection: 'close', Authorization: 'Bearer ' + rig.token }, signal: controller.signal });
    const reader = response.body!.getReader();
    let data = '';
    while (!data.includes('event: snapshot\ndata: ')) data += new TextDecoder().decode((await reader.read()).value);
    while (!data.slice(data.indexOf('event: snapshot')).includes('\n\n')) data += new TextDecoder().decode((await reader.read()).value);
    return JSON.parse(data.split('event: snapshot\ndata: ')[1]!.split('\n\n')[0]!).server_boot_id;
  } finally { controller.abort(); }
}

it('inbox reads publish server time and stream boot identity survives an in-process restart', async () => {
  const rig = await approvalHoldRig();
  try {
    const before = Date.now();
    const body = await (await rig.request('/api/hub/inbox')).json() as any;
    expect(body.data.server_now).toEqual(expect.stringMatching(/^\d{4}-.*Z$/));
    expect(Date.parse(body.data.server_now)).toBeGreaterThanOrEqual(before);
    expect(Date.parse(body.data.server_now)).toBeLessThanOrEqual(Date.now());
    const first = await bootId(rig);
    expect(first).toEqual(expect.stringMatching(/^[a-f0-9]{32}$/));
    await rig.channel.stop(); await rig.channel.start();
    expect(await bootId(rig)).toBe(first);
  } finally { await rig.stop(); }
});

it('a shutdown hold retry after in-process restart returns approval_not_found', async () => {
  const rig = await approvalHoldRig();
  const held = rig.gate.evaluate('memory_insert', { text_redacted: true, text_bytes: 12, tag_count: 0 });
  try {
    let id: string | undefined;
    await vi.waitFor(async () => { const body = await (await rig.request('/api/hub/inbox')).json() as any; id = body.data.items[0]?.item_id; expect(id).toBeTruthy(); });
    await rig.channel.stop(); await held; await rig.channel.start();
    const response = await rig.request('/api/hub/inbox/' + id + '/approve', 'POST');
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ ok: false, public_code: 'approval_not_found' });
  } finally { await rig.stop(); await held; }
});
