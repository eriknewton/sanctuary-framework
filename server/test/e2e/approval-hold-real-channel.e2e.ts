import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer, toolResult } from '../../src/router.js';
import { memoryInsertApprovalArgs } from '../../src/sdw/memory-tools.js';
import { test, expect } from './fixtures/dashboard.js';
import { approvalHoldRig } from '../dashboard/v1_1/approval-hold-rig.js';

for (const width of [1600, 390]) {
  test(`real hold allows only on Confirm, with preview and readable controls at ${width}px`, async ({ page }) => {
    const rig = await approvalHoldRig(30);
    const held = rig.channel.requestApproval({ operation: 'memory_insert', tier: 1, reason: 'Tier 1', context: {}, timestamp: new Date().toISOString(), operator_preview: [{ kind: 'byte_count', field: 'memory', value: 1240 }, { kind: 'item_count', field: 'tags', value: 2 }] });
    try {
      await page.setViewportSize({ width, height: 900 });
      await page.addInitScript(token => sessionStorage.setItem('authToken', token), rig.token);
      await page.goto(rig.url + '/v1.1#approvals');
      await page.locator('[data-action="approval-select"]').first().click();
      const drawer = page.locator('.approval-drawer');
      await expect(drawer).toContainText('Save a memory: 1,240 bytes, 2 tags');
      await expect(drawer).toContainText(/Expires in \d+:\d{2}/);
      let settled = false; void held.then(() => { settled = true; });
      await drawer.locator('[data-action="approval-start-tier1-allow"]').click();
      expect(settled).toBe(false);
      const confirm = drawer.locator('[data-action="approval-confirm-tier1-allow"]');
      await expect(confirm).toContainText('Yes, allow');
      await expect(drawer).toContainText('This sends the approval');
      for (const theme of ['dark', 'light']) {
        await page.evaluate(theme === 'dark' ? 'document.documentElement.setAttribute("data-theme", "dark")' : 'document.documentElement.removeAttribute("data-theme")');
        const paints = await page.evaluate(`(() => {
          const button = document.querySelector('[data-action="approval-confirm-tier1-allow"]');
          const chip = button.querySelector('.held-subject');
          return { foreground: getComputedStyle(chip).color, chip: getComputedStyle(chip).backgroundColor, background: getComputedStyle(button).backgroundColor };
        })()`) as { foreground: string; chip: string; background: string };
        const luminance = (rgb: string) => rgb.match(/[\d.]+/g)!.slice(0, 3).map(Number).map(v => { v /= 255; return v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4; }).reduce((sum, v, i) => sum + v * [.2126, .7152, .0722][i]!, 0);
        const a = luminance(paints.foreground), b = luminance(paints.chip === 'rgba(0, 0, 0, 0)' ? paints.background : paints.chip);
        expect((Math.max(a, b) + .05) / (Math.min(a, b) + .05)).toBeGreaterThanOrEqual(4.5);
      }
      const buttonBox = (await confirm.boundingBox())!;
      const hintBox = (await drawer.locator('.approval-confirm-row p').boundingBox())!;
      expect(buttonBox.y + buttonBox.height).toBeLessThanOrEqual(hintBox.y);
      expect(buttonBox.x + buttonBox.width).toBeLessThanOrEqual(width);
      await confirm.click();
      expect(await held).toMatchObject({ decision: 'approve', decided_by: 'human' });
    } finally { await page.close(); await rig.stop(); await held; }
  });
}

test('expired real hold drops armed Confirm, disables decisions and never posts', async ({ page }) => {
  const rig = await approvalHoldRig(4);
  // Load first so the four-second window measures review, not browser startup.
  try {
    await page.addInitScript(token => sessionStorage.setItem('authToken', token), rig.token);
    await page.goto(rig.url + '/v1.1#approvals');
    await expect(page.locator('#main')).toContainText('Held operations');
    const posts: string[] = [];
    page.on('request', request => { if (request.method() === 'POST' && request.url().includes('/api/hub/inbox/')) posts.push(request.url()); });
    const held = rig.channel.requestApproval({ operation: 'memory_insert', tier: 1, reason: 'Tier 1', context: {}, timestamp: new Date().toISOString() });
    await page.locator('[data-action="approval-select"]').first().click();
    await page.locator('[data-action="approval-start-tier1-allow"]').click();
    await expect(page.locator('[data-action="approval-confirm-tier1-allow"]')).toBeVisible();
    expect(await held).toMatchObject({ decision: 'deny', decided_by: 'timeout' });
    await expect(page.locator('.approval-drawer')).toContainText('This request expired after 4 seconds and was denied automatically.');
    await expect(page.locator('[data-action="approval-start-tier1-allow"]')).toBeDisabled();
    await expect(page.locator('.approval-drawer [data-action="inbox-deny"]')).toBeDisabled();
    await expect(page.locator('[data-action="approval-confirm-tier1-allow"]')).toHaveCount(0);
    expect(posts).toEqual([]);
  } finally { await page.close(); await rig.stop(); }
});

test('server restart with the same token reconnects without a click and explains denied holds', async ({ page }) => {
  const rig = await approvalHoldRig(30);
  try {
    await page.addInitScript(token => sessionStorage.setItem('authToken', token), rig.token);
    const firstStream = page.waitForResponse(response => new URL(response.url()).pathname === '/api/stream' && response.status() === 200);
    await page.goto(rig.url + '/v1.1#approvals');
    await firstStream;
    const held = rig.channel.requestApproval({ operation: 'memory_insert', tier: 1, reason: 'Tier 1', context: {}, timestamp: new Date().toISOString() });
    await expect(page.locator('[data-action="approval-select"]').first()).toBeVisible();
    const offlineSession = page.waitForEvent('requestfailed', { predicate: request => new URL(request.url()).pathname === '/auth/session' });
    await rig.channel.stop();
    expect(await held).toMatchObject({ decision: 'deny', decided_by: 'auto' });
    await offlineSession;
    const reopened = page.waitForResponse(response => new URL(response.url()).pathname === '/api/stream' && response.status() === 200);
    await rig.channel.start();
    await reopened;
    const banner = page.locator('[data-stream-recovery-banner]');
    await expect(banner).toHaveCount(1);
    await expect(banner).toHaveText('The server restarted. Requests that were waiting before the restart were denied.');
    await expect(page.locator('[data-action="approval-select"]')).toHaveCount(0);
  } finally { await page.close(); await rig.stop(); }
});

test('router memory excerpt reaches only the operator card through the real gate and channel', async ({ page }) => {
  const rig = await approvalHoldRig(30);
  const server = createServer([{ name: 'memory_insert', description: 'test', tool_class: 'write', approvalTargetArgs: memoryInsertApprovalArgs,
    inputSchema: { type: 'object', properties: { text: { type: 'string' }, tags: { type: 'array', items: { type: 'string' } } } }, handler: async () => toolResult({ executed: true }) }], { gate: rig.gate });
  const client = new Client({ name: 'browser-memory-preview', version: '1.0.0' });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(b); await client.connect(a);
  const text = '<script>alert(1)</script>\n<img onerror="alert(2)" src=x>\n<a href="javascript:alert(3)">link</a>\n' + 'a'.repeat(600);
  const held = client.callTool({ name: 'memory_insert', arguments: { text, tags: ['one', 'two'] } });
  try {
    await page.addInitScript(token => sessionStorage.setItem('authToken', token), rig.token);
    await page.goto(rig.url + '/v1.1#approvals');
    await page.locator('[data-action="approval-select"]').first().click();
    const drawer = page.locator('.approval-drawer');
    await expect(drawer).toContainText('Save a memory: ' + Buffer.byteLength(text).toLocaleString('en-US') + ' bytes, 2 tags');
    await expect(drawer).toContainText('(cut to the first 600 characters)');
    const quote = drawer.locator('.approval-passage');
    await expect(quote).toContainText('<script>alert(1)</script>');
    await expect(quote).toContainText('javascript:alert(3)');
    await expect(quote.locator('script,img,a')).toHaveCount(0);
    await expect(quote.locator('br')).toHaveCount(3);
    await drawer.locator('[data-action="inbox-deny"]').click();
    expect(JSON.stringify(await held)).not.toContain('alert(');
    const audit = await rig.auditLog.query({});
    expect(JSON.stringify(audit)).not.toContain('alert(');
  } finally { await page.close(); await rig.stop(); await held; await client.close(); await server.close(); }
});
