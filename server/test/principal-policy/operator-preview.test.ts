import { describe, expect, it } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import * as gateModule from '../../src/principal-policy/gate.js';
import { DEFAULT_POLICY } from '../../src/principal-policy/loader.js';
import { BaselineTracker } from '../../src/principal-policy/baseline.js';
import { AuditLog } from '../../src/operational/audit-log.js';
import { MemoryStorage } from '../../src/storage/memory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer, toolResult } from '../../src/router.js';
import type { ApprovalRequest } from '../../src/principal-policy/types.js';

describe('bounded operator preview', () => {
  it('describes full signed bytes before truncation and caps oversized identifiers', () => {
    const bytes = Buffer.from('a full payload beyond summary truncation '.repeat(50));
    expect(gateModule.buildOperatorPreview('identity_sign', { payload: bytes.toString('base64url'), private_key: 'never' })).toEqual([
      { kind: 'byte_count', field: 'payload', value: bytes.length },
      { kind: 'digest12', field: 'payload', value: createHash('sha256').update(bytes).digest('hex').slice(0, 12) },
    ]);
    const preview = gateModule.buildOperatorPreview('state_export', { namespace: '\u0000'.repeat(10000), format: '\u0000'.repeat(10000), secret: 'never' });
    expect(preview).toHaveLength(2);
    expect(Buffer.byteLength(JSON.stringify(preview))).toBeLessThanOrEqual(gateModule.OPERATOR_PREVIEW_MAX_BYTES);
    expect(JSON.stringify(preview)).not.toContain('never');
    expect(gateModule.buildOperatorPreview('state_export', {})).toBeUndefined();
    for (const operation of ['unknown', 'sanctuary_forget', 'state_delete']) expect(gateModule.buildOperatorPreview(operation, { text: 'private' })).toBeUndefined();
  });
  it('emits only the closed per-operation table and host, never passage or payload text', () => {
    expect(gateModule.buildOperatorPreview('memory_insert', { text: 'private passage', tags: ['private', 'secret'] })).toEqual([{ kind: 'byte_count', field: 'memory', value: 15 }, { kind: 'item_count', field: 'tags', value: 2 }]);
    expect(gateModule.buildOperatorPreview('state_export', { namespace: 'notes', format: 'sanctuary-v1' })).toEqual([{ kind: 'subject', field: 'namespace', value: 'notes' }, { kind: 'subject', field: 'format', value: 'sanctuary-v1' }]);
    for (const operation of ['reputation_export', 'sanctuary_export_identity_bundle']) expect(gateModule.buildOperatorPreview(operation, { identity_id: 'operator' })).toEqual([{ kind: 'subject', field: 'identity_id', value: 'operator' }]);
    expect(gateModule.buildOperatorPreview('reputation_publish', { type: 'shr', verascore_url: 'https://user:secret@example.com/private?token=secret' })).toEqual([{ kind: 'subject', field: 'type', value: 'shr' }, { kind: 'subject', field: 'destination_host', value: 'example.com' }]);
  });
  it('keeps agent-visible denial byte-identical with and without a preview', async () => {
    const storage = new MemoryStorage(), key = randomBytes(32);
    const requests: ApprovalRequest[] = [];
    const channel = { requestApproval: async (request: ApprovalRequest) => { requests.push(request); return { decision: 'deny' as const, decided_by: 'human' as const, decided_at: '2026-10-28T00:00:00.000Z' }; } };
    const gate = new gateModule.ApprovalGate(DEFAULT_POLICY, new BaselineTracker(storage, key), channel, new AuditLog(storage, key));
    const server = createServer([{ name: 'identity_sign', description: 'test', tool_class: 'write', inputSchema: { type: 'object', properties: { payload: { type: 'string' } } }, handler: async () => toolResult({ executed: true }) }], { gate });
    const client = new Client({ name: 'preview-denial-test', version: '1.0.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      const withPreview = await client.callTool({ name: 'identity_sign', arguments: { payload: 'YXNk' } });
      expect(requests[0]!.operator_preview).toHaveLength(2);
      const original = channel.requestApproval;
      channel.requestApproval = request => { delete request.operator_preview; return original(request); };
      const withoutPreview = await client.callTool({ name: 'identity_sign', arguments: { payload: 'YXNk' } });
      expect(JSON.stringify(withPreview)).toBe(JSON.stringify(withoutPreview));
      expect(JSON.stringify(withPreview)).not.toContain('operator_preview');
    } finally { await client.close(); await server.close(); }
  });
});
