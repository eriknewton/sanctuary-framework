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
import { memoryInsertApprovalArgs } from '../../src/sdw/memory-tools.js';
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
  it('emits only the closed per-operation table and host, with memory text only in its excerpt', () => {
    expect(gateModule.buildOperatorPreview('memory_insert', { text: 'private passage', tags: ['private', 'secret'] })).toEqual([{ kind: 'byte_count', field: 'memory', value: 15 }, { kind: 'item_count', field: 'tags', value: 2 }, { kind: 'passage_excerpt', field: 'memory', value: 'private passage', truncated: false }]);
    expect(gateModule.buildOperatorPreview('state_export', { namespace: 'notes', format: 'sanctuary-v1' })).toEqual([{ kind: 'subject', field: 'namespace', value: 'notes', truncated: false }, { kind: 'subject', field: 'format', value: 'sanctuary-v1', truncated: false }]);
    for (const operation of ['reputation_export', 'sanctuary_export_identity_bundle']) expect(gateModule.buildOperatorPreview(operation, { identity_id: 'operator' })).toEqual([{ kind: 'subject', field: 'identity_id', value: 'operator', truncated: false }]);
    expect(gateModule.buildOperatorPreview('reputation_publish', { type: 'shr', verascore_url: 'https://user:secret@example.com/private?token=secret' })).toEqual([{ kind: 'subject', field: 'type', value: 'shr', truncated: false }, { kind: 'subject', field: 'destination_host', value: 'example.com', truncated: false }]);
  });
  it.each(['denial', 'audit'])('keeps memory excerpt operator-only: %s', async (witness) => {
    const text = 'OPERATOR-ONLY-MEMORY-PASSAGE';
    const storage = new MemoryStorage(), key = randomBytes(32);
    const auditLog = new AuditLog(storage, key);
    const requests: ApprovalRequest[] = [];
    const channel = { requestApproval: async (request: ApprovalRequest) => { requests.push(request); return { decision: 'deny' as const, decided_by: 'human' as const, decided_at: '2026-10-28T00:00:00.000Z' }; } };
    const gate = new gateModule.ApprovalGate(DEFAULT_POLICY, new BaselineTracker(storage, key), channel, auditLog);
    const server = createServer([{ name: 'memory_insert', description: 'test', tool_class: 'write', approvalTargetArgs: memoryInsertApprovalArgs, inputSchema: { type: 'object', properties: { text: { type: 'string' }, tags: { type: 'array', items: { type: 'string' } } } }, handler: async () => toolResult({ executed: true }) }], { gate });
    const client = new Client({ name: 'preview-denial-test', version: '1.0.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      const withPreview = await client.callTool({ name: 'memory_insert', arguments: { text, tags: ['notes'] } });
      expect(requests[0]!.operator_preview).toContainEqual({ kind: 'passage_excerpt', field: 'memory', value: text, truncated: false });
      expect(JSON.stringify(requests[0])).not.toContain(text);
      if (witness === 'audit') {
        const audit = await auditLog.query({});
        expect(audit.entries.some(entry => entry.operation === 'gate_deny:memory_insert')).toBe(true);
        expect(JSON.stringify(audit)).not.toContain(text);
      } else {
        const original = channel.requestApproval;
        channel.requestApproval = request => { delete request.operator_preview; return original(request); };
        const withoutPreview = await client.callTool({ name: 'memory_insert', arguments: { text, tags: ['notes'] } });
        expect(JSON.stringify(withPreview)).toBe(JSON.stringify(withoutPreview));
      }
      expect(JSON.stringify(withPreview)).not.toContain(text);
      expect(JSON.stringify(withPreview)).not.toContain('operator_preview');
    } finally { await client.close(); await server.close(); }
  });
  it('caps oversized passages on code-point boundaries and bounds the entire serialized record', () => {
    const text = 'a'.repeat(599) + '😀' + 'tail'.repeat(10000);
    const preview = gateModule.buildOperatorPreview('memory_insert', { text, tags: ['tag'], secret_text: 'SECRET-KEY' })!;
    expect(preview).toContainEqual({ kind: 'passage_excerpt', field: 'memory', value: 'a'.repeat(599), truncated: true });
    expect(preview).toContainEqual({ kind: 'byte_count', field: 'memory', value: Buffer.byteLength(text) });
    const worst = gateModule.buildOperatorPreview('memory_insert', { text: '\u0000'.repeat(100000), tags: Array(10000).fill('secret') })!;
    expect(worst).toHaveLength(3);
    expect(worst[2]).toEqual({ kind: 'passage_excerpt', field: 'memory', value: '\u0000'.repeat(600), truncated: true });
    expect(Buffer.byteLength(JSON.stringify(worst))).toBeLessThanOrEqual(gateModule.OPERATOR_PREVIEW_MAX_BYTES);
    expect(gateModule.OPERATOR_PREVIEW_MAX_BYTES).toBe(1794 + 6 * 600 + 128);
    expect(JSON.stringify(preview)).not.toContain('SECRET-KEY');
    expect(gateModule.buildOperatorPreview('memory_insert', { text: 'a'.repeat(598) + '😀' })![1]).toMatchObject({ value: 'a'.repeat(598) + '😀', truncated: false });
    expect(gateModule.buildOperatorPreview('memory_insert', { secret_text: 'never' })).toBeUndefined();
  });
});
