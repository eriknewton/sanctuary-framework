import { describe, expect, it, vi } from 'vitest';
import { randomBytes } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer, toolResult } from '../../src/router.js';
import { ApprovalGate } from '../../src/principal-policy/gate.js';
import { DEFAULT_POLICY } from '../../src/principal-policy/loader.js';
import { BaselineTracker } from '../../src/principal-policy/baseline.js';
import { AuditLog } from '../../src/operational/audit-log.js';
import { MemoryStorage } from '../../src/storage/memory.js';
import { memoryInsertApprovalArgs } from '../../src/sdw/memory-tools.js';
import type { ApprovalRequest } from '../../src/principal-policy/types.js';

describe('server-owned operator preview handoff', () => {
  it.each(['memory_insert', 'state_export', 'identity_list'])('leaves %s enforcement arguments, binding and response byte-identical', async name => {
    const args = name === 'memory_insert' ? { text: 'private passage', tags: ['tag'] } : name === 'state_export' ? { namespace: 'notes', format: 'sanctuary-v1' } : {};
    const storage = new MemoryStorage(), key = randomBytes(32);
    const requests: ApprovalRequest[] = [];
    const gate = new ApprovalGate(DEFAULT_POLICY, new BaselineTracker(storage, key), { requestApproval: async request => {
      requests.push(request); return { decision: 'deny', decided_by: 'human', decided_at: '2026-10-28T00:00:00.000Z' };
    } }, new AuditLog(storage, key));
    const evaluate = gate.evaluate.bind(gate);
    let stripHandoff = false;
    const calls: unknown[][] = [];
    vi.spyOn(gate, 'evaluate').mockImplementation((...input) => {
      calls.push(input);
      return evaluate(input[0], input[1], input[2], stripHandoff ? undefined : input[3]);
    });
    const server = createServer([{ name, description: 'test', tool_class: name === 'identity_list' ? 'read' : 'write', inputSchema: { type: 'object', properties: { text: { type: 'string' }, tags: { type: 'array', items: { type: 'string' } }, namespace: { type: 'string' }, format: { type: 'string' } } },
      ...(name === 'memory_insert' ? { approvalTargetArgs: memoryInsertApprovalArgs } : {}), handler: async () => toolResult({ completed: true }) }], { gate });
    const client = new Client({ name: 'handoff-test', version: '1.0.0' });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await server.connect(b); await client.connect(a);
    try {
      const withHandoff = await client.callTool({ name, arguments: args });
      expect(calls[0]![3]).toEqual({ operation: name, args });
      stripHandoff = true;
      const withoutHandoff = await client.callTool({ name, arguments: args });
      const projected = name === 'memory_insert' ? memoryInsertApprovalArgs(args) : args;
      expect(JSON.stringify(calls[0]!.slice(0, 3))).toBe(JSON.stringify([name, projected, undefined]));
      expect(JSON.stringify(calls[1]!.slice(0, 3))).toBe(JSON.stringify(calls[0]!.slice(0, 3)));
      expect(JSON.stringify(withHandoff)).toBe(JSON.stringify(withoutHandoff));
      if (name === 'identity_list') {
        expect(requests).toHaveLength(0);
        expect(withHandoff.isError).not.toBe(true);
      } else {
        expect(requests).toHaveLength(2);
        expect(requests[0]!.args_binding).toBe(requests[1]!.args_binding);
        expect(JSON.stringify(requests[0]!.context)).toBe(JSON.stringify(requests[1]!.context));
        if (name === 'memory_insert') {
          expect(requests[0]!.operator_preview).toContainEqual({ kind: 'passage_excerpt', field: 'memory', value: args.text, truncated: false });
          expect(requests[1]!.operator_preview?.some(arg => arg.kind === 'passage_excerpt')).toBe(false);
        }
      }
    } finally { await client.close(); await server.close(); }
  });
});
