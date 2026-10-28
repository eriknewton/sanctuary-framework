import { afterEach, expect, it, vi } from 'vitest';
import { DashboardApprovalChannel } from '../../../src/principal-policy/dashboard.js';
import type { ApprovalResponse } from '../../../src/principal-policy/types.js';

const DEADLINE_MS = 1000; // The fixture's one-second approval budget.
afterEach(() => { vi.restoreAllMocks(); vi.clearAllTimers(); vi.useRealTimers(); });

it.each(['human-first', 'timer-first', 'human-at-deadline', 'human-after-deadline', 'shutdown-first'] as const)(
  'settles exactly once with consistent close bookkeeping: %s', async order => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-28T12:00:00Z'));
    const start = Date.now();
    const scheduled = vi.spyOn(globalThis, 'setTimeout');
    const channel = new DashboardApprovalChannel({ port: 0, host: '127.0.0.1', timeout_seconds: 1, auto_open: false });
    const inspect = channel as unknown as {
      pending: Map<string, { resolve(response: ApprovalResponse): void }>;
      resolveApprovalDecision(id: string, decision: 'approve'): boolean;
      rememberClosedApproval(id: string, decision: 'approve' | 'deny', by: 'human' | 'timeout' | 'shutdown', at: string): void;
    };
    const received = vi.fn();
    const result = channel.requestApproval({ operation: 'memory_insert', tier: 1, reason: '', context: {}, timestamp: new Date().toISOString() }).then(response => { received(response); return response; });
    const id = [...inspect.pending.keys()][0]!;
    const resolve = vi.spyOn(inspect.pending.get(id)!, 'resolve');
    // Capture the actual scheduled closure; explicit late delivery also exercises a callback already queued before cancellation.
    const timer = scheduled.mock.calls.find(call => call[1] === DEADLINE_MS)![0] as () => void;
    try {
      if (order === 'human-first') {
        vi.setSystemTime(start + DEADLINE_MS - 1);
        expect(inspect.resolveApprovalDecision(id, 'approve')).toBe(true);
        vi.setSystemTime(start + DEADLINE_MS);
        timer();
      } else if (order === 'timer-first') {
        vi.setSystemTime(start + DEADLINE_MS);
        timer();
        expect(inspect.resolveApprovalDecision(id, 'approve')).toBe(false);
      } else if (order === 'shutdown-first') {
        const remember = inspect.rememberClosedApproval.bind(channel);
        vi.spyOn(inspect, 'rememberClosedApproval').mockImplementation((...args) => {
          remember(...args);
          vi.setSystemTime(Date.now() + 1); // Clock movement between bookkeeping and response must not create two close timestamps.
        });
        await channel.stop();
        expect(inspect.resolveApprovalDecision(id, 'approve')).toBe(false);
        timer();
      } else {
        vi.setSystemTime(start + DEADLINE_MS + (order === 'human-after-deadline' ? 1 : 0));
        expect(inspect.resolveApprovalDecision(id, 'approve')).toBe(false);
        timer();
      }
      const response = await result;
      expect(resolve).toHaveBeenCalledTimes(1);
      expect(received).toHaveBeenCalledTimes(1);
      expect(inspect.pending.size).toBe(0);
      const expectedBy = order === 'human-first' ? 'human' : order === 'shutdown-first' ? 'auto' : 'timeout';
      expect(response).toMatchObject({ decision: order === 'human-first' ? 'approve' : 'deny', decided_by: expectedBy });
      // Shutdown's existing channel response is auto; the operator-only tombstone names that cause shutdown. No agent behavior changes.
      expect(channel.closedApproval(id)).toMatchObject({ decision: response.decision, decided_by: response.decided_by === 'auto' ? 'shutdown' : response.decided_by, decided_at: response.decided_at });
    } finally { await channel.stop(); }
  },
);
