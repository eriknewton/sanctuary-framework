import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DashboardApprovalChannel } from '../../../src/principal-policy/dashboard.js';
import { buildV11Bindings } from '../../../src/dashboard/v1_1/wiring.js';
import { MemoryStorage } from '../../../src/storage/memory.js';
import { AuditLog } from '../../../src/operational/audit-log.js';
import { BaselineTracker } from '../../../src/principal-policy/baseline.js';
import { ApprovalGate } from '../../../src/principal-policy/gate.js';
import { DEFAULT_POLICY, parsePolicy } from '../../../src/principal-policy/loader.js';
import { OperatorAuthorizationSpentStore } from '../../../src/v1/operator-authorization-spent-store.js';
import { getFreePort } from '../../helpers/free-port.js';

/** Real channel, gate and v1.1 route composition; all storage is temporary or in memory. */
export async function approvalHoldRig(timeoutSeconds = 20, options: { port?: number; token?: string } = {}) {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  const baseline = new BaselineTracker(storage, masterKey);
  const storagePath = await mkdtemp(join(tmpdir(), 'approval-hold-'));
  const token = options.token ?? randomBytes(32).toString('hex');
  const port = options.port ?? await getFreePort();
  const channel = new DashboardApprovalChannel({ port, host: '127.0.0.1', timeout_seconds: timeoutSeconds, auth_token: token, auto_open: false });
  const policy = parsePolicy(JSON.stringify({ ...DEFAULT_POLICY, memory_save_approval: "always" }));
  channel.setDependencies({ policy, baseline, auditLog });
  await channel.setOperatorAuthorizationSpentStore(OperatorAuthorizationSpentStore.durableFromBoot(storage, masterKey));
  const bindings = buildV11Bindings({ identityId: 'approval-test', fortressId: 'approval-fortress', storage, masterKey, auditLog, storagePath, warnProducerKeyUnavailable: () => {} });
  channel.setV11Bindings(bindings);
  const gate = new ApprovalGate(policy, baseline, channel, auditLog);
  await channel.start();
  const url = `http://127.0.0.1:${port}`;
  const request = (path: string, method = 'GET') => fetch(url + path, { method, headers: { Connection: 'close', Authorization: `Bearer ${token}`, ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}) }, ...(method === 'POST' ? { body: '{}' } : {}) });
  return { channel, bindings, gate, auditLog, url, token, request,
    stop: async () => { await channel.stop(); await rm(storagePath, { recursive: true, force: true }); } };
}
