// Real fresh-process CLI composition; only test custody, human approval, and
// host liveness are injected. Filesystem state and auditing remain real.
import { mock } from 'node:test';
import { setKeychainExec } from '../../../src/wrap/keychain-exec.ts';
setKeychainExec(async () => { throw new Error('Unexpected credential access in checkpoint fixture'); });
const custodyUrl = new URL('../../../src/core/master-custody.ts', import.meta.url);
const custody = await import(custodyUrl.href);
mock.module(custodyUrl.href, { namedExports: {
  ...custody,
  resolveCliMasterKey: async () => Buffer.from(process.env.CHECKPOINT_TEST_MASTER_KEY, 'hex'),
} });
const { ApprovalGate } = await import('../../../src/principal-policy/gate.ts');
mock.method(ApprovalGate.prototype, 'evaluate', async () => ({ allowed: true }));
const parkedUrl = new URL('../../../src/egress-gate/parked-claim.ts', import.meta.url);
const parked = await import(parkedUrl.href);
mock.module(parkedUrl.href, { namedExports: {
  ...parked,
  assessHarnessParked: async () => ({ state: 'parked', sentence: 'Test harness is parked.' }),
} });
const { runCheckpointCommand } = await import('../../../src/cli/checkpoint.ts');
process.exitCode = await runCheckpointCommand({ argv: process.argv.slice(2) });
