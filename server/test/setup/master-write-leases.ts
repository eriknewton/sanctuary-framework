import { afterAll, aroundAll, expect } from "vitest";
import { setTimeout as setRealTimeout, clearTimeout as clearRealTimeout } from "node:timers";
import { performance } from "node:perf_hooks";
import { leaseGuardHookTimeoutMs } from "../../vitest.config.js";
import { relative } from "node:path";
import { fileURLToPath } from "node:url";
import type { MasterWriteBarrierLease } from "../../src/storage/cross-process-lock.js";

// Existing owners are named explicitly so an unrelated file can never inherit an exemption.
const existingLeaseOwners = new Set<string>([
  "test/agent-native/first-class-surfacing.test.ts",
  "test/agent-native/phase2-cooperative-surface.test.ts",
  "test/agent-native/protection-layers.test.ts",
  "test/anomaly-detection/anomaly-ux.test.ts",
  "test/audit/checkpoint-signer-wiring.test.ts",
  "test/auto-trigger/auto-trigger.test.ts",
  "test/castle-wall/legacy-fortress-no-claim.test.ts",
  "test/castle-wall/observe/cli-option-a.test.ts",
  "test/castle-wall/observe/promote-enforcement-reach.test.ts",
  "test/cli/agents-config-approval-redirect.test.ts",
  "test/cli/anomaly-sentinel-subscription-audit.test.ts",
  "test/cli/audit-search.test.ts",
  "test/cli/auto-trigger-audit.test.ts",
  "test/cli/castle-wall-audit-regate-repros.test.ts",
  "test/cli/cortex-export-command.test.ts",
  "test/cli/distress.test.ts",
  "test/cli/doctor.test.ts",
  "test/cli/exit-export-did-web-auto-include.test.ts",
  "test/cli/federation-operator-ux.test.ts",
  "test/cli/federation-revoke-push.test.ts",
  "test/cli/file-grant-revoke-error-handling.test.ts",
  "test/cli/fleet.test.ts",
  "test/cli/identity-create.test.ts",
  "test/cli/import-state-warning.test.ts",
  "test/cli/license.test.ts",
  "test/cli/local-fortress-unlock.test.ts",
  "test/cli/memory-archive.test.ts",
  "test/cli/memory-file.test.ts",
  "test/cli/sdw-owner.test.ts",
  "test/cli/secrets-surrogate-operator.test.ts",
  "test/cli/secrets-surrogate.test.ts",
  "test/cli/secrets.test.ts",
  "test/cli/singleton-audit-writes.test.ts",
  "test/cli/verify-transparency-counter-floor.test.ts",
  "test/dashboard-slice2-park.test.ts",
  "test/dashboard-standalone-enrolled-custody.test.ts",
  "test/dashboard-standalone-v010-4.test.ts",
  "test/dashboard-standalone-v010-5.test.ts",
  "test/dashboard-standalone-v010-6.test.ts",
  "test/dashboard-standalone.test.ts",
  "test/dashboard/protection-observations.test.ts",
  "test/dashboard/snapshot-source-of-truth.test.ts",
  "test/disclosure/broker/token-prune-fortress-unlock.test.ts",
  "test/exit/exit-bundle-envelope-custody.test.ts",
  "test/exit/exit-export-namespace-discovery.test.ts",
  "test/exit/exit-import-atomic-activation.test.ts",
  "test/exit/exit-recover-verb.test.ts",
  "test/exit/fortress-open-recovery-wiring.test.ts",
  "test/hermes-memory-bridge/process-shell.test.ts",
  "test/manifest-honest-grades.test.ts",
  "test/operational/audit-log-hardening-r.test.ts",
  "test/policy-engine/english-policy-activator.test.ts",
  "test/policy-engine/english-policy-compiler.test.ts",
  "test/principal-policy/gate-requesting-agent-wiring.test.ts",
  "test/principal-policy/memory-saves-silent-wiring.test.ts",
  "test/principal-policy/reputation-publish-approval-tier.test.ts",
  "test/proxy/response-cleanup.test.ts",
  "test/proxy/response-composition.test.ts",
  "test/sdw/sdw-vault-tools-wiring.test.ts",
  "test/security/agent-audit-allowlist.test.ts",
  "test/security/boot-credential-shared-resolver.test.ts",
  "test/security/cred-return-hardening.test.ts",
  "test/security/custody-unification.test.ts",
  "test/security/f5-dashboard-bind-degrade.test.ts",
  "test/security/h1-hands-free-boot.test.ts",
  "test/security/index-keychain-factor-zeroization.test.ts",
  "test/security/intelligence-boot-integrity-checkpoint.test.ts",
  "test/security/sec-020-recovery-key-restart.test.ts",
  "test/security/sec-036-reputation-publish.test.ts",
  "test/security/self-vouch-composition-wiring.test.ts",
  "test/sentinel/sentinel-framework.test.ts",
  "test/structure/dashboard-fold-retirement.test.ts",
  "test/structure/public-surface-snapshot.test.ts",
  "test/structure/reorg-surface-snapshots.test.ts",
  "test/structure/tool-descriptions-shape.test.ts",
  "test/templates/template-library.test.ts",
  "test/transparency/anchor-cli.test.ts",
  "test/transparency/anchor-verify-cli.test.ts",
  "test/transparency/auditor-pack-drill.test.ts",
  "test/transparency/cli-transparency.test.ts",
  "test/unit/config-storage-path-divergence.test.ts",
  "test/v1/federation-cli-admin-session.test.ts",
  "test/v1/federation-cli-admin.test.ts",
  "test/v1/federation-compromise-rotate.test.ts",
  "test/v1/federation-provision-cli.test.ts",
  "test/v1/federation-real-join-marquee.test.ts",
  "test/v1/federation-reveal-master-secret-cli.test.ts",
  "test/v1/operator-authorization-spent-store-wiring.test.ts",
  "test/wrap/custody-credential-resolver.test.ts",
  "test/wrap/custody-flow.test.ts",
  "test/wrap/fresh-install-smoke.test.ts",
  "test/wrap/init.test.ts",
  "test/wrap/legacy-fortress-stray-custody-item.test.ts",
  "test/wrap/protect-contract-boots-dashboard.test.ts",
  "test/wrap/protect-dashboard-auth.test.ts",
  "test/wrap/protect-uses-enrolled-custody.test.ts",
]);

// test/hermes-memory-bridge/process-shell.test.ts deliberately unlinks its lease socket before release.
const expectedReapFailureOwners = new Set<string>([
  "test/hermes-memory-bridge/process-shell.test.ts",
]);

const observerKey = Symbol.for("sanctuary.test.master-write-lease-observer");
type Acquisition = () => Promise<MasterWriteBarrierLease>;
const observers = globalThis as typeof globalThis & {
  [observerKey]?: (acquire: Acquisition, stack: string | undefined) => Promise<MasterWriteBarrierLease>;
};
const leases = new Map<MasterWriteBarrierLease, string>();
const pending = new Map<Promise<MasterWriteBarrierLease>, string>();
const pendingAcquisitionMarginMs = 1_000; // Reserve one second for lease release and failure reporting.
const pendingAcquisitionDeadlineMs = leaseGuardHookTimeoutMs - pendingAcquisitionMarginMs;
const serverRoot = fileURLToPath(new URL("../../", import.meta.url));

observers[observerKey] = (acquire, stack) => {
  const acquisition = acquire().then(lease => {
    leases.set(lease, stack ?? "Acquisition stack unavailable");
    const release = lease.release.bind(lease);
    lease.release = async () => {
      await release();
      leases.delete(lease);
    };
    return lease;
  });
  pending.set(acquisition, stack ?? "Acquisition stack unavailable");
  void acquisition.then(() => pending.delete(acquisition), () => pending.delete(acquisition));
  return acquisition;
};

async function finishFile(): Promise<void> {
  // Await acquisitions already started by a failing test before taking the teardown snapshot.
  const deadline = performance.now() + pendingAcquisitionDeadlineMs;
  let timer: ReturnType<typeof setRealTimeout> | undefined;
  const expired = new Promise<void>(resolve => {
    timer = setRealTimeout(resolve, pendingAcquisitionDeadlineMs);
  });
  try {
    while (pending.size > 0 && performance.now() < deadline) {
      await Promise.race([Promise.allSettled([...pending.keys()]), expired]);
    }
  } finally {
    clearRealTimeout(timer);
  }
  const stillPending = [...pending.values()];
  const leaked = [...leases];
  const results = await Promise.allSettled(leaked.map(([lease]) => lease.release()));
  const failures = results.flatMap(result => result.status === "rejected" ? [result.reason] : []);
  const file = relative(serverRoot, expect.getState().testPath ?? "").replaceAll("\\", "/");
  delete observers[observerKey];
  // Only fixtures that deliberately break their lease may tolerate a rejected reap.
  const reapFailed = failures.length > 0 && !expectedReapFailureOwners.has(file);
  if (stillPending.length > 0 || reapFailed || (leaked.length > 0 && !existingLeaseOwners.has(file))) {
    const pendingDiagnostic = stillPending.length > 0
      ? `\n${stillPending.length} master-write acquisition(s) still pending after ${pendingAcquisitionDeadlineMs}ms\n${stillPending.join("\n\n")}`
      : "";
    throw new Error(`${leaked.length} master-write lease(s) left open in ${file}\n${leaked.map(([, stack]) => stack).join("\n\n")}${pendingDiagnostic}`, {
      ...(failures.length > 0 ? { cause: new AggregateError(failures, "Lease teardown failed") } : {}),
    });
  }
}

let finishing: Promise<void> | undefined;
const finishOnce = () => finishing ??= finishFile();
afterAll(finishOnce);

// A throwing file hook skips later afterAll hooks, so the outer wrapper still performs teardown.
aroundAll(async runSuite => {
  const errors: unknown[] = [];
  try { await runSuite(); }
  catch (error) { errors.push(error); }
  try { if (!finishing) await finishOnce(); }
  catch (error) { errors.push(error); }
  if (errors.length > 1) throw new AggregateError(errors, "File teardown and master-write lease guard failed");
  if (errors.length > 0) throw errors[0];
});
