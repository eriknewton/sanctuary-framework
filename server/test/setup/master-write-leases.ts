import { afterAll, aroundAll, expect } from "vitest";
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
  "test/audit/checkpoint-signing-rotation.test.ts",
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
  "test/cli/singleton-audit-writes.test.ts",
  "test/cli/verify-transparency-counter-floor.test.ts",
  "test/core/custody-write-lock.test.ts",
  "test/core/master-custody.test.ts",
  "test/core/master-rotation.test.ts",
  "test/core/unlock-diagnostic.test.ts",
  "test/dashboard-slice2-park.test.ts",
  "test/dashboard-standalone-enrolled-custody.test.ts",
  "test/dashboard-standalone-v010-4.test.ts",
  "test/dashboard-standalone-v010-5.test.ts",
  "test/dashboard-standalone-v010-6.test.ts",
  "test/dashboard-standalone.test.ts",
  "test/dashboard/fleet-panel-render.test.ts",
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
  "test/mesh/operator-cloud-joined-node-store.test.ts",
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
  "test/v1/federation-joiner-trust-root-store.test.ts",
  "test/v1/federation-provision-cli.test.ts",
  "test/v1/federation-real-join-marquee.test.ts",
  "test/v1/federation-reveal-master-secret-cli.test.ts",
  "test/v1/federation-trust-root-hybrid-persistence.test.ts",
  "test/v1/federation-trust-root-store.test.ts",
  "test/v1/operator-authorization-spent-store-wiring.test.ts",
  "test/wrap/custody-credential-resolver.test.ts",
  "test/wrap/custody-flow.test.ts",
  "test/wrap/fleet-roster-provider.test.ts",
  "test/wrap/fresh-install-smoke.test.ts",
  "test/wrap/init.test.ts",
  "test/wrap/legacy-fortress-stray-custody-item.test.ts",
  "test/wrap/protect-contract-boots-dashboard.test.ts",
  "test/wrap/protect-dashboard-auth.test.ts",
  "test/wrap/protect-uses-enrolled-custody.test.ts",
]);

const observerKey = Symbol.for("sanctuary.test.master-write-lease-observer");
type Acquisition = () => Promise<MasterWriteBarrierLease>;
const observers = globalThis as typeof globalThis & {
  [observerKey]?: (acquire: Acquisition, stack: string | undefined) => Promise<MasterWriteBarrierLease>;
};
const leases = new Map<MasterWriteBarrierLease, string>();
const pending = new Set<Promise<MasterWriteBarrierLease>>();
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
  pending.add(acquisition);
  void acquisition.then(() => pending.delete(acquisition), () => pending.delete(acquisition));
  return acquisition;
};

async function finishFile(): Promise<void> {
  // Await acquisitions already started by a failing test before taking the teardown snapshot.
  while (pending.size > 0) await Promise.allSettled([...pending]);
  const leaked = [...leases];
  const results = await Promise.allSettled(leaked.map(([lease]) => lease.release()));
  const failures = results.flatMap(result => result.status === "rejected" ? [result.reason] : []);
  const file = relative(serverRoot, expect.getState().testPath ?? "").replaceAll("\\", "/");
  delete observers[observerKey];
  if (failures.length > 0 || (leaked.length > 0 && !existingLeaseOwners.has(file))) {
    throw new Error(`${leaked.length} master-write lease(s) left open in ${file}\n${leaked.map(([, stack]) => stack).join("\n\n")}`, {
      ...(failures.length > 0 ? { cause: new AggregateError(failures, "Lease teardown failed") } : {}),
    });
  }
}

let finishing: Promise<void> | undefined;
const finishOnce = () => finishing ??= finishFile();
afterAll(finishOnce);

// A throwing file hook skips later afterAll hooks, so the outer wrapper still performs teardown.
aroundAll(async runSuite => {
  try { await runSuite(); }
  finally { if (!finishing) await finishOnce(); }
});
