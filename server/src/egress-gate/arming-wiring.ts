/**
 * Root-supervisor PRODUCTION WIRING for the exclusive-egress stack (Unified
 * Protect Slice 5 S5-6). This module maps the pure S5-1..S5-5 libraries onto
 * real side effects for the three callers that now exist:
 *
 *   1. INSTALL (`sudo sanctuary protect --hermes --exclusive-egress`, via
 *      `wrap/auto-provision.ts` -> `runProvisionFlow`'s exclusive stage):
 *      {@link createInstallExclusiveEgressOps}.
 *   2. REPAIR (`sudo sanctuary protect --repair-egress-gate`):
 *      {@link createRepairExclusiveEgressOps} (+ the MED-7 drift guard).
 *   3. BOOT (the root Castle Wall policy daemon):
 *      {@link startExclusiveEgressBootSupervisor} -- re-arm -> gate-verify ->
 *      recommit/hold per the S5-5 persistent-park contract, plus the ongoing
 *      oracle freshness-token refresh loop the gate's per-CONNECT liveness
 *      depends on.
 *
 * It also provides the S5-P posture PRODUCER
 * ({@link createExclusiveEgressPostureProducer}) that the dashboard binds via
 * `setExclusiveEgressPostureProvider` -- retiring S5-P's "no live producer"
 * staging disclosure.
 *
 * NAMED DEVIATION (bind-first handoff): G1 binds the ephemeral port in THIS
 * root process (`bindEphemeralGatePort`) so no pf/manifest rule ever names an
 * unowned port; after G5 the placeholder is released and the gate DAEMON
 * (running as the non-root gate uid) rebinds the committed port. The
 * release-to-rebind window is closed FAIL-CLOSED, not prevented: the S5-5
 * barrier's `verifyGate` re-verifies the listener's pid/uid (lsof) and the
 * committed generation before any unpark, so a squatter on the port parks the
 * agent (amber) rather than receiving agent traffic. The only party pf allows
 * to CONNECT to the port is the agent uid, which is parked until the verify
 * passes.
 *
 * HONESTY BOUNDS: everything here is the WIRED production path; the composed
 * fused flow is S5-DRILL-owed (Erik-present, Mini1) and no capability claim
 * advances until that drill captures evidence.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  type KeyObject,
} from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  PfAnchorRegistry,
  createFsRegistryStore,
  type PfAnchorQuarantineRepairResult,
} from "./anchor-registry.js";
import type { PfLivenessResult } from "./pf-anchor.js";
import {
  GenerationCoordinator,
  bindEphemeralGatePort,
  createFsGenerationStagingStore,
  evaluateGenerationMatch,
  resolveCommittedGeneration,
  type GateBinding,
} from "./generation.js";
import { createExecFilePfRunner, checkPfAnchorLiveness } from "./pf-anchor.js";
import {
  GateLivenessOracle,
  createFsLivenessOracleOps,
  GATE_LIVENESS_DIR,
  gateLivenessTokenPath,
} from "./liveness-oracle.js";
import {
  createFsGateCredentialAuthority,
  gateCredentialAcceptPath,
  gateCredentialTokenPath,
} from "./gate-credential.js";
import { deriveGateAccountName, planAndCreateGateAccount } from "./gate-account.js";
import {
  AGENT_HARNESS_DAEMON_LABEL,
  AGENT_HARNESS_DAEMON_PLIST_PATH,
  agentHarnessDaemonStatus,
  agentHarnessDaemonStableRunning,
  installAgentHarnessDaemon,
  planAgentHarnessDaemonInstall,
  setAgentHarnessJobDisabled,
  type HarnessDaemonOps,
  type HarnessDaemonStatus,
} from "./harness-daemon.js";
import {
  AGENT_HARNESS_HOLD_DIR,
  holdFilePathForUid,
  planParkedHarnessInstall,
  renderHarnessReleaseHoldFile,
  runReleaseBarrierSequence,
  type CommittedGenerationIdentity,
  type ReleaseBarrierOps,
  type ReleaseBarrierOutcome,
} from "./release-barrier.js";
import {
  GATE_ORACLE_PUBLIC_KEY_PATH,
  egressGateDaemonLabel,
  egressGateDaemonPlistPath,
  egressGatePolicyConfigPath,
  egressGateRulesConfigPath,
  egressGateRuntimeStatePath,
  egressGateRuntimeUidDirPath,
  parseEgressGateRuntimeState,
  renderEgressGateDaemonPlist,
  type EgressGateRuntimeState,
} from "./gate-daemon.js";
import { diffTransientPfRules } from "./drift-guard.js";
import { ensureExclusiveEgressRuntimeFs } from "./runtime-fs-plan.js";
import {
  buildExclusiveEgressPosture,
  summarizeExclusiveEgressStatus,
  failedExclusiveEgressStatus,
  type ExclusiveEgressStatus,
} from "./posture.js";
import { verifyLivenessToken } from "./liveness-oracle.js";
import {
  exclusiveRoutingMarkerPath,
  loadExclusiveRoutingMarker,
  renderExclusiveRoutingMarker,
} from "../castle-wall/allowlist/routing-marker.js";
import {
  EXCLUSIVE_EGRESS_GATE_FILENAME,
} from "../castle-wall/allowlist/gate-derivation.js";
import { composeExclusiveRoutingRules } from "../castle-wall/allowlist/exclusive-routing.js";
import type {
  ExclusiveEgressArmOps,
  ExclusiveGenerationIdentity,
} from "../castle-wall/provision/exclusive-arm.js";
import {
  runBootExclusiveEgressRelease,
  type BootReleaseResult,
} from "../castle-wall/provision/exclusive-arm.js";
import type { EgressGateUnprotectOps } from "../castle-wall/provision/exclusive-unprotect.js";
import {
  PROVISION_LOCK_PATH,
  withProvisionLock,
  type ProvisionLockOps,
} from "../castle-wall/provision/lockfile.js";

const execFileAsync = promisify(execFile);

/** Root-only private half of the supervisor oracle key. */
export const GATE_ORACLE_PRIVATE_KEY_PATH = `${GATE_LIVENESS_DIR}/supervisor-oracle-key.pem`;

const LAUNCHCTL_TIMEOUT_MS = 15_000;
const GATE_RUNTIME_WAIT_BUDGET_MS = 15_000;
const GATE_RUNTIME_WAIT_INTERVAL_MS = 250;

/** Real O_EXCL lock ops (the shipped provision-lock discipline). */
export function fsLockOps(): ProvisionLockOps {
  return {
    async acquire(lockPath: string): Promise<void> {
      const { open } = await import("node:fs/promises");
      const handle = await open(lockPath, "wx");
      await handle.close();
    },
    async release(lockPath: string): Promise<void> {
      const { unlink } = await import("node:fs/promises");
      await unlink(lockPath).catch((err) => {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      });
    },
  };
}

/** The production S5-1 registry (fs store + O_EXCL lock + execFile pfctl). */
export function createProductionAnchorRegistry(): PfAnchorRegistry {
  return new PfAnchorRegistry({
    store: createFsRegistryStore(),
    lock: fsLockOps(),
    runner: createExecFilePfRunner(),
  });
}

/**
 * Load-or-create the supervisor oracle Ed25519 keypair: private half
 * root-only 0600, public half 0644 at {@link GATE_ORACLE_PUBLIC_KEY_PATH}
 * (the gate daemon pins it). Idempotent.
 */
export async function ensureSupervisorOracleKeys(): Promise<{
  privateKey: KeyObject;
  publicKey: KeyObject;
}> {
  // EXPLICIT mode (fix-round BLOCKER-2 class): 0711 so the non-root gate uid
  // can traverse to its token + the 0644 public key (mkdir's mode argument is
  // umask-masked and silent on a pre-existing dir). Loud on failure: keys the
  // gate cannot reach are a guaranteed all-deny.
  await mkdir(GATE_LIVENESS_DIR, { recursive: true, mode: 0o711 });
  const { chmod } = await import("node:fs/promises");
  await chmod(GATE_LIVENESS_DIR, 0o711);
  try {
    const pem = await readFile(GATE_ORACLE_PRIVATE_KEY_PATH, "utf8");
    const privateKey = createPrivateKey(pem);
    const publicKey = createPublicKey({ key: privateKey.export({ type: "pkcs8", format: "pem" }).toString(), format: "pem" });
    // Re-assert the public half (a missing/garbled pub file must self-heal:
    // the gate pins THIS file). ATOMIC tmp+rename (fix-round-2 LOW-8): the
    // running gate daemon re-reads this pinned key; an in-place write leaves
    // a partial-PEM window in which every gate verify fails.
    await atomicRootWrite(
      GATE_ORACLE_PUBLIC_KEY_PATH,
      publicKey.export({ type: "spki", format: "pem" }).toString(),
      0o644,
    );
    return { privateKey, publicKey };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  const pair = generateKeyPairSync("ed25519");
  await atomicRootWrite(
    GATE_ORACLE_PRIVATE_KEY_PATH,
    pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    0o600,
  );
  await atomicRootWrite(
    GATE_ORACLE_PUBLIC_KEY_PATH,
    pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
    0o644,
  );
  return { privateKey: pair.privateKey, publicKey: pair.publicKey };
}

/** Build the production oracle over the pfctl probe (root-side). */
export function createProductionOracle(privateKey: KeyObject, gateUid: number): GateLivenessOracle {
  const runner = createExecFilePfRunner();
  return new GateLivenessOracle(
    privateKey,
    createFsLivenessOracleOps({
      gateUid,
      probe: ({ agentUid, gatePort }) =>
        checkPfAnchorLiveness(runner, { agent_uid: agentUid, gate_port: gatePort }),
    }),
  );
}

/**
 * Tolerance for comparing the gate's self-reported start epoch against the
 * kernel's (`ps -o lstart=`, 1s resolution, plus Date.now()/uptime jitter).
 * A recycled pid would need to land within this window AND on the same port
 * with the same uid to fool the check.
 */
export const PID_START_TOLERANCE_MS = 10_000;

/**
 * Discriminated port-owner verdict (fix-round-2 MED-4): a failed owner check
 * names WHICH check failed (listener/pid/uid/pid_start token/lstart parse)
 * so a persistent park/degrade on a real host is diagnosable from the log,
 * not a bare boolean.
 */
export type PortOwnerVerdict = { ok: true } | { ok: false; reason: string };

/**
 * lsof-backed loopback TCP port-owner check (TCP-only by construction: the
 * whole exclusive-egress stack is 127.0.0.1 TCP). The listener on `port`
 * must be the expected pid, and -- when supplied -- the expected uid and the
 * expected `pid_start` token (`<pid>-<startEpochMs>`, the gate runtime
 * state's pid-reuse defense, fix-round finding: the stored token was
 * previously never enforced). The start-time check reads the kernel's
 * process start via `ps -p <pid> -o lstart=` -- ALWAYS under `LC_ALL=C`
 * (fix-round-2 MED-4: sudo inherits the operator's locale, and a
 * French/German `lstart` string gives `Date.parse` NaN, persistently
 * bricking the owner check on non-English hosts) -- and requires it within
 * {@link PID_START_TOLERANCE_MS} of the token's epoch. Fail-closed: any
 * lookup/parse failure or mismatch is NOT owner-verified, with the failing
 * check named in the verdict.
 */
export async function verifyLoopbackTcpPortOwner(input: {
  port: number;
  expectedPid: number;
  expectedUid?: number;
  /** The runtime state's `pid_start` token (`<pid>-<startEpochMs>`). */
  expectedPidStart?: string;
  execFileFn?: typeof execFileAsync;
}): Promise<PortOwnerVerdict> {
  const run = input.execFileFn ?? execFileAsync;
  try {
    const { stdout } = await run("lsof", [
      "-nP",
      `-iTCP:${input.port}`,
      "-sTCP:LISTEN",
      "-Fpu",
    ]);
    let pid: number | undefined;
    let uid: number | undefined;
    for (const line of stdout.split("\n")) {
      if (line.startsWith("p")) pid = Number(line.slice(1));
      if (line.startsWith("u")) uid = Number(line.slice(1));
      if (pid !== undefined && uid !== undefined) break;
    }
    if (pid !== input.expectedPid) {
      return {
        ok: false,
        reason: `pid check failed: listener pid ${pid === undefined ? "absent" : pid} != expected pid ${input.expectedPid}`,
      };
    }
    if (input.expectedUid !== undefined && uid !== input.expectedUid) {
      return {
        ok: false,
        reason: `uid check failed: listener uid ${uid === undefined ? "absent" : uid} != expected uid ${input.expectedUid}`,
      };
    }
    if (input.expectedPidStart !== undefined) {
      const m = /^(\d+)-(\d+)$/.exec(input.expectedPidStart);
      if (m === null) {
        // Malformed token: never owner-verified.
        return { ok: false, reason: `pid_start token check failed: token ${JSON.stringify(input.expectedPidStart)} is malformed` };
      }
      if (Number(m[1]) !== input.expectedPid) {
        return { ok: false, reason: `pid_start token check failed: token names pid ${m[1]}, expected pid ${input.expectedPid}` };
      }
      const expectedStartMs = Number(m[2]);
      // LC_ALL=C pins the lstart format Date.parse understands (MED-4).
      const { stdout: lstartOut } = await run(
        "ps",
        ["-p", String(input.expectedPid), "-o", "lstart="],
        { env: { ...process.env, LC_ALL: "C" } },
      );
      const lstart = lstartOut.trim();
      if (lstart.length === 0) {
        return { ok: false, reason: `pid_start check failed: ps returned no start time for pid ${input.expectedPid} (process gone?)` };
      }
      const actualStartMs = Date.parse(lstart);
      if (!Number.isFinite(actualStartMs)) {
        return { ok: false, reason: `pid_start-parse check failed: ps lstart ${JSON.stringify(lstart)} is not parseable` };
      }
      if (Math.abs(actualStartMs - expectedStartMs) > PID_START_TOLERANCE_MS) {
        return {
          ok: false,
          reason:
            `pid_start check failed: kernel start time differs from the token by ` +
            `${Math.abs(actualStartMs - expectedStartMs)}ms (> ${PID_START_TOLERANCE_MS}ms tolerance; possible pid reuse)`,
        };
      }
    }
    return { ok: true };
  } catch (err) {
    // No listener / lsof or ps failure: not owner-verified (fail-closed).
    return { ok: false, reason: `listener lookup failed: ${(err as Error).message}` };
  }
}

async function runLaunchctl(args: readonly string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await execFileAsync("launchctl", [...args], {
      timeout: LAUNCHCTL_TIMEOUT_MS,
    });
    return { code: 0, stdout, stderr };
  } catch (err) {
    const e = err as { code?: number; stdout?: string; stderr?: string; message?: string };
    return {
      code: typeof e.code === "number" ? e.code : 1,
      stdout: e.stdout ?? "",
      stderr: e.stderr ?? (e.message ?? ""),
    };
  }
}

function realHarnessOps(): HarnessDaemonOps {
  return {
    async writeFile(path, content, mode): Promise<void> {
      await writeFile(path, content, { mode });
    },
    async removeFile(path): Promise<void> {
      await rm(path, { force: true });
    },
    runLaunchctl,
  };
}

async function atomicRootWrite(path: string, content: string, mode: number): Promise<void> {
  const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
  await writeFile(tmp, content, { mode });
  try {
    await rename(tmp, path);
  } catch (err) {
    await rm(tmp, { force: true }).catch(() => undefined);
    throw err;
  }
}

/** Everything the install/repair wiring needs to know about one agent. */
export interface ExclusiveEgressWiringInput {
  agentId: string;
  agentUid: number;
  agentAccount: string;
  /** The operator fortress the wall + manifest belong to. */
  fortressPath: string;
  /** The REAL harness argv (the S5-5 wrapper digest source). */
  harnessArgv: string[];
  /** Harness daemon log dir (agent-writable). */
  harnessLogDir: string;
  /** The confined agent's template identity (e.g. "hermes"), for the S5-4 marker. */
  agentTemplate: string;
  /** The sanctuary CLI argv prefix used to spawn the gate daemon entrypoint. */
  gateDaemonArgvPrefix: string[];
  /** Operator/console uids the gate account must never collide with. */
  excludeUids: number[];
  /** Uid ceiling for the gate service account (the shipped arm-time ceiling). */
  gateAccountCeiling: number;
  /** The gate service account's home directory (a dir it owns; never the agent's). */
  gateHomeDirectory: string;
  /** Trigger the policy daemon's manifest reload (the shipped pinned-signer path). */
  reloadPolicy(): Promise<{ ok: boolean; error?: string }>;
  /** Republish the provisioned endpoint rules with the given routing scope. */
  publishProvisionedRules(routing: { mode: "coarse" } | { mode: "exclusive"; gate_uid: number }): Promise<
    { ok: true; ruleIds: string[] } | { ok: false; error: string }
  >;
  /** Best-effort audit (distinct local ops; never throws). */
  audit(operation: string, details: Record<string, unknown>): Promise<void>;
  print(line: string): void;
  /** Account-provision ops (the shipped sysadminctl/dscl real ops). */
  accountOps: Parameters<typeof planAndCreateGateAccount>[1];
  /**
   * S5-7 MED-1 fallback: when the harness argv could not be resolved (the
   * re-homed Hermes runtime tree that argv derives from was damaged or
   * deleted), the unprotect park REMOVES the host-singleton harness plist
   * (absent === unbootable) instead of restoring the parked barrier form, so
   * the teardown can still complete rather than wedging permanently. Only the
   * S5-7 unprotect wiring reads it; install/repair ignore it. Default (absent /
   * false) === the normal restore disposition. `harnessArgv` is unused on this
   * path (the plist is removed, never rendered).
   */
  parkPlistFallbackRemoval?: boolean;
  /**
   * TEST-ONLY seam; production omits. Injecting `barrierOps` bypasses the
   * gate-account/oracle bring-up so the release sequence (and its fix-round-4
   * P1 captured-generation guard) is exercisable host-free.
   */
  internals?: {
    barrierOps?: ReleaseBarrierOps;
  };
}

interface BringUpState {
  gateUid: number;
  gateAccountName: string;
}

/**
 * The full production bring-up: gate account -> generation G1-G5 (placeholder
 * bind, lsof owner check, registry pf arm, gate-readable config publish +
 * gate policy + exclusive marker + manifest reload, commit) -> credential
 * mint -> gate daemon install + bootstrap -> runtime-state + owner verify ->
 * first oracle refresh. Throws on ANY failure (the generation machine's own
 * recovery has already tombstoned the pf pass by then).
 */
async function productionBringUp(
  input: ExclusiveEgressWiringInput,
  state: BringUpState,
  oracle: GateLivenessOracle,
): Promise<ExclusiveGenerationIdentity> {
  // FIRST (fix-round BLOCKER-1 + BLOCKER-2): assert the runtime filesystem
  // layout -- the gate-uid-owned per-uid runtime subdir, the 0711 traversal
  // modes on gate-cred/gate-liveness, 0755 on the parents -- with explicit
  // chown/chmod as root, BEFORE any config publish, credential mint, or gate
  // bootstrap. Throws on failure (no arming over a broken layout).
  await ensureExclusiveEgressRuntimeFs({ agentUid: input.agentUid, gateUid: state.gateUid });
  const registry = createProductionAnchorRegistry();
  let lastBinding: GateBinding | null = null;

  const coordinator = new GenerationCoordinator({
    bind: async (request) => {
      const binding = await bindEphemeralGatePort();
      lastBinding = binding;
      void request;
      return binding;
    },
    // Placeholder-bind owner check (G2): pid-only by design -- the in-process
    // placeholder's pidStart token is the NON-AUTHORITATIVE `pid-<pid>` form
    // (see bindEphemeralGatePort); the authoritative pid_start enforcement
    // applies to the GATE DAEMON's runtime state below and in verifyGate.
    verifyOwner: async ({ port, pid }) =>
      (await verifyLoopbackTcpPortOwner({ port, expectedPid: pid })).ok,
    registry: {
      armEntry: async (entry) => {
        await registry.addOrUpdate({
          agent_uid: entry.agent_uid,
          gate_port: entry.gate_port,
          fortress_path: entry.fortress_path,
          generation_id: entry.generation_id,
        });
      },
      tombstone: async (agentUid, fallback) => {
        await registry.tombstone(agentUid, fallback);
      },
      readEntry: async (agentUid) => {
        const { entries } = await registry.list();
        return entries.find((e) => e.agent_uid === agentUid) ?? null;
      },
      // Fix-round-5 P1: the persisted floor covering repair-discarded
      // generations; bring-up must allocate strictly above it.
      readGenerationFloor: async () => (await registry.list()).generationFloor,
    },
    publishManifest: async (gen) => {
      // (a) Re-scope the provisioned endpoint rules to the GATE principal
      // (the S5-4 routing model; scope moves off the agent).
      const published = await input.publishProvisionedRules({
        mode: "exclusive",
        gate_uid: state.gateUid,
      });
      if (!published.ok) {
        throw new Error(`exclusive re-scope publish failed: ${published.error}`);
      }
      // (b) The generation-bearing gate policy file (G4 contract: the policy
      // carries port + generation) into the fortress for the signing daemon...
      const policyDoc = JSON.stringify(
        { agent_uid: gen.agent_uid, gate_port: gen.gate_port, generation_id: gen.generation_id },
        null,
        2,
      );
      const fortressPolicyPath = join(
        input.fortressPath,
        "policy",
        "egress",
        EXCLUSIVE_EGRESS_GATE_FILENAME,
      );
      await mkdir(join(input.fortressPath, "policy", "egress"), { recursive: true }).catch(
        () => undefined,
      );
      await atomicRootWrite(fortressPolicyPath, policyDoc, 0o600);
      // (c) ...and the gate-readable runtime copies (policy + rules) for the
      // non-root gate daemon, which cannot read the operator fortress. The
      // runtime dir layout (modes + per-uid gate-owned subdir) was asserted
      // by ensureExclusiveEgressRuntimeFs at the top of the bring-up.
      await atomicRootWrite(egressGatePolicyConfigPath(gen.agent_uid), policyDoc, 0o644);
      const { readEgressRulesFromDisk } = await import("../castle-wall/provision/egress.js");
      const rules = await readEgressRulesFromDisk(input.fortressPath);
      await atomicRootWrite(egressGateRulesConfigPath(gen.agent_uid), JSON.stringify(rules), 0o644);
      // (d) The exclusive-routing marker: from here the signing daemon
      // composes through the S5-4 exclusive composition (compose-time
      // assertion = fail-closed chokepoint on every reload).
      await atomicRootWrite(
        exclusiveRoutingMarkerPath(input.fortressPath),
        renderExclusiveRoutingMarker({
          agent_uid: gen.agent_uid,
          gate_uid: state.gateUid,
          agent_id: input.agentId,
          agent_template: input.agentTemplate,
        }),
        0o600,
      );
      // (e) Reload: the daemon re-composes (exclusive assertion runs), re-signs,
      // broadcasts. A reload failure fails the G4 transition (recovery
      // tombstones the staged pass; never a half-published generation).
      const reload = await input.reloadPolicy();
      if (!reload.ok) {
        throw new Error(`policy reload after exclusive publish failed: ${reload.error ?? "unknown"}`);
      }
    },
    staging: createFsGenerationStagingStore(),
    lock: fsLockOps(),
  });

  const committed = await coordinator.bringUp({
    agent_uid: input.agentUid,
    fortress_path: input.fortressPath,
  });

  // Mint the generation-bound bearer credential BEFORE the gate daemon comes
  // up (accept-state precedes any CONNECT) and BEFORE unpark (design M5).
  const credAuthority = createFsGateCredentialAuthority({ gateUid: state.gateUid });
  await credAuthority.mint({ agentUid: input.agentUid, generationId: committed.generation_id });

  // Hand the committed port from the root placeholder to the gate daemon:
  // release, install the gate daemon plist, bootstrap, then wait for the
  // runtime state naming EXACTLY this {port, generation} and verify the
  // listener's owner (fail-closed: any mismatch throws; the S5-5 barrier will
  // ALSO re-verify before unpark).
  if (lastBinding !== null) {
    await (lastBinding as GateBinding).release();
  }
  const label = egressGateDaemonLabel(input.agentUid);
  const plistPath = egressGateDaemonPlistPath(input.agentUid);
  await writeFile(
    plistPath,
    renderEgressGateDaemonPlist({
      agentUid: input.agentUid,
      gateAccount: state.gateAccountName,
      programArguments: [
        ...input.gateDaemonArgvPrefix,
        "castle-wall",
        "egress-gate-daemon",
        `--agent-uid=${input.agentUid}`,
      ],
      fortressPath: input.fortressPath,
      logDir: input.harnessLogDir,
    }),
    { mode: 0o644 },
  );
  const bootstrap = await runLaunchctl(["bootstrap", "system", plistPath]);
  if (bootstrap.code !== 0 && !/already bootstrapped|Bootstrap failed: 5: Input\/output error/i.test(bootstrap.stderr)) {
    throw new Error(`launchctl bootstrap ${label} exited ${bootstrap.code}: ${bootstrap.stderr.trim()}`);
  }
  const kick = await runLaunchctl(["kickstart", `system/${label}`]);
  if (kick.code !== 0) {
    throw new Error(`launchctl kickstart ${label} exited ${kick.code}: ${kick.stderr.trim()}`);
  }
  const runtime = await waitForGateRuntime(input.agentUid, committed.generation_id, committed.gate_port);
  const owner = await verifyLoopbackTcpPortOwner({
    port: committed.gate_port,
    expectedPid: runtime.pid,
    expectedUid: state.gateUid,
    expectedPidStart: runtime.pid_start,
  });
  if (!owner.ok) {
    throw new Error(
      `gate daemon owner check failed: the listener on port ${committed.gate_port} is not the gate ` +
        `daemon pid ${runtime.pid} under uid ${state.gateUid} (${owner.reason}; refusing to proceed toward release)`,
    );
  }
  // First oracle refresh: publish the signed freshness token so the gate's
  // per-CONNECT verify has a live-bound verdict from the first CONNECT.
  const token = await oracle.refresh({
    agentUid: input.agentUid,
    gatePort: committed.gate_port,
    generationId: committed.generation_id,
  });
  if (token === null) {
    throw new Error("first oracle refresh reported the pf anchor NOT live; refusing to proceed toward release");
  }
  return {
    generation_id: committed.generation_id,
    agent_uid: committed.agent_uid,
    gate_port: committed.gate_port,
  };
}

async function waitForGateRuntime(
  agentUid: number,
  generationId: number,
  gatePort: number,
  deps?: {
    readState?: (agentUid: number) => Promise<string>;
    budgetMs?: number;
    intervalMs?: number;
  },
): Promise<EgressGateRuntimeState> {
  const budgetMs = deps?.budgetMs ?? GATE_RUNTIME_WAIT_BUDGET_MS;
  const intervalMs = deps?.intervalMs ?? GATE_RUNTIME_WAIT_INTERVAL_MS;
  const path = egressGateRuntimeStatePath(agentUid);
  const readState = deps?.readState ?? (async (uid: number): Promise<string> => readFile(egressGateRuntimeStatePath(uid), "utf8"));
  const deadline = Date.now() + budgetMs;
  let lastError: string | undefined;
  for (;;) {
    try {
      const text = await readState(agentUid);
      const state = parseEgressGateRuntimeState(text, path);
      if (state.generation_id === generationId && state.gate_port === gatePort && state.agent_uid === agentUid) {
        return state;
      }
      lastError = `runtime state names generation ${state.generation_id} port ${state.gate_port}, expected ${generationId}/${gatePort}`;
    } catch (err) {
      lastError = (err as Error).message;
    }
    if (Date.now() >= deadline) break;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(
    `gate daemon did not publish a matching runtime state within ${budgetMs}ms: ${lastError ?? "runtime state never appeared"}`,
  );
}

/**
 * Bootstrap + kickstart one agent's gate daemon LaunchDaemon and (when a
 * committed identity is known) wait for its runtime state (fix-round H2: the
 * gate plist is `RunAtLoad=false`, so WITHOUT this step nothing starts the
 * gate after a reboot and `verifyGate` parks the agent forever). Mirrors the
 * install path's bootstrap sequence in {@link productionBringUp}. Throws on
 * failure; the boot caller logs loudly and lets the barrier's `verifyGate`
 * produce the honest parked outcome.
 */
export async function bootstrapGateDaemonForBoot(input: {
  agentUid: number;
  /** The committed identity to await, or null to skip the runtime wait. */
  expected: { generationId: number; gatePort: number } | null;
  runLaunchctlFn?: (args: readonly string[]) => Promise<{ code: number; stdout: string; stderr: string }>;
  readState?: (agentUid: number) => Promise<string>;
  waitBudgetMs?: number;
  waitIntervalMs?: number;
}): Promise<void> {
  const run = input.runLaunchctlFn ?? runLaunchctl;
  const label = egressGateDaemonLabel(input.agentUid);
  const plistPath = egressGateDaemonPlistPath(input.agentUid);
  const bootstrap = await run(["bootstrap", "system", plistPath]);
  if (
    bootstrap.code !== 0 &&
    !/already bootstrapped|service already loaded|Bootstrap failed: 5: Input\/output error/i.test(bootstrap.stderr)
  ) {
    throw new Error(`launchctl bootstrap ${label} exited ${bootstrap.code}: ${bootstrap.stderr.trim()}`);
  }
  const kick = await run(["kickstart", `system/${label}`]);
  if (kick.code !== 0) {
    throw new Error(`launchctl kickstart ${label} exited ${kick.code}: ${kick.stderr.trim()}`);
  }
  if (input.expected !== null) {
    await waitForGateRuntime(input.agentUid, input.expected.generationId, input.expected.gatePort, {
      ...(input.readState !== undefined ? { readState: input.readState } : {}),
      ...(input.waitBudgetMs !== undefined ? { budgetMs: input.waitBudgetMs } : {}),
      ...(input.waitIntervalMs !== undefined ? { intervalMs: input.waitIntervalMs } : {}),
    });
  }
}

/**
 * The production S5-5 barrier ops for one agent. `rearm` distinguishes the
 * install path (pf armed at G3: no-op ok) from the boot path (re-assert the
 * registry union).
 *
 * REGISTRY READS ARE QUARANTINE-AWARE (fix-round-3 MED-3): every registry
 * read here routes through `listQuarantined`, so ONE malformed sibling entry
 * no longer throws this uid's whole release into the outer catch
 * (park-not-verified with no ops verified). The valid uid proceeds through
 * the barrier's own fail-closed machinery (a quarantine forces `dirty`, so
 * gate-verify still refuses to RELEASE until repair), and each quarantined
 * sibling is reported loudly via `print`.
 */
export function createProductionReleaseBarrierOps(input: {
  agentUid: number;
  agentAccount: string;
  harnessArgv: string[];
  fortressPath: string;
  harnessLogDir: string;
  gateUid: number;
  oracle: GateLivenessOracle;
  rearm: "install-noop" | "boot-rearm";
  /** Loud sink for quarantined-sibling findings (fix-round-3 MED-3). */
  print?: (line: string) => void;
  /** TEST-ONLY seams; production omits (real fs registry + pfctl probe). */
  internals?: {
    registry?: PfAnchorRegistry;
    probeAnchorLiveness?: (policy: { agent_uid: number; gate_port: number }) => Promise<PfLivenessResult>;
  };
}): ReleaseBarrierOps {
  const registry = input.internals?.registry ?? createProductionAnchorRegistry();
  const probeAnchorLiveness =
    input.internals?.probeAnchorLiveness ??
    ((policy: { agent_uid: number; gate_port: number }): Promise<PfLivenessResult> =>
      checkPfAnchorLiveness(createExecFilePfRunner(), policy));
  const print = input.print ?? ((): void => undefined);
  const staging = createFsGenerationStagingStore();
  const harnessOps = realHarnessOps();
  const holdPath = holdFilePathForUid(input.agentUid);

  /**
   * One quarantine-aware registry snapshot (fix-round-3 MED-3): valid entries
   * + the registry-level dirty bit stay usable; every quarantined sibling is
   * individually loud. Structural corruption still throws (nothing salvageable).
   */
  async function listQuarantineAware(context: string): Promise<{
    entries: { agent_uid: number; gate_port: number; fortress_path: string; generation_id?: number; tombstone?: boolean }[];
    dirty: boolean;
    quarantined: { index: number; reason: string }[];
  }> {
    const listed = await registry.listQuarantined();
    for (const q of listed.quarantined) {
      print(
        `[castle-wall] release barrier (uid ${input.agentUid}, ${context}): registry entry #${q.index} ` +
          `is malformed and QUARANTINED (${q.reason}); uid ${input.agentUid}'s valid entry proceeds ` +
          "through the barrier's own fail-closed checks; repair is owed: sudo sanctuary protect --repair-egress-gate",
      );
    }
    return listed;
  }

  async function writePlist(expectedGenerationId: number): Promise<void> {
    const plan = planParkedHarnessInstall({
      agentAccount: input.agentAccount,
      agentUid: input.agentUid,
      harnessArgv: input.harnessArgv,
      fortressPath: input.fortressPath,
      logDir: input.harnessLogDir,
      expectedGenerationId,
    });
    await writeFile(plan.plistPath, plan.plistContent, { mode: 0o644 });
  }

  // Resolve the committed identity from ONE registry listing (fix-round-2
  // LOW-7: readCommitted + a second registry.list() in verifyGate was a
  // read/re-read TOCTOU with a non-null assertion on the re-read).
  async function readCommittedFrom(listed: {
    entries: { agent_uid: number; gate_port: number; generation_id?: number; tombstone?: boolean }[];
    dirty: boolean;
  }): Promise<CommittedGenerationIdentity | null> {
    const entry = listed.entries.find((e) => e.agent_uid === input.agentUid) ?? null;
    const stagingRecord = await staging.load(input.agentUid);
    const committed = resolveCommittedGeneration({
      entry,
      stagingRecordPresent: stagingRecord !== null,
      registryDirty: listed.dirty,
    });
    if (committed.committedGenerationId === undefined || entry === null) return null;
    return { generation_id: committed.committedGenerationId, agent_uid: input.agentUid };
  }

  async function readCommitted(): Promise<CommittedGenerationIdentity | null> {
    return readCommittedFrom(await listQuarantineAware("commit-generation"));
  }

  return {
    async disableJob(): Promise<void> {
      const r = await runLaunchctl(["disable", `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
      if (r.code !== 0) throw new Error(`launchctl disable exited ${r.code}: ${r.stderr.trim()}`);
    },
    async enableJob(): Promise<void> {
      const r = await runLaunchctl(["enable", `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
      if (r.code !== 0) throw new Error(`launchctl enable exited ${r.code}: ${r.stderr.trim()}`);
    },
    async bootstrapJob(): Promise<void> {
      const plistPath = `/Library/LaunchDaemons/${AGENT_HARNESS_DAEMON_LABEL}.plist`;
      const b = await runLaunchctl(["bootstrap", "system", plistPath]);
      if (b.code !== 0 && !/already bootstrapped/i.test(b.stderr)) {
        throw new Error(`launchctl bootstrap exited ${b.code}: ${b.stderr.trim()}`);
      }
      const k = await runLaunchctl(["kickstart", `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
      if (k.code !== 0) throw new Error(`launchctl kickstart exited ${k.code}: ${k.stderr.trim()}`);
    },
    async bootoutJob(): Promise<void> {
      const r = await runLaunchctl(["bootout", `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
      if (r.code !== 0 && !/No such process|Could not find/i.test(r.stderr)) {
        throw new Error(`launchctl bootout exited ${r.code}: ${r.stderr.trim()}`);
      }
    },
    async removeHoldFile(): Promise<void> {
      await rm(holdPath, { force: true });
    },
    async writeHoldFile(record): Promise<void> {
      await mkdir(AGENT_HARNESS_HOLD_DIR, { recursive: true, mode: 0o755 }).catch(() => undefined);
      await atomicRootWrite(holdPath, renderHarnessReleaseHoldFile(record), 0o644);
    },
    async bootSessionUuid(): Promise<string> {
      const { stdout } = await execFileAsync("/usr/sbin/sysctl", ["-n", "kern.bootsessionuuid"]);
      const uuid = stdout.trim();
      if (uuid.length === 0) throw new Error("kern.bootsessionuuid is empty");
      return uuid;
    },
    async rearmAnchor(): Promise<{ ok: true } | { ok: false; reason: string }> {
      if (input.rearm === "install-noop") return { ok: true };
      try {
        // Quarantine-aware read (fix-round-3 MED-3): a malformed SIBLING
        // entry no longer throws this uid's rearm into a bare failure.
        const listed = await listQuarantineAware("rearm-anchor");
        const entry = listed.entries.find((e) => e.agent_uid === input.agentUid);
        if (entry === undefined) {
          return { ok: false, reason: `no registry entry for uid ${input.agentUid}` };
        }
        if (listed.quarantined.length > 0) {
          // A quarantined sibling means the FULL committed union cannot be
          // read, and every registry MUTATION refuses a partially-valid
          // baseline by design (re-rendering a partial union could DROP the
          // quarantined uid's live block rules from the anchor -- fail-open).
          // So instead of re-arming, VERIFY this uid's rules are live
          // AS-ARMED: live means there is nothing to re-arm for this uid and
          // the release proceeds to gate-verify (which still refuses over
          // the dirty registry until repair); not-live fails LOUD -- never a
          // partial union re-render.
          const live = await probeAnchorLiveness({ agent_uid: entry.agent_uid, gate_port: entry.gate_port });
          if (live.live) return { ok: true };
          return {
            ok: false,
            reason:
              `uid ${input.agentUid}'s pf anchor rules are not live (${live.reasons.join("; ")}) and a ` +
              `quarantined registry entry (#${listed.quarantined.map((q) => q.index).join(", #")}) blocks a ` +
              "safe union re-arm (a partial re-render could drop the quarantined uid's block rules); " +
              "repair: sudo sanctuary protect --repair-egress-gate",
          };
        }
        // Re-assert the committed union (idempotent add/update re-renders +
        // re-loads + re-verifies per-uid liveness through the locked registry).
        await registry.addOrUpdate(entry);
        return { ok: true };
      } catch (err) {
        return { ok: false, reason: (err as Error).message };
      }
    },
    async verifyGate(): Promise<
      { ok: true; observed: CommittedGenerationIdentity } | { ok: false; reasons: string[] }
    > {
      const reasons: string[] = [];
      // ONE registry snapshot for the whole verify (fix-round-2 LOW-7),
      // quarantine-aware (fix-round-3 MED-3): a malformed sibling entry is
      // loud + this uid's verify proceeds; the quarantine forces `dirty`,
      // which the check below turns into an honest parked reason.
      const listed = await listQuarantineAware("gate-verify");
      const { dirty } = listed;
      const entry = listed.entries.find((e) => e.agent_uid === input.agentUid) ?? null;
      const committed = await readCommittedFrom(listed);
      if (committed === null || entry === null) {
        return { ok: false, reasons: ["no committed generation (registry empty/dirty/staging in flight)"] };
      }
      // Gate runtime + owner.
      let runtime: EgressGateRuntimeState;
      try {
        const path = egressGateRuntimeStatePath(input.agentUid);
        runtime = parseEgressGateRuntimeState(await readFile(path, "utf8"), path);
      } catch (err) {
        return { ok: false, reasons: [`gate runtime state unreadable: ${(err as Error).message}`] };
      }
      const match = evaluateGenerationMatch({
        committedGenerationId: committed.generation_id,
        committedPort: entry.gate_port,
        pfPassPort: entry.tombstone === true ? undefined : entry.gate_port,
        manifestPort: runtime.gate_port,
        manifestGenerationId: runtime.generation_id,
      });
      if (!match.serve) reasons.push(...match.reasons);
      if (dirty) reasons.push("registry is dirty (needs repair)");
      const owner = await verifyLoopbackTcpPortOwner({
        port: entry.gate_port,
        expectedPid: runtime.pid,
        expectedUid: input.gateUid,
        expectedPidStart: runtime.pid_start,
      });
      if (!owner.ok) {
        reasons.push(`gate port ${entry.gate_port} listener is not the gate daemon (${owner.reason})`);
      }
      // Fresh oracle probe: the pf union must be LIVE right now (and this
      // publishes/refreshes the signed token the gate verifies per-CONNECT).
      try {
        const token = await input.oracle.refresh({
          agentUid: input.agentUid,
          gatePort: entry.gate_port,
          generationId: committed.generation_id,
        });
        if (token === null) reasons.push("pf anchor liveness probe reported NOT live");
      } catch (err) {
        reasons.push(`oracle refresh failed: ${(err as Error).message}`);
      }
      if (reasons.length > 0) return { ok: false, reasons };
      return { ok: true, observed: committed };
    },
    async commitGeneration(): Promise<CommittedGenerationIdentity> {
      // Install path: G5 already committed by the coordinator strictly before
      // this sequence; boot path: the committed generation persisted. Either
      // way the commit this release binds to is the REGISTRY's committed
      // generation, resolved through the S5-2 resolver (staging/dirty aware).
      const committed = await readCommitted();
      if (committed === null) {
        throw new Error(`no committed generation for uid ${input.agentUid}; refusing to release`);
      }
      return committed;
    },
    async writeReleasedPlist(committed): Promise<void> {
      await writePlist(committed.generation_id);
    },
    async restoreParkedPlist(): Promise<void> {
      await writePlist(0);
    },
    async harnessStatus(): Promise<HarnessDaemonStatus> {
      const status = await agentHarnessDaemonStatus(harnessOps);
      if (!status.known || !status.running) return status;
      const stable = await agentHarnessDaemonStableRunning(harnessOps);
      return { ...status, running: stable };
    },
  };
}

/**
 * Build the install-time {@link ExclusiveEgressArmOps} (the object
 * `runProvisionFlow`'s exclusive stage consumes). Provisions the gate service
 * account on first use inside `bringUpGeneration` (fail-closed: no account,
 * no generation).
 */
export function createInstallExclusiveEgressOps(input: ExclusiveEgressWiringInput): ExclusiveEgressArmOps {
  let state: BringUpState | null = null;
  let oracle: GateLivenessOracle | null = null;

  async function ensureState(): Promise<{ state: BringUpState; oracle: GateLivenessOracle }> {
    if (state !== null && oracle !== null) return { state, oracle };
    const account = await planAndCreateGateAccount(
      {
        agentId: input.agentId,
        agentUid: input.agentUid,
        excludeUids: input.excludeUids,
        ceiling: input.gateAccountCeiling,
        homeDirectory: input.gateHomeDirectory,
      },
      input.accountOps,
    );
    const keys = await ensureSupervisorOracleKeys();
    state = { gateUid: account.uid, gateAccountName: account.accountName };
    oracle = createProductionOracle(keys.privateKey, account.uid);
    return { state, oracle };
  }

  return {
    async bringUpGeneration(): Promise<ExclusiveGenerationIdentity> {
      const { state: s, oracle: o } = await ensureState();
      return productionBringUp(input, s, o);
    },
    async runReleaseSequence(committed): Promise<ReleaseBarrierOutcome> {
      let barrierOps: ReleaseBarrierOps;
      if (input.internals?.barrierOps !== undefined) {
        barrierOps = input.internals.barrierOps;
      } else {
        const { state: s, oracle: o } = await ensureState();
        barrierOps = createProductionReleaseBarrierOps({
          agentUid: committed.agent_uid,
          agentAccount: input.agentAccount,
          harnessArgv: input.harnessArgv,
          fortressPath: input.fortressPath,
          harnessLogDir: input.harnessLogDir,
          gateUid: s.gateUid,
          oracle: o,
          rearm: "install-noop",
          print: input.print,
        });
      }
      // Fix-round-4 P1: bind the release to the generation THIS RUN brought
      // up, exactly like the boot path's fix-round-3 MED-4 guard. The barrier
      // ops' `commitGeneration` re-reads the registry and would bind to
      // whatever generation is CURRENT -- under a concurrent repair/install
      // for the same uid, run A would release run B's generation with A's
      // stale context (gate uid, oracle, argv) while A's caller audits and
      // reports A's generation id. A mismatch THROWS, which the barrier maps
      // to a loud fail-closed park at commit-generation (agent stays parked).
      const guardedOps: ReleaseBarrierOps = {
        ...barrierOps,
        commitGeneration: async (): Promise<CommittedGenerationIdentity> => {
          const observed = await barrierOps.commitGeneration();
          if (observed.generation_id !== committed.generation_id) {
            throw new Error(
              `registry changed during release for uid ${input.agentUid}: this run brought up committed ` +
                `generation ${committed.generation_id} but the registry now commits generation ` +
                `${observed.generation_id} (a concurrent install/repair advanced it); refusing to ` +
                "release a generation this run did not bring up; the agent stays parked fail-closed " +
                "-- re-run the repair",
            );
          }
          return observed;
        },
      };
      return runReleaseBarrierSequence(
        {
          agentUid: input.agentUid,
          harnessLabel: AGENT_HARNESS_DAEMON_LABEL,
          harnessArgv: input.harnessArgv,
        },
        guardedOps,
      );
    },
    async restoreCoarseComposition(reason): Promise<void> {
      await restoreCoarseCompositionProduction(input, reason);
    },
    async startHarnessCoarse(): Promise<void> {
      // The degrade path re-renders the PLAIN (RunAtLoad/KeepAlive) plist and
      // brings the harness up through the shipped coarse install path
      // (bootstrap + stable-pid verify), after re-enabling the job the park
      // disabled.
      const harnessOps = realHarnessOps();
      const plan = planAgentHarnessDaemonInstall({
        agentAccount: input.agentAccount,
        programArguments: input.harnessArgv,
        fortressPath: input.fortressPath,
        logDir: input.harnessLogDir,
      });
      await setAgentHarnessJobDisabled(harnessOps, false);
      await installAgentHarnessDaemon(plan, harnessOps);
    },
    audit: input.audit,
    print: input.print,
  };
}

/**
 * DEGRADE-LOUD manifest restore (the S5-4 coarse-only path): stop the gate
 * DAEMON first (fix-round M5: a live gate must never keep serving over
 * surfaces this function is about to tear down, and a failed stop THROWS
 * loudly rather than being swallowed), then remove the exclusive marker +
 * gate policy, republish the endpoint rules agent-scoped, verify the coarse
 * composition residue-free + emit the REQUIRED
 * `exclusive_routing_coarse_fallback` audit, tear the remaining gate
 * surfaces down (registry entry, credential, oracle token), reload. Throws
 * on failure (the caller keeps the agent parked, loudly).
 */
export async function restoreCoarseCompositionProduction(
  input: ExclusiveEgressWiringInput,
  reason: string,
  /** TEST SEAM: launchctl/rm recorders (production always uses the real ops). */
  deps?: {
    runLaunchctl?: (args: readonly string[]) => Promise<{ code: number; stdout: string; stderr: string }>;
    removeFile?: (path: string) => Promise<void>;
  },
): Promise<void> {
  const launchctl = deps?.runLaunchctl ?? runLaunchctl;
  const removeFile = deps?.removeFile ?? (async (path: string): Promise<void> => rm(path, { force: true, recursive: true }));
  // 0. GATE DAEMON DOWN FIRST (fix-round M5). A "no such process"/not-found
  // bootout is success (nothing was running); any OTHER failure throws --
  // tearing down the credential/registry/config under a still-serving gate
  // would leave a live-but-unaccounted-for daemon, and swallowing that was
  // the exact reviewed defect. The caller keeps the agent parked, loudly.
  const bootout = await launchctl(["bootout", `system/${egressGateDaemonLabel(input.agentUid)}`]);
  if (bootout.code !== 0 && !/No such process|Could not find|not find service/i.test(bootout.stderr)) {
    throw new Error(
      `coarse restore: could not stop the egress-gate daemon (launchctl bootout exited ${bootout.code}: ` +
        `${bootout.stderr.trim()}); refusing to tear down the gate surfaces under a possibly-live gate`,
    );
  }
  // 1. Marker + gate policy OFF next: from the next compose the daemon is in
  // plain coarse mode (gate-scoped rules briefly compose coarse -- the agent
  // has no direct allows in that window, which is the safe direction).
  await removeFile(exclusiveRoutingMarkerPath(input.fortressPath));
  await removeFile(join(input.fortressPath, "policy", "egress", EXCLUSIVE_EGRESS_GATE_FILENAME));
  // 2. Registry entry off (un-confine the agent's loopback from the dead gate
  // port; flush only fires when the last uid leaves) + token/credential off.
  const registry = createProductionAnchorRegistry();
  const { entries } = await registry.list();
  if (entries.some((e) => e.agent_uid === input.agentUid)) {
    await registry.remove(input.agentUid);
  }
  const keys = await ensureSupervisorOracleKeys();
  const gateAccountName = deriveGateAccountName(input.agentId);
  // Best-effort uid resolution for teardown surfaces that need the gate uid;
  // a missing account means nothing to tear down on those surfaces.
  let gateUid: number | undefined;
  try {
    const found = await input.accountOps.lookupAccountUid(gateAccountName);
    gateUid = found ?? undefined;
  } catch {
    gateUid = undefined;
  }
  if (gateUid !== undefined) {
    const oracle = createProductionOracle(keys.privateKey, gateUid);
    await oracle.invalidate(input.agentUid);
    await createFsGateCredentialAuthority({ gateUid }).revoke(input.agentUid);
  }
  // 3. Plist + config copies + the per-uid runtime dir off (daemon already
  // stopped in step 0).
  await removeFile(egressGateDaemonPlistPath(input.agentUid));
  await removeFile(egressGatePolicyConfigPath(input.agentUid));
  await removeFile(egressGateRulesConfigPath(input.agentUid));
  await removeFile(egressGateRuntimeUidDirPath(input.agentUid));
  // 4. Republish the endpoint rules AGENT-scoped (coarse) + reload.
  const published = await input.publishProvisionedRules({ mode: "coarse" });
  if (!published.ok) {
    throw new Error(`coarse republish failed: ${published.error}`);
  }
  // 5. Verify + AUDIT through the S5-4 coarse-only composition (residue check
  // + the REQUIRED exclusive_routing_coarse_fallback audit record). The
  // compose here is a verification pass over the read-back rules -- the
  // daemon's own signed compose is the enforced one; both consume the same
  // persisted rule files.
  const { readEgressRulesFromDisk } = await import("../castle-wall/provision/egress.js");
  const { collectSystemResolvers } = await import("../castle-wall/runtime/system-resolvers.js");
  const rules = await readEgressRulesFromDisk(input.fortressPath);
  await composeExclusiveRoutingRules({
    base: {
      operatorRules: rules,
      resolvers: await collectSystemResolvers(),
      createdAt: new Date().toISOString(),
    },
    routing: {
      mode: "coarse-only",
      agent_uid: input.agentUid,
      reason,
      audit: async (record) => {
        await input.audit(record.operation, {
          reason: record.reason,
          agent_uid: record.agent_uid,
          coarse_provisioned_rule_ids: record.coarse_provisioned_rule_ids,
        });
      },
    },
  });
}

/** What the persistent-park helpers need to know about the agent. */
export interface PersistentParkContext {
  agentUid: number;
  agentAccount: string;
  harnessArgv: string[];
  fortressPath: string;
  harnessLogDir: string;
}

/** TEST-ONLY dep seams for the persistent-park helpers; production omits. */
export interface PersistentParkDeps {
  runLaunchctlFn?: (args: readonly string[]) => Promise<{ code: number; stdout: string; stderr: string }>;
  writeFileFn?: (path: string, content: string, mode: number) => Promise<void>;
  removeFileFn?: (path: string) => Promise<void>;
  readFileFn?: (path: string) => Promise<string>;
  sleepMs?: (ms: number) => Promise<void>;
}

/**
 * Check launchd's PERSISTENT override database for the harness job's
 * disabled state (`launchctl print-disabled system`). A `launchctl disable`
 * whose override write silently did not take effect leaves the job
 * bootable at the next boot, so "disabled" must be read back, not assumed
 * (fix-round-2 HIGH-2). Fail-closed: an unreadable override db or an absent
 * / enabled entry is NOT disabled-verified.
 */
export async function verifyHarnessJobDisabled(
  runLaunchctlFn: (args: readonly string[]) => Promise<{ code: number; stdout: string; stderr: string }> = runLaunchctl,
): Promise<{ ok: true } | { ok: false; reason: string }> {
  const r = await runLaunchctlFn(["print-disabled", "system"]);
  if (r.code !== 0) {
    return { ok: false, reason: `launchctl print-disabled system exited ${r.code}: ${r.stderr.trim()}` };
  }
  // macOS prints either `"<label>" => disabled` (newer) or `"<label>" => true`.
  const label = AGENT_HARNESS_DAEMON_LABEL.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (new RegExp(`"${label}"\\s*=>\\s*(disabled|true)\\b`).test(r.stdout)) {
    return { ok: true };
  }
  return {
    ok: false,
    reason: `launchd's override database does not show ${AGENT_HARNESS_DAEMON_LABEL} disabled (the job can boot at next reboot)`,
  };
}

/**
 * Verify the FULL persistent parked posture for the harness (fix-round-2
 * HIGH-2): (a) the job has no running pid, (b) the job is disabled in
 * launchd's persistent override db, (c) the per-uid hold file is ABSENT,
 * and (d) the on-disk plist is the PARKED barrier form (or absent -- no
 * unit at all is unbootable). A stopped-but-releasable harness (enable
 * override on, released plist + hold file still on disk) fails this check:
 * it can boot at the next reboot. Never throws; every failed check is one
 * enumerated problem.
 */
export async function verifyHarnessParkedPersistent(
  ctx: PersistentParkContext,
  deps: PersistentParkDeps = {},
): Promise<{ ok: true } | { ok: false; problems: string[] }> {
  const launchctlFn = deps.runLaunchctlFn ?? runLaunchctl;
  const readFileFn = deps.readFileFn ?? (async (path: string): Promise<string> => readFile(path, "utf8"));
  const harnessOps: HarnessDaemonOps = {
    ...realHarnessOps(),
    runLaunchctl: launchctlFn,
    ...(deps.sleepMs !== undefined ? { sleepMs: deps.sleepMs } : {}),
  };
  const problems: string[] = [];
  // (a) Not running.
  try {
    const status = await agentHarnessDaemonStatus(harnessOps);
    if (!status.known) {
      problems.push("launchctl did not return a trustworthy harness status");
    } else if (status.running) {
      problems.push(`the harness job reports RUNNING (pid ${status.pid ?? "unknown"})`);
    }
  } catch (err) {
    problems.push(`status probe errored: ${(err as Error).message}`);
  }
  // (b) Persistently disabled.
  const disabled = await verifyHarnessJobDisabled(launchctlFn);
  if (!disabled.ok) problems.push(disabled.reason);
  // (c) Hold file absent (stale release material).
  const holdPath = holdFilePathForUid(ctx.agentUid);
  try {
    await readFileFn(holdPath);
    problems.push(`the release hold file ${holdPath} is still present (stale release material)`);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      problems.push(`could not check the release hold file ${holdPath}: ${(err as Error).message}`);
    }
  }
  // (d) Parked plist form (a released plist embeds a real generation id the
  // wrapper would accept; an ABSENT plist is unbootable, which is fine).
  const plan = planParkedHarnessInstall({
    agentAccount: ctx.agentAccount,
    agentUid: ctx.agentUid,
    harnessArgv: ctx.harnessArgv,
    fortressPath: ctx.fortressPath,
    logDir: ctx.harnessLogDir,
  });
  try {
    const onDisk = await readFileFn(plan.plistPath);
    if (onDisk !== plan.plistContent) {
      problems.push(
        `the harness plist ${plan.plistPath} is not the parked barrier form (possible released-plist residue)`,
      );
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      problems.push(`could not check the harness plist ${plan.plistPath}: ${(err as Error).message}`);
    }
  }
  return problems.length === 0 ? { ok: true } : { ok: false, problems };
}

/**
 * PARK the harness into the FULL persistent parked state (fix-round-2
 * HIGH-2; supersedes the fix-round BLOCKER-3 bootout+disable-only park):
 * bootout (not-running is success) + persistent disable + hold-file removal
 * + parked-plist restore, EACH result captured, then verify the whole
 * posture via {@link verifyHarnessParkedPersistent}. Throws with every
 * failed step enumerated unless the full parked state is verified -- a
 * "parked" claim that leaves stale release material bootable at the next
 * reboot was the exact reviewed defect.
 */
export async function parkHarnessPersistently(
  ctx: PersistentParkContext,
  deps: PersistentParkDeps = {},
): Promise<void> {
  const launchctlFn = deps.runLaunchctlFn ?? runLaunchctl;
  const writeFileFn =
    deps.writeFileFn ?? (async (path: string, content: string, mode: number): Promise<void> => writeFile(path, content, { mode }));
  const removeFileFn = deps.removeFileFn ?? (async (path: string): Promise<void> => rm(path, { force: true }));
  const problems: string[] = [];
  const bootout = await launchctlFn(["bootout", `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
  if (bootout.code !== 0 && !/No such process|Could not find|not find service/i.test(bootout.stderr)) {
    problems.push(`launchctl bootout exited ${bootout.code}: ${bootout.stderr.trim()}`);
  }
  const disable = await launchctlFn(["disable", `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
  if (disable.code !== 0) {
    problems.push(`launchctl disable exited ${disable.code}: ${disable.stderr.trim()}`);
  }
  try {
    await removeFileFn(holdFilePathForUid(ctx.agentUid));
  } catch (err) {
    problems.push(`hold-file removal failed: ${(err as Error).message}`);
  }
  try {
    const plan = planParkedHarnessInstall({
      agentAccount: ctx.agentAccount,
      agentUid: ctx.agentUid,
      harnessArgv: ctx.harnessArgv,
      fortressPath: ctx.fortressPath,
      logDir: ctx.harnessLogDir,
    });
    await writeFileFn(plan.plistPath, plan.plistContent, 0o644);
  } catch (err) {
    problems.push(`parked-plist restore failed: ${(err as Error).message}`);
  }
  const verified = await verifyHarnessParkedPersistent(ctx, deps);
  if (!verified.ok) problems.push(...verified.problems);
  if (problems.length > 0) {
    throw new Error(`park not verified: ${problems.join("; ")}`);
  }
}

/**
 * Recover any in-flight (uncommitted) generation for one uid through the
 * production S5-2 coordinator: real registry, real staging store, real
 * owner-check, per-uid O_EXCL lock. Shared by the repair verb and the S5-7
 * unprotect sequence (recover() never allocates or publishes; the manifest
 * publisher throws by construction).
 */
async function productionRecoverGeneration(agentUid: number): Promise<void> {
  const registry = createProductionAnchorRegistry();
  const coordinator = new GenerationCoordinator({
    bind: async () => bindEphemeralGatePort(),
    verifyOwner: async ({ port, pid }) =>
      (await verifyLoopbackTcpPortOwner({ port, expectedPid: pid })).ok,
    registry: {
      armEntry: async (entry) => {
        await registry.addOrUpdate({
          agent_uid: entry.agent_uid,
          gate_port: entry.gate_port,
          fortress_path: entry.fortress_path,
          generation_id: entry.generation_id,
        });
      },
      tombstone: async (uid, fallback) => {
        await registry.tombstone(uid, fallback);
      },
      readEntry: async (uid) => {
        const { entries } = await registry.list();
        return entries.find((e) => e.agent_uid === uid) ?? null;
      },
      // Fix-round-5 P1: the persisted floor covering repair-discarded
      // generations (recover() never allocates, but the adapter stays
      // complete and consistent with the install-path adapter).
      readGenerationFloor: async () => (await registry.list()).generationFloor,
    },
    publishManifest: async () => {
      throw new Error("recover() must never publish a manifest");
    },
    staging: createFsGenerationStagingStore(),
    lock: fsLockOps(),
  });
  await coordinator.recover(agentUid);
}

/**
 * Repair ops (`--repair-egress-gate`): drift guard + verified PERSISTENT
 * harness park (fix-round BLOCKER-3 + fix-round-2 HIGH-2) + recover +
 * bring-up + release.
 */
export function createRepairExclusiveEgressOps(input: ExclusiveEgressWiringInput): {
  diffTransientPfRules(): Promise<{ foreign: string[] }>;
  parkHarness(): Promise<void>;
  verifyParkedPersistent(): Promise<{ ok: true } | { ok: false; problems: string[] }>;
  repairQuarantinedRegistry(): Promise<PfAnchorQuarantineRepairResult>;
  recoverGeneration(): Promise<void>;
  bringUpGeneration(): Promise<ExclusiveGenerationIdentity>;
  runReleaseSequence(committed: ExclusiveGenerationIdentity): Promise<ReleaseBarrierOutcome>;
  audit(operation: string, details: Record<string, unknown>): Promise<void>;
  print(line: string): void;
} {
  const install = createInstallExclusiveEgressOps(input);
  const parkCtx: PersistentParkContext = {
    agentUid: input.agentUid,
    agentAccount: input.agentAccount,
    harnessArgv: input.harnessArgv,
    fortressPath: input.fortressPath,
    harnessLogDir: input.harnessLogDir,
  };
  return {
    async diffTransientPfRules(): Promise<{ foreign: string[] }> {
      const diff = await diffTransientPfRules(createExecFilePfRunner());
      return { foreign: diff.foreign };
    },
    parkHarness: () => parkHarnessPersistently(parkCtx),
    verifyParkedPersistent: () => verifyHarnessParkedPersistent(parkCtx),
    async repairQuarantinedRegistry(): Promise<PfAnchorQuarantineRepairResult> {
      // Fix-round-4 P2: the coded recovery path for a quarantined committed
      // entry. Every OTHER registry mutation in the repair sequence enters
      // through `normalizeState`, which throws on the malformed entry -- so
      // this must run FIRST or the documented repair verb can never rewrite
      // anything (host-wide token denial until manual surgery).
      return createProductionAnchorRegistry().repairQuarantined();
    },
    recoverGeneration: () => productionRecoverGeneration(input.agentUid),
    bringUpGeneration: () => install.bringUpGeneration(),
    runReleaseSequence: (committed) => install.runReleaseSequence(committed),
    audit: input.audit,
    print: input.print,
  };
}

/**
 * How the S5-7 park disposes of the harness plist. Because step 0 asserts the
 * leaving uid is the SOLE exclusive agent (no sibling behind the host-singleton
 * label), the park always fully tears the label down; only the plist byte-state
 * differs:
 *  - `restore`: rewrite the parked barrier plist (the normal path -- the
 *    harness argv is available, so the parked form is re-rendered on disk).
 *  - `remove`: DELETE the plist (the argv-unavailable fallback, MED-1). An
 *    ABSENT plist is unbootable, which {@link verifyHarnessParkedPersistent}
 *    already accepts, so the unprotect can still complete its teardown when the
 *    re-homed harness runtime tree (the argv source) was damaged or deleted --
 *    instead of wedging permanently while pf rules + the registry entry + the
 *    gate daemon + credentials all persist with no recovery path.
 */
export type UnprotectParkPlistDisposition = "restore" | "remove";

/**
 * Verified persistent park for the S5-7 unprotect sequence. Because the leaving
 * uid is the sole exclusive agent (step 0 invariant), the host-singleton
 * harness label ({@link AGENT_HARNESS_DAEMON_LABEL}) + its plist
 * ({@link AGENT_HARNESS_DAEMON_PLIST_PATH}) belong to it alone, so the full
 * S5-5 verified park applies:
 *  - `restore`: delegate to {@link parkHarnessPersistently} (bootout + disable
 *    + hold-file removal + parked-plist RESTORE, verified) -- the exact,
 *    well-covered S5-5 path, unchanged.
 *  - `remove`: bootout + disable + hold-file removal + parked-plist REMOVAL
 *    (absent === unbootable), then the same {@link verifyHarnessParkedPersistent}
 *    posture (which accepts an absent plist).
 */
async function parkHarnessForUnprotect(
  ctx: PersistentParkContext,
  plistDisposition: UnprotectParkPlistDisposition,
  deps: PersistentParkDeps = {},
): Promise<void> {
  // Normal restore disposition == the exact S5-5 verified park; delegate so
  // that well-covered path is unchanged.
  if (plistDisposition === "restore") {
    await parkHarnessPersistently(ctx, deps);
    return;
  }
  // argv-unavailable fallback (MED-1): full label teardown + REMOVE the plist.
  const launchctlFn = deps.runLaunchctlFn ?? runLaunchctl;
  const removeFileFn = deps.removeFileFn ?? (async (path: string): Promise<void> => rm(path, { force: true }));
  const problems: string[] = [];
  const bootout = await launchctlFn(["bootout", `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
  if (bootout.code !== 0 && !/No such process|Could not find|not find service/i.test(bootout.stderr)) {
    problems.push(`launchctl bootout exited ${bootout.code}: ${bootout.stderr.trim()}`);
  }
  const disable = await launchctlFn(["disable", `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
  if (disable.code !== 0) {
    problems.push(`launchctl disable exited ${disable.code}: ${disable.stderr.trim()}`);
  }
  try {
    await removeFileFn(holdFilePathForUid(ctx.agentUid));
  } catch (err) {
    problems.push(`hold-file removal failed: ${(err as Error).message}`);
  }
  try {
    await removeFileFn(AGENT_HARNESS_DAEMON_PLIST_PATH);
  } catch (err) {
    problems.push(`parked-plist removal failed: ${(err as Error).message}`);
  }
  const verified = await verifyHarnessParkedPersistent(ctx, deps);
  if (!verified.ok) problems.push(...verified.problems);
  if (problems.length > 0) {
    throw new Error(`park not verified: ${problems.join("; ")}`);
  }
}

/** TEST-ONLY dep seams for {@link createUnprotectExclusiveEgressOps}; production omits. */
export interface UnprotectWiringDeps {
  runLaunchctl?: (args: readonly string[]) => Promise<{ code: number; stdout: string; stderr: string }>;
  removeFile?: (path: string) => Promise<void>;
  registry?: PfAnchorRegistry;
  recoverGeneration?: (agentUid: number) => Promise<void>;
  parkDeps?: PersistentParkDeps;
  scrubRules?: () => Promise<{ removedRuleIds: string[]; reloadOk: boolean }>;
  /** Injected provision-lock ops (production: the real O_EXCL {@link fsLockOps}). */
  lockOps?: ProvisionLockOps;
}

/**
 * Production ops for the S5-7 per-agent unprotect sequence
 * (`runEgressGateUnprotect`, `castle-wall/provision/exclusive-unprotect.ts`).
 * Maps each injected op onto the real primitive:
 *
 *  - lock: `withUnprotectLock` -> `withProvisionLock(PROVISION_LOCK_PATH, ...)`,
 *    the SAME O_EXCL lock the arm/repair paths take, held around the WHOLE
 *    sequence (S5-7 fix-round-2 HIGH-1) so a concurrent `protect --exclusive-egress`
 *    cannot commit a sibling between the invariant assertion and the teardown.
 *  - invariant: `assertSoleUserInvariant` reads the committed non-tombstone
 *    registry set (under the lock) and refuses when ANY other committed entry
 *    shares the leaving uid's fortress OR harness. The registry entry does not
 *    record a harness id and v1 provisions a single harness (Hermes), so the
 *    fail-closed reading is that ANY other committed non-tombstone entry is a
 *    shared-fortress/harness sibling -- the ONLY reachable v1 state is exactly
 *    one exclusive agent, and a second exclusive install overwrites the first's
 *    single-uid marker. An unreadable registry THROWS (the sequence refuses).
 *  - park/verify: the full S5-5 verified persistent park (bootout + persistent
 *    disable + hold-file removal + parked-plist restore-or-remove, read back).
 *    Because the invariant proved the leaving uid is the sole exclusive agent,
 *    the host-singleton harness label + plist belong to it alone, so the whole
 *    label is torn down (no sibling branch). See {@link parkHarnessForUnprotect}.
 *  - policy surfaces: every surface goes -- the per-uid gate daemon plist /
 *    config copies / runtime dir AND the fortress exclusive-routing marker +
 *    gate policy file (the leaving uid is the sole user; no retention branch).
 *  - manifest scrub: `scrubProvisionedEgressRules` removes the LEAVING harness's
 *    `provisioned-<harnessId>-*` rules; runs BEFORE the routing-marker removal so
 *    a crash + external reload composes marker-present-no-rules (blocked,
 *    fail-closed) rather than marker-gone-rules-present (agent-scoped, fail-open).
 *  - recover: the shared production S5-2 recovery (staging record resolved
 *    per the crash table; a tombstoned dead generation keeps its id in the
 *    registry entry so the final remove folds it into the persisted floor).
 *  - gate daemon: `launchctl bootout` -- not-found is success, any other
 *    failure THROWS (S5-6 M5: never tear down surfaces under a live gate).
 *  - credential/oracle: DIRECT single-source path removals
 *    ({@link gateCredentialAcceptPath}/{@link gateCredentialTokenPath}/
 *    {@link gateLivenessTokenPath}) -- deliberately NOT through a constructed
 *    authority/oracle, so revocation works even when the gate service
 *    account or oracle keys are already gone (idempotent re-run after a
 *    partial teardown).
 *  - registry: the production S5-1 locked registry `remove()` (union re-render,
 *    per-remaining-tombstone liveness, flush when empty, generation floor folded).
 */
export function createUnprotectExclusiveEgressOps(
  input: ExclusiveEgressWiringInput,
  deps: UnprotectWiringDeps = {},
): EgressGateUnprotectOps {
  const launchctl = deps.runLaunchctl ?? runLaunchctl;
  const removeFile =
    deps.removeFile ?? (async (path: string): Promise<void> => rm(path, { force: true, recursive: true }));
  const registry = deps.registry ?? createProductionAnchorRegistry();
  const lockOps = deps.lockOps ?? fsLockOps();
  const parkDeps = deps.parkDeps ?? {};
  const plistDisposition: UnprotectParkPlistDisposition =
    input.parkPlistFallbackRemoval === true ? "remove" : "restore";
  const parkCtx: PersistentParkContext = {
    agentUid: input.agentUid,
    agentAccount: input.agentAccount,
    harnessArgv: input.harnessArgv,
    fortressPath: input.fortressPath,
    harnessLogDir: input.harnessLogDir,
  };
  return {
    withUnprotectLock: <T>(fn: () => Promise<T>): Promise<T> =>
      withProvisionLock(PROVISION_LOCK_PATH, lockOps, fn),
    async assertSoleUserInvariant(): Promise<{ ok: true } | { ok: false; conflictingUids: number[] }> {
      // Read the COMMITTED non-tombstone set (an unreadable registry throws ->
      // the sequence refuses fail-closed). Any OTHER committed non-tombstone
      // entry is a shared-fortress/harness sibling this per-agent teardown
      // cannot safely dismantle: the routing marker names ONE uid, the gate
      // policy file is fortress-keyed, and the scrub is harness-keyed, and the
      // registry carries no per-entry harness id (v1 is single-harness). So the
      // fail-closed invariant is exactly "no other committed non-tombstone uid."
      const { entries } = await registry.list();
      const conflictingUids = entries
        .filter((e) => e.agent_uid !== input.agentUid && e.tombstone !== true)
        .map((e) => e.agent_uid);
      return conflictingUids.length === 0 ? { ok: true } : { ok: false, conflictingUids };
    },
    parkHarness: async (): Promise<void> => {
      await parkHarnessForUnprotect(parkCtx, plistDisposition, parkDeps);
    },
    verifyParkedPersistent: async (): Promise<{ ok: true } | { ok: false; problems: string[] }> =>
      verifyHarnessParkedPersistent(parkCtx, parkDeps),
    recoverGeneration: () => (deps.recoverGeneration ?? productionRecoverGeneration)(input.agentUid),
    async bootoutGateDaemon(): Promise<void> {
      const label = egressGateDaemonLabel(input.agentUid);
      const bootout = await launchctl(["bootout", `system/${label}`]);
      if (bootout.code !== 0 && !/No such process|Could not find|not find service/i.test(bootout.stderr)) {
        throw new Error(`launchctl bootout ${label} exited ${bootout.code}: ${bootout.stderr.trim()}`);
      }
    },
    async invalidateOracleToken(): Promise<void> {
      await removeFile(gateLivenessTokenPath(input.agentUid));
    },
    async revokeCredential(): Promise<void> {
      await removeFile(gateCredentialAcceptPath(input.agentUid));
      await removeFile(gateCredentialTokenPath(input.agentUid));
    },
    async removeGateSurfaces(): Promise<void> {
      // The leaving uid is the sole exclusive agent (step 0 invariant), so
      // every surface is torn down. PER-UID surfaces (the gate daemon was
      // already booted out, step 3):
      await removeFile(egressGateDaemonPlistPath(input.agentUid));
      await removeFile(egressGatePolicyConfigPath(input.agentUid));
      await removeFile(egressGateRulesConfigPath(input.agentUid));
      await removeFile(egressGateRuntimeUidDirPath(input.agentUid));
      // Fortress exclusive-routing marker + gate policy file (single-uid /
      // fortress-keyed; safe to remove because no sibling shares them).
      await removeFile(exclusiveRoutingMarkerPath(input.fortressPath));
      await removeFile(join(input.fortressPath, "policy", "egress", EXCLUSIVE_EGRESS_GATE_FILENAME));
    },
    async scrubProvisionedRules(): Promise<{ removedRuleIds: string[]; reloadOk: boolean }> {
      if (deps.scrubRules !== undefined) return deps.scrubRules();
      const { scrubProvisionedEgressRules } = await import("../castle-wall/provision/egress.js");
      const result = await scrubProvisionedEgressRules({
        fortressPath: input.fortressPath,
        harnessId: input.agentId,
        reloadPolicy: () => input.reloadPolicy(),
      });
      return { removedRuleIds: result.removedRuleIds, reloadOk: result.reloadOk };
    },
    async removeRegistryEntry(): Promise<{ remainingUids: number[]; flushed: boolean; dirty: boolean }> {
      const result = await registry.remove(input.agentUid);
      return {
        remainingUids: result.committed.map((e) => e.agent_uid),
        flushed: result.committed.length === 0,
        dirty: result.dirty,
      };
    },
    audit: input.audit,
    print: input.print,
  };
}

// ---------------------------------------------------------------------------
// Boot supervisor (called by the root Castle Wall policy daemon)
// ---------------------------------------------------------------------------

/** Handle for the boot supervisor's ongoing oracle refresh loop. */
export interface ExclusiveEgressBootSupervisorHandle {
  results: BootReleaseResult[];
  stopOracleLoop(): void;
}

/** Registry entry shape the supervisor consumes (S5-1 + additive S5-2 fields). */
export interface BootRegistryEntry {
  agent_uid: number;
  gate_port: number;
  fortress_path: string;
  generation_id?: number;
  tombstone?: boolean;
}

/**
 * The honest v1-scope park reason for a non-Hermes confined agent (fix-round
 * M6: the prior "marker/account missing" wording misdescribed a deliberate
 * scope bound as a fault). Exported so the CLI resolver and the tests share
 * one string.
 */
export const NON_HERMES_BOOT_PARK_REASON =
  "v1 releases only Hermes; other confined agents stay parked by design.";

/** Discriminated boot-agent resolution (fix-round H1: never a bare null). */
export type BootAgentResolution =
  | {
      kind: "ok";
      agentAccount: string;
      harnessArgv: string[];
      harnessLogDir: string;
      gateUid: number;
    }
  | { kind: "unresolvable"; reason: string };

/**
 * A committed registry entry that failed per-entry validation and was
 * QUARANTINED by the read layer (fix-round-2 MED-6): identified by its
 * position so the operator can find and repair it; its agent's gate keeps
 * denying (fail-closed) while other agents keep refreshing.
 */
export interface QuarantinedBootRegistryEntry {
  index: number;
  reason: string;
}

/** A boot-supervisor registry read: usable entries + quarantined findings. */
export interface BootRegistryListing {
  entries: BootRegistryEntry[];
  quarantined: QuarantinedBootRegistryEntry[];
  /**
   * Registry-level needs-repair bit (fix-round-3 HIGH-2): true on a
   * quarantined entry, a journaled pending set, an explicit dirty marker, or
   * a missing enable token. While dirty, the live pf anchor may DIVERGE from
   * the committed union, and the per-uid liveness probe behind the oracle
   * refresh cannot rule out EXTRA permissive rules -- so the refresh loop
   * WITHHOLDS freshness tokens (the gate denies within one TTL, fail-closed)
   * instead of re-signing liveness nobody can verify.
   */
  dirty: boolean;
}

/**
 * TEST-ONLY seams for {@link startExclusiveEgressBootSupervisor}. Production
 * callers omit this entirely (real registry, launchctl, barrier, oracle).
 * Kept in one bag so the production call sites stay obviously seam-free.
 */
export interface ExclusiveEgressBootSupervisorInternals {
  listRegistryEntries?: () => Promise<BootRegistryListing>;
  ensureKeys?: () => Promise<{ privateKey: KeyObject; publicKey: KeyObject }>;
  runLaunchctlFn?: (args: readonly string[]) => Promise<{ code: number; stdout: string; stderr: string }>;
  runBarrier?: typeof runReleaseBarrierSequence;
  createBarrierOps?: typeof createProductionReleaseBarrierOps;
  createOracle?: (privateKey: KeyObject, gateUid: number) => Pick<GateLivenessOracle, "refresh">;
  removeHoldFile?: (agentUid: number) => Promise<void>;
  readRuntimeState?: (agentUid: number) => Promise<string>;
  gateWaitBudgetMs?: number;
  gateWaitIntervalMs?: number;
  loadMarker?: (fortressPath: string) => Promise<{ agent_uid: number; gate_uid: number } | null>;
  ensureRuntimeFs?: (input: { agentUid: number; gateUid: number }) => Promise<void>;
}

/**
 * Reassert the parked state for an agent whose release CONTEXT could not be
 * resolved (fix-round H1: the pre-fix code reported a SYNTHETIC "parked"
 * with no ops run at all -- a crash-left enable override or hold file could
 * boot the harness while the log said PARKED). Without the harness argv /
 * account we cannot re-render the parked plist, but the ops we CAN run are
 * sufficient to hold the park: bootout stops any live job, the disable
 * override keeps launchd from bootstrapping it at boot, and removing the
 * hold file makes the exec wrapper refuse even a mistakenly-started job.
 *
 * SHARED-LABEL GUARD (fix-round-2 HIGH-3): the harness LaunchDaemon label
 * ({@link AGENT_HARNESS_DAEMON_LABEL}) is a HOST SINGLETON, so bootout /
 * disable act on whichever uid's harness currently owns it. When ANOTHER
 * registry entry resolved for release, running them here would kill that
 * uid's just-released (or about-to-be-released) harness while the log blames
 * this uid. In that case the caller passes `sharedLabelOpsAllowed: false`:
 * only the strictly PER-UID op (this uid's hold-file removal) runs -- which
 * alone holds this uid's park, because the exec wrapper refuses any start
 * without a matching hold file -- and the skip is reported honestly
 * (`sharedLabelOpsSkipped`, `jobDisabled: false`).
 *
 * Every failure is reported loudly in the returned flags/errors -- never a
 * clean "parked" that nobody verified.
 */
async function reassertParkedWithoutContext(input: {
  agentUid: number;
  runLaunchctlFn: (args: readonly string[]) => Promise<{ code: number; stdout: string; stderr: string }>;
  removeHoldFile: (agentUid: number) => Promise<void>;
  /** False when another uid resolved for release on the shared label (HIGH-3). */
  sharedLabelOpsAllowed: boolean;
}): Promise<{
  holdFileRemoved: boolean;
  jobDisabled: boolean;
  sharedLabelOpsSkipped: boolean;
  cleanupErrors: string[];
}> {
  const errors: string[] = [];
  if (input.sharedLabelOpsAllowed) {
    const bootout = await input.runLaunchctlFn(["bootout", `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
    if (bootout.code !== 0 && !/No such process|Could not find|not find service/i.test(bootout.stderr)) {
      errors.push(`bootout failed: launchctl exited ${bootout.code}: ${bootout.stderr.trim()}`);
    }
  }
  let holdFileRemoved = false;
  try {
    await input.removeHoldFile(input.agentUid);
    holdFileRemoved = true;
  } catch (err) {
    errors.push(`hold-file removal failed: ${(err as Error).message}`);
  }
  let jobDisabled = false;
  if (input.sharedLabelOpsAllowed) {
    const disable = await input.runLaunchctlFn(["disable", `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
    if (disable.code === 0) {
      jobDisabled = true;
    } else {
      errors.push(`disable failed: launchctl exited ${disable.code}: ${disable.stderr.trim()}`);
    }
  }
  return {
    holdFileRemoved,
    jobDisabled,
    sharedLabelOpsSkipped: !input.sharedLabelOpsAllowed,
    cleanupErrors: errors,
  };
}

/**
 * The boot daemon's exclusive-egress supervisor: for every fortress with an
 * exclusive-routing marker + registry entry, assert the runtime fs layout,
 * BOOTSTRAP the per-uid gate daemon (fix-round H2: its plist is
 * `RunAtLoad=false`, so the boot path must start it before `verifyGate` can
 * ever pass), then run the S5-5 boot release sequence (re-arm ->
 * gate-verify -> recommit/hold -> enable+bootstrap -> re-park) -- and keep
 * the oracle freshness-token loop running. NEVER throws.
 *
 * THE REFRESH LOOP RE-SCANS THE REGISTRY EVERY TICK (fix-round H3): the
 * install CLI's own oracle refresh dies when the CLI exits, so the
 * PERSISTENT cadence for install-provisioned agents lives HERE, in the
 * always-running root policy daemon. A successful install requires a live
 * policy-daemon reload (fail-closed), so any agent that armed exclusively
 * has this daemon running; its next tick (<= refreshIntervalMs) picks the
 * new registry entry up and keeps the token fresh. HONEST RESIDUAL (stated
 * loudly): the cadence lives in the boot-safe-mode policy daemon's process;
 * if an operator runs a fortress with NO castle-wall policy daemon resident,
 * tokens expire within the TTL and the gate denies everything -- fail-closed
 * non-functional, repairable by starting the daemon; drill-owed.
 *
 * Boot wiring detail: the harness argv + agent account are recovered from the
 * registry entry's fortress + the parked plist contract via the injected
 * resolver, because the boot daemon has no wrap context. An UNRESOLVABLE
 * agent (no marker, non-Hermes, OR a THROWING resolver -- fix-round-2
 * BLOCKER-1) is still parked FOR REAL via
 * {@link reassertParkedWithoutContext} -- never a synthetic unverified
 * "parked" report (fix-round H1).
 *
 * ORDERING (fix-round-2 HIGH-3): ALL entries are resolved BEFORE any side
 * effect, every contextless re-park runs BEFORE any release, and the
 * host-singleton harness label is booted out / disabled by a contextless
 * re-park ONLY when no entry resolved for release -- a stale unresolvable
 * entry must never kill another uid's just-released harness (with the log
 * blaming the wrong uid). A failure BEFORE the re-park/release loop
 * (supervisor oracle keys unavailable) yields the LOUD `park-not-verified`
 * outcome per agent, never a synthetic PARKED.
 */
export async function startExclusiveEgressBootSupervisor(input: {
  /** Resolve per-agent release context from the registry entry. */
  resolveAgent: (entry: { agent_uid: number; fortress_path: string }) => Promise<BootAgentResolution>;
  audit: (operation: string, details: Record<string, unknown>) => Promise<void>;
  print: (line: string) => void;
  /** Oracle refresh cadence (default: half the token TTL). */
  refreshIntervalMs?: number;
  /** TEST-ONLY seams; production omits. */
  internals?: ExclusiveEgressBootSupervisorInternals;
}): Promise<ExclusiveEgressBootSupervisorHandle> {
  const internals = input.internals ?? {};
  const listEntries =
    internals.listRegistryEntries ??
    (async (): Promise<BootRegistryListing> => {
      // Per-entry quarantine (fix-round-2 MED-6): one malformed committed
      // entry must not stop the boot release / oracle refresh for every
      // OTHER agent (a wholesale-throwing read was a mass egress denial
      // within one token TTL). Structural corruption still throws.
      const listed = await createProductionAnchorRegistry().listQuarantined();
      return { entries: listed.entries, quarantined: listed.quarantined, dirty: listed.dirty };
    });
  const launchctlFn = internals.runLaunchctlFn ?? runLaunchctl;
  const runBarrier = internals.runBarrier ?? runReleaseBarrierSequence;
  const createBarrierOps = internals.createBarrierOps ?? createProductionReleaseBarrierOps;
  const createOracle =
    internals.createOracle ??
    ((privateKey: KeyObject, gateUid: number): Pick<GateLivenessOracle, "refresh"> =>
      createProductionOracle(privateKey, gateUid));
  const removeHold =
    internals.removeHoldFile ?? (async (uid: number): Promise<void> => rm(holdFilePathForUid(uid), { force: true }));
  const loadMarker =
    internals.loadMarker ??
    (async (fortressPath: string): Promise<{ agent_uid: number; gate_uid: number } | null> =>
      loadExclusiveRoutingMarker(fortressPath));
  const ensureRuntimeFs = internals.ensureRuntimeFs ?? ensureExclusiveEgressRuntimeFs;

  let listing: BootRegistryListing;
  try {
    listing = await listEntries();
  } catch (err) {
    // HONESTY (fix-round-2 BLOCKER-1 class): an unreadable registry means NO
    // re-park op ran here; agents remain in their PERSISTED parked posture
    // (hold files + launchd disable overrides survive boots) but nothing was
    // re-verified this boot -- never claim a verified park.
    input.print(
      `[castle-wall] boot: exclusive-egress registry unreadable (${(err as Error).message}); ` +
        "NO boot release or re-park ran; confined agents remain in their persisted parked state, " +
        "which was NOT re-verified this boot. Repair: sudo sanctuary protect --repair-egress-gate",
    );
    return { results: [], stopOracleLoop: () => undefined };
  }
  const entries = listing.entries;
  for (const q of listing.quarantined) {
    input.print(
      `[castle-wall] boot: registry entry #${q.index} is malformed and QUARANTINED (${q.reason}); ` +
        "its agent gets no boot release and its gate denies (fail-closed); repair is owed. " +
        "Other agents proceed. Repair: sudo sanctuary protect --repair-egress-gate",
    );
  }
  if (entries.length === 0) {
    return { results: [], stopOracleLoop: () => undefined };
  }

  // PHASE 1 (fix-round-2 HIGH-3): resolve EVERY entry before any side
  // effect, so contextless re-parks can be ordered strictly before any
  // release and the shared-label guard knows whether any uid will release.
  // A THROWING resolver (missing Hermes runtime etc.) routes into the same
  // contextless re-park path as a null resolution (fix-round-2 BLOCKER-1).
  const resolutions = new Map<number, BootAgentResolution>();
  for (const entry of entries) {
    let resolution: BootAgentResolution;
    try {
      resolution = await input.resolveAgent({ agent_uid: entry.agent_uid, fortress_path: entry.fortress_path });
    } catch (err) {
      resolution = {
        kind: "unresolvable",
        reason: `release-context resolver threw: ${(err as Error).message}`,
      };
    }
    resolutions.set(entry.agent_uid, resolution);
  }
  const resolvedUids = entries
    .filter((e) => resolutions.get(e.agent_uid)!.kind === "ok")
    .map((e) => e.agent_uid);

  let keys: { privateKey: KeyObject; publicKey: KeyObject };
  try {
    keys = internals.ensureKeys !== undefined ? await internals.ensureKeys() : await ensureSupervisorOracleKeys();
  } catch (err) {
    // PRE-LOOP failure (fix-round-2 BLOCKER-1): no re-park or release op ran
    // for ANY agent, so the honest outcome is the LOUD `park-not-verified`
    // kind per agent -- never a synthetic PARKED nobody verified.
    const reason =
      `boot supervisor failed before any re-park/release op ran ` +
      `(supervisor oracle keys unavailable: ${(err as Error).message}); the parked state was NOT verified`;
    const results: BootReleaseResult[] = [];
    for (const entry of entries) {
      input.print(
        `[castle-wall] boot: uid ${entry.agent_uid} ${reason}; treat the agent as possibly ` +
          "startable and intervene manually. Repair: sudo sanctuary protect --repair-egress-gate",
      );
      await input.audit("exclusive_egress_boot_release", {
        agent_uid: entry.agent_uid,
        outcome: "park-not-verified",
        reason,
      });
      results.push({ agent_uid: entry.agent_uid, outcome: { kind: "park-not-verified", reason } });
    }
    return { results, stopOracleLoop: () => undefined };
  }
  // Gate-uid cache for the refresh loop (seeded by the boot release, extended
  // by marker reads for agents armed after boot).
  const gateUids = new Map<number, number>();

  // PHASE 2 ORDERING (fix-round-2 HIGH-3): every UNRESOLVABLE entry's
  // contextless re-park runs BEFORE any resolvable entry's release, so a
  // stale entry can never act on the shared harness label after another
  // uid's harness was released on it.
  const orderedAgents = [
    ...entries.filter((e) => resolutions.get(e.agent_uid)!.kind !== "ok"),
    ...entries.filter((e) => resolutions.get(e.agent_uid)!.kind === "ok"),
  ].map((e) => ({ agent_uid: e.agent_uid }));

  const results = await runBootExclusiveEgressRelease(
    orderedAgents,
    {
      releaseAgent: async (agentUid): Promise<ReleaseBarrierOutcome> => {
        const entry = entries.find((e) => e.agent_uid === agentUid)!;
        const resolution = resolutions.get(agentUid)!;
        if (resolution.kind === "unresolvable") {
          // Fix-round H1: park FOR REAL (bootout + hold-file removal +
          // disable) and report the ACTUAL results, never a synthetic parked.
          // Fix-round-2 HIGH-3: the shared-label ops (bootout/disable of the
          // host-singleton harness label) run ONLY when no other uid resolved
          // for release; the per-uid hold-file removal alone holds this uid's
          // park (the exec wrapper refuses without a matching hold file).
          const reassert = await reassertParkedWithoutContext({
            agentUid,
            runLaunchctlFn: launchctlFn,
            removeHoldFile: removeHold,
            sharedLabelOpsAllowed: resolvedUids.length === 0,
          });
          if (reassert.sharedLabelOpsSkipped) {
            input.print(
              `[castle-wall] boot: uid ${agentUid} is unresolvable; its per-uid hold file was removed ` +
                `(the exec wrapper refuses any start without it), but bootout/disable of the shared ` +
                `harness label ${AGENT_HARNESS_DAEMON_LABEL} were SKIPPED because uid(s) ` +
                `${resolvedUids.join(", ")} resolved for release on that same host-singleton label.`,
            );
            // Fix-round-3 HIGH-1: with bootout withheld, NOTHING above stopped
            // a harness already running from stale launchd state -- hold-file
            // removal blocks only the NEXT start (the exec wrapper), never a
            // live process. VERIFY not-running (the same launchd status probe
            // the repair path's park verify uses) before claiming PARKED; a
            // running or unknowable job is a LOUD park-not-verified (the
            // throw below maps to that distinct outcome), never a silent
            // PARKED report over a live process. This probe runs BEFORE any
            // resolved uid's release (phase-2 ordering), so a running job
            // here is stale state by construction, not a fresh release.
            const status = await agentHarnessDaemonStatus({ ...realHarnessOps(), runLaunchctl: launchctlFn });
            if (!status.known || status.running) {
              throw new Error(
                `uid ${agentUid} re-park NOT verified: ` +
                  (status.known
                    ? `the shared harness job ${AGENT_HARNESS_DAEMON_LABEL} reports RUNNING (pid ${status.pid ?? "unknown"})`
                    : `launchctl did not return a trustworthy status for the shared harness job ${AGENT_HARNESS_DAEMON_LABEL}`) +
                  ` while bootout/disable were withheld (uid(s) ${resolvedUids.join(", ")} resolved for ` +
                  "release on that host-singleton label); the hold file was removed so the exec wrapper " +
                  "refuses any NEW start, but a process already running from stale launchd state was NOT " +
                  "stopped; intervene manually",
              );
            }
          }
          if (reassert.cleanupErrors.length > 0) {
            input.print(
              `[castle-wall] boot: uid ${agentUid} could NOT be fully re-parked while unresolvable ` +
                `(${reassert.cleanupErrors.join("; ")}); treat the agent as possibly startable and intervene manually.`,
            );
          }
          return {
            kind: "parked",
            stage: "reassert-parked",
            reason: resolution.reason,
            holdFileRemoved: reassert.holdFileRemoved,
            jobDisabled: reassert.jobDisabled,
            cleanupErrors: reassert.cleanupErrors,
          };
        }
        const ctx = resolution;
        gateUids.set(agentUid, ctx.gateUid);
        // Re-assert the runtime fs layout (idempotent; heals drift and
        // pre-plan installs). A failure is loud but NOT terminal here: the
        // barrier's verifyGate will produce the honest parked outcome.
        try {
          await ensureRuntimeFs({ agentUid, gateUid: ctx.gateUid });
        } catch (err) {
          input.print(`[castle-wall] boot: uid ${agentUid} runtime-fs assert failed: ${(err as Error).message}`);
        }
        // Fix-round H2: START the gate daemon (RunAtLoad=false by contract;
        // nothing else starts it after a reboot), then let the barrier verify
        // it. A bootstrap failure logs loudly and still runs the barrier,
        // which parks the agent through its own fail-closed machinery.
        try {
          const expected =
            entry.tombstone !== true &&
            typeof entry.generation_id === "number" &&
            Number.isInteger(entry.generation_id) &&
            entry.generation_id > 0
              ? { generationId: entry.generation_id, gatePort: entry.gate_port }
              : null;
          await bootstrapGateDaemonForBoot({
            agentUid,
            expected,
            runLaunchctlFn: launchctlFn,
            ...(internals.readRuntimeState !== undefined ? { readState: internals.readRuntimeState } : {}),
            ...(internals.gateWaitBudgetMs !== undefined ? { waitBudgetMs: internals.gateWaitBudgetMs } : {}),
            ...(internals.gateWaitIntervalMs !== undefined ? { waitIntervalMs: internals.gateWaitIntervalMs } : {}),
          });
        } catch (err) {
          input.print(
            `[castle-wall] boot: uid ${agentUid} gate daemon bootstrap failed (${(err as Error).message}); ` +
              "the release barrier will verify and park fail-closed.",
          );
        }
        const oracle = createOracle(keys.privateKey, ctx.gateUid);
        const barrierOps = createBarrierOps({
          agentUid,
          agentAccount: ctx.agentAccount,
          harnessArgv: ctx.harnessArgv,
          fortressPath: entry.fortress_path,
          harnessLogDir: ctx.harnessLogDir,
          gateUid: ctx.gateUid,
          oracle: oracle as GateLivenessOracle,
          rearm: "boot-rearm",
          print: input.print,
        });
        // Fix-round-3 MED-4: the release context (fortressPath, harnessArgv,
        // gateUid) was resolved from THIS registry entry in phase 1. Between
        // that resolution and the barrier's release, a concurrent repair or
        // install for the same uid can commit a NEW generation -- the barrier
        // would then verify the new generation while releasing with the STALE
        // resolved context. Capture the entry's committed generation at
        // resolution time and re-check it at the commit step (immediately
        // before any release surface is written): a mismatch THROWS, which
        // the barrier maps to a loud fail-closed park at commit-generation.
        const resolvedGenerationId = entry.generation_id;
        const guardedOps: ReleaseBarrierOps = {
          ...barrierOps,
          commitGeneration: async (): Promise<CommittedGenerationIdentity> => {
            const committed = await barrierOps.commitGeneration();
            if (committed.generation_id !== resolvedGenerationId) {
              throw new Error(
                `registry changed during boot release for uid ${agentUid}: resolution captured committed ` +
                  `generation ${resolvedGenerationId ?? "none"} but the registry now commits generation ` +
                  `${committed.generation_id} (a concurrent install/repair advanced it); the resolved ` +
                  "release context may be stale; parking fail-closed -- re-run the boot release or repair",
              );
            }
            return committed;
          },
        };
        return runBarrier(
          { agentUid, harnessLabel: AGENT_HARNESS_DAEMON_LABEL, harnessArgv: ctx.harnessArgv },
          guardedOps,
        );
      },
      audit: input.audit,
      print: input.print,
    },
  );

  // Ongoing oracle refresh (TTL-fresh liveness), fix-round H3: RE-SCAN the
  // registry every tick so agents armed AFTER boot (the install CLI path,
  // whose own refresh dies with the CLI process) are picked up within one
  // interval. A refresh failure removes the token (fail-closed: the gate
  // denies) and is logged; the loop keeps trying (self-healing posture).
  //
  // RE-ENTRANCY GUARD (fix-round-2 MED-5): the tick body is async; on a slow
  // host (hung pfctl, slow disk) overlapping ticks would pile up concurrent
  // registry reads + pfctl probes. A tick is SKIPPED while the previous one
  // is still running; consecutive skips are counted and warned loudly at a
  // threshold (tokens may expire -> gates deny, fail-closed but visible).
  //
  // LOG DISCIPLINE (fix-round-2 MED-6): "registry unreadable" and
  // per-quarantined-entry findings are WARN-ONCE (re-armed on recovery),
  // never a 1-per-second flood that buries the signal.
  //
  // DIRTY REGISTRY WITHHOLDS TOKENS (fix-round-3 HIGH-2): while the registry
  // reads dirty (quarantined entry, pending journal, explicit dirty marker,
  // missing enable token), the anchor may diverge from the committed union
  // in ways the per-uid liveness probe cannot see, so the loop withholds
  // EVERY freshness token (gates deny within one TTL, fail-closed) and
  // warns once per uid until the registry is clean again.
  const interval = input.refreshIntervalMs ?? 1_000;
  const REFRESH_SKIP_WARN_THRESHOLD = 3;
  const warnedUids = new Set<number>();
  const warnedQuarantined = new Set<string>();
  const warnedDirtyUids = new Set<number>();
  let warnedRegistryUnreadable = false;
  let refreshInFlight = false;
  let consecutiveSkips = 0;
  const timer = setInterval(() => {
    if (refreshInFlight) {
      consecutiveSkips += 1;
      if (consecutiveSkips % REFRESH_SKIP_WARN_THRESHOLD === 0) {
        input.print(
          `[castle-wall] oracle refresh: previous refresh still running; ${consecutiveSkips} ` +
            "consecutive tick(s) skipped (slow host or hung registry/pfctl probe); tokens may " +
            "expire within the TTL and gates then deny (fail-closed)",
        );
      }
      return;
    }
    refreshInFlight = true;
    void (async (): Promise<void> => {
      let current: BootRegistryListing;
      try {
        current = await listEntries();
      } catch (err) {
        if (!warnedRegistryUnreadable) {
          warnedRegistryUnreadable = true;
          input.print(
            `[castle-wall] oracle refresh: registry unreadable (${(err as Error).message}); gates deny ` +
              "within one TTL (fail-closed); this warning is suppressed until the registry recovers",
          );
        }
        return;
      }
      if (warnedRegistryUnreadable) {
        warnedRegistryUnreadable = false;
        input.print("[castle-wall] oracle refresh: registry readable again; refresh resumed");
      }
      for (const q of current.quarantined) {
        const key = `${q.index}:${q.reason}`;
        if (!warnedQuarantined.has(key)) {
          warnedQuarantined.add(key);
          input.print(
            `[castle-wall] oracle refresh: registry entry #${q.index} is malformed and QUARANTINED ` +
              `(${q.reason}); its agent gets no token refresh and its gate denies (fail-closed); ` +
              "the quarantine marks the registry DIRTY, so every entry's token is withheld until " +
              "repair; repair is owed (warn-once)",
          );
        }
      }
      // Fix-round-3 HIGH-2: while the registry is DIRTY (quarantined entry,
      // journaled pending set, explicit dirty marker, or missing enable
      // token) the live anchor may diverge from the committed union, and the
      // per-uid liveness probe behind oracle.refresh checks only that THIS
      // uid's rules are present -- it cannot rule out EXTRA permissive rules
      // on a dirty anchor. WITHHOLD every token: the previous one expires
      // within one TTL and the gate denies (fail-closed), matching the
      // release barrier, which also refuses to release over a dirty
      // registry. Warn-once per uid; re-armed when the registry is clean.
      if (current.dirty) {
        for (const entry of current.entries) {
          if (!warnedDirtyUids.has(entry.agent_uid)) {
            warnedDirtyUids.add(entry.agent_uid);
            input.print(
              `[castle-wall] oracle refresh: registry is DIRTY (needs repair), so the freshness token ` +
                `for uid ${entry.agent_uid} is WITHHELD; its gate denies within one TTL (fail-closed: ` +
                "per-uid liveness cannot rule out extra permissive rules on a dirty anchor); " +
                "repair: sudo sanctuary protect --repair-egress-gate (warn-once until the registry is clean)",
            );
          }
        }
        return;
      }
      if (warnedDirtyUids.size > 0) {
        warnedDirtyUids.clear();
        input.print("[castle-wall] oracle refresh: registry is clean again; token refresh resumed");
      }
      for (const entry of current.entries) {
        if (entry.tombstone === true) continue;
        const generationId = entry.generation_id;
        if (typeof generationId !== "number" || !Number.isInteger(generationId) || generationId <= 0) continue;
        let gateUid = gateUids.get(entry.agent_uid);
        if (gateUid === undefined) {
          try {
            const marker = await loadMarker(entry.fortress_path);
            if (marker === null || marker.agent_uid !== entry.agent_uid) {
              if (!warnedUids.has(entry.agent_uid)) {
                warnedUids.add(entry.agent_uid);
                input.print(
                  `[castle-wall] oracle refresh: no exclusive-routing marker resolves a gate uid for uid ${entry.agent_uid}; its gate denies within one TTL (fail-closed)`,
                );
              }
              continue;
            }
            gateUid = marker.gate_uid;
            gateUids.set(entry.agent_uid, gateUid);
          } catch (err) {
            if (!warnedUids.has(entry.agent_uid)) {
              warnedUids.add(entry.agent_uid);
              input.print(
                `[castle-wall] oracle refresh: marker read failed for uid ${entry.agent_uid} (${(err as Error).message}); its gate denies within one TTL (fail-closed)`,
              );
            }
            continue;
          }
        }
        try {
          const oracle = createOracle(keys.privateKey, gateUid);
          await oracle.refresh({
            agentUid: entry.agent_uid,
            gatePort: entry.gate_port,
            generationId,
          });
        } catch (err) {
          input.print(
            `[castle-wall] oracle refresh failed for uid ${entry.agent_uid}: ${(err as Error).message} (gate denies until it recovers)`,
          );
        }
      }
    })().finally(() => {
      refreshInFlight = false;
      consecutiveSkips = 0;
    });
  }, interval);
  timer.unref();
  return {
    results,
    stopOracleLoop: (): void => clearInterval(timer),
  };
}

// ---------------------------------------------------------------------------
// S5-P posture producer (retires the "no live producer" disclosure)
// ---------------------------------------------------------------------------

/**
 * Build the exclusive-egress posture PROVIDER the dashboard binds via
 * `setExclusiveEgressPostureProvider`. Reads the REAL surfaces per call:
 * the exclusive-routing marker (fine-grained intent), the S5-1 registry
 * (+dirty), the S5-2 staging store, the gate runtime state, the oracle token
 * (verified against the pinned public key -- the gate's own fail-closed
 * verdict), and the injected coarse-wall-armed probe. FAIL-CLOSED: a read
 * failure THROWS; the dashboard's shared resolver maps a throwing provider to
 * `failedExclusiveEgressStatus` (caps green). Returns null when no
 * fine-grained agent was ever provisioned (marker absent + registry empty).
 */
export function createExclusiveEgressPostureProducer(input: {
  fortressPath: string;
  /** The same coarse-wall evidence surface the caller already trusts. */
  coarseWallArmed: () => Promise<boolean>;
}): () => Promise<ExclusiveEgressStatus | null> {
  return async (): Promise<ExclusiveEgressStatus | null> => {
    const marker = await loadExclusiveRoutingMarker(input.fortressPath).catch((err) => {
      // A malformed marker is a fail-closed cap, not a null.
      throw err instanceof Error ? err : new Error(String(err));
    });
    const registry = createProductionAnchorRegistry();
    let entries: { agent_uid: number; gate_port: number; fortress_path: string; generation_id?: number; tombstone?: boolean }[];
    let dirty: boolean;
    try {
      const listed = await registry.list();
      entries = listed.entries;
      dirty = listed.dirty;
    } catch (err) {
      // No registry file at all + no marker = affirmatively no fine-grained
      // agent; any OTHER failure caps green.
      if (marker === null && (err as { name?: string }).name === "PfAnchorRegistryStateError") {
        return null;
      }
      throw err;
    }
    if (marker === null && entries.length === 0) {
      return null;
    }
    const staging = createFsGenerationStagingStore();
    const coarseArmed = await input.coarseWallArmed();
    const publicKey: KeyObject | null = await readFile(GATE_ORACLE_PUBLIC_KEY_PATH, "utf8")
      .then((pem) => createPublicKey(pem))
      .catch(() => null);

    const uids = new Set<number>(entries.map((e) => e.agent_uid));
    if (marker !== null) uids.add(marker.agent_uid);
    const agents = [];
    for (const uid of uids) {
      const entry = entries.find((e) => e.agent_uid === uid) ?? null;
      const stagingRecord = await staging.load(uid).catch(() => null);
      const runtimeStatePath = egressGateRuntimeStatePath(uid);
      const runtime: EgressGateRuntimeState | null = await readFile(runtimeStatePath, "utf8")
        .then((text) => parseEgressGateRuntimeState(text, runtimeStatePath))
        .catch(() => null);
      // The oracle token IS the pf-liveness verdict (the gate's own check).
      let pfLiveness: { live: false | true; reasons: string[] } = {
        live: false,
        reasons: ["oracle public key unavailable"],
      };
      if (publicKey !== null) {
        const raw: string | null = await readFile(join(GATE_LIVENESS_DIR, `${uid}.token`), "utf8").catch(
          () => null,
        );
        const committed = resolveCommittedGeneration({
          entry,
          stagingRecordPresent: stagingRecord !== null,
          registryDirty: dirty,
        });
        pfLiveness = verifyLivenessToken({
          raw,
          publicKey,
          binding: {
            agentUid: uid,
            gatePort: entry?.gate_port ?? 0,
            generationId: committed.committedGenerationId ?? 0,
          },
          now: Date.now(),
        });
      }
      // Owner check with the full evidence available to posture: expected
      // gate uid from the marker (the registry entry carries no gate uid) and
      // the runtime state's pid_start token (pid-reuse defense, fix-round:
      // previously stored but never enforced). The verdict's reason feeds the
      // posture reasons for diagnosability (fix-round-2 MED-4).
      const ownerVerdict: PortOwnerVerdict =
        runtime === null
          ? { ok: false, reason: "gate runtime state absent" }
          : await verifyLoopbackTcpPortOwner({
              port: runtime.gate_port,
              expectedPid: runtime.pid,
              ...(marker !== null && marker.agent_uid === uid ? { expectedUid: marker.gate_uid } : {}),
              expectedPidStart: runtime.pid_start,
            });
      agents.push(
        buildExclusiveEgressPosture({
          agent_uid: uid,
          fine_grained_declared: marker !== null && marker.agent_uid === uid ? true : entry !== null,
          coarse_wall_armed: coarseArmed,
          registry_entry: entry,
          staging_record_present: stagingRecord !== null,
          registry_dirty: dirty,
          pf_pass_port: entry !== null && entry.tombstone !== true ? entry.gate_port : undefined,
          manifest: runtime !== null ? { gate_port: runtime.gate_port, generation_id: runtime.generation_id } : null,
          pf_liveness: pfLiveness,
          gate_process: {
            up: runtime !== null,
            port_owner_verified: ownerVerdict.ok,
            reasons:
              runtime === null
                ? ["gate runtime state absent"]
                : ownerVerdict.ok
                  ? []
                  : [ownerVerdict.reason],
          },
        }),
      );
    }
    return summarizeExclusiveEgressStatus(agents);
  };
}

// Re-exported so wiring callers do not need a second import site.
export { failedExclusiveEgressStatus };
